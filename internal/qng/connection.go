package quic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	tls "github.com/tmc/go-iroh/internal/itls/tls"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/flowcontrol"
	"github.com/tmc/go-iroh/internal/qng/internal/handshake"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/utils/ringbuffer"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/qlog"
	"github.com/tmc/go-iroh/internal/qng/qlogwriter"
)

type unpacker interface {
	UnpackLongHeader(hdr *wire.Header, data []byte) (*unpackedPacket, error)
	UnpackShortHeader(rcvTime monotime.Time, pid protocol.PathID, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error)
}

type cryptoStreamHandler interface {
	StartHandshake(context.Context) error
	ChangeConnectionID(protocol.ConnectionID)
	SetLargest1RTTAcked(protocol.PacketNumber) error
	SetHandshakeConfirmed()
	GetSessionTicket() ([]byte, error)
	NextEvent() handshake.Event
	DiscardInitialKeys()
	HandleMessage([]byte, protocol.EncryptionLevel) error
	io.Closer
	ConnectionState() handshake.ConnectionState
}

type receivedPacket struct {
	buffer *packetBuffer

	remoteAddr net.Addr
	rcvTime    monotime.Time
	data       []byte

	ecn protocol.ECN

	info packetInfo // only valid if the contained IP address is valid
}

type receivedPacketWithDatagramID struct {
	receivedPacket
	datagramID qlog.DatagramID
}

func (p *receivedPacket) Size() protocol.ByteCount { return protocol.ByteCount(len(p.data)) }

func packetSourceAddrPort(addr net.Addr) netip.AddrPort {
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	return canonicalNATTraversalAddr(udp.AddrPort())
}

func (p *receivedPacket) Clone() *receivedPacket {
	return &receivedPacket{
		remoteAddr: p.remoteAddr,
		rcvTime:    p.rcvTime,
		data:       p.data,
		buffer:     p.buffer,
		ecn:        p.ecn,
		info:       p.info,
	}
}

type connRunner interface {
	Add(protocol.ConnectionID, packetHandler) bool
	Remove(protocol.ConnectionID)
	ReplaceWithClosed([]protocol.ConnectionID, []byte, time.Duration)
	AddResetToken(protocol.StatelessResetToken, packetHandler)
	RemoveResetToken(protocol.StatelessResetToken)
}

type closeError struct {
	err       error
	immediate bool
}

type errCloseForRecreating struct {
	nextPacketNumber protocol.PacketNumber
	nextVersion      protocol.Version
}

func (e *errCloseForRecreating) Error() string {
	return "closing connection in order to recreate it"
}

var deadlineSendImmediately = monotime.Time(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type blockMode uint8

const (
	// blockModeNone means that the connection is not blocked.
	blockModeNone blockMode = iota
	// blockModeCongestionLimited means that the connection is congestion limited.
	// In that case, we can still send acknowledgments and PTO probe packets.
	blockModeCongestionLimited
	// blockModeHardBlocked means that no packet can be sent, under no circumstances. This can happen when:
	// * the send queue is full
	// * the SentPacketHandler returns SendNone, e.g. when we are tracking the maximum number of packets
	// In that case, the timer will be set to the idle timeout.
	blockModeHardBlocked
)

// A Conn is a QUIC connection between two peers.
// Calls to the connection (and to streams) can return the following types of errors:
//   - [ApplicationError]: for errors triggered by the application running on top of QUIC
//   - [TransportError]: for errors triggered by the QUIC transport (in many cases a misbehaving peer)
//   - [IdleTimeoutError]: when the peer goes away unexpectedly (this is a [net.Error] timeout error)
//   - [HandshakeTimeoutError]: when the cryptographic handshake takes too long (this is a [net.Error] timeout error)
//   - [StatelessResetError]: when we receive a stateless reset
//   - [VersionNegotiationError]: returned by the client, when there's no version overlap between the peers
type Conn struct {
	// Destination connection ID used during the handshake.
	// Used to check source connection ID on incoming packets.
	handshakeDestConnID protocol.ConnectionID
	// Set for the client. Destination connection ID used on the first Initial sent.
	origDestConnID protocol.ConnectionID
	retrySrcConnID *protocol.ConnectionID // only set for the client (and if a Retry was performed)

	srcConnIDLen int

	perspective protocol.Perspective
	version     protocol.Version
	config      *Config

	conn      sendConn
	sendQueue sender

	// lazily initialzed: most connections never migrate
	pathManager         *pathManager
	largestRcvdAppData  protocol.PacketNumber
	pathManagerOutgoing atomic.Pointer[pathManagerOutgoing]

	// multipathManager records the read-side state of QUIC multipath
	// (draft-ietf-quic-multipath) paths, keyed by protocol.PathID. It is
	// distinct from pathManager (the RFC 9000 single-path migration manager,
	// keyed by an int64 path id). It is only consulted for frames admitted
	// once multipathNegotiated() is true.
	multipathManager *multipathManager

	// perPathDestConnIDs holds the destination connection IDs the peer issued
	// for non-zero QUIC multipath paths via PATH_NEW_CONNECTION_ID (0x3e78),
	// keyed by protocol.PathID. The send side uses these as the DCID for 1-RTT
	// packets on a path != 0 (consumed by the packer in 5d via
	// destConnIDForPath). It is STRICTLY SEPARATE from connIDManager (the
	// connection-level / PathID 0 DCID source) and from
	// connIDManager.pathProbing (the RFC 9000 int64 single-path migration CID
	// set). PathIDZero is never stored here; its DCID always comes from
	// connIDManager.Get.
	perPathDestConnIDs map[protocol.PathID]protocol.ConnectionID

	// pathAcksReceived counts inbound PATH_ACK / PATH_ACK_ECN frames (multipath,
	// per non-zero PathID). It is observable from any goroutine (atomic) so a
	// test can confirm a second path's packets were acknowledged with PATH_ACK
	// frames, driving that path's bytes-in-flight down. It is never touched on a
	// single-path connection.
	pathAcksReceived atomic.Uint64

	// lastPathAckID records the PathID carried by the most recently received
	// PATH_ACK / PATH_ACK_ECN frame (stored as id+1 so the zero value means "no
	// PATH_ACK seen", since PathIDZero is a legitimate id). It is observable from
	// any goroutine (atomic) so a test can confirm an acknowledgement arrived for
	// the specific non-zero path it expected, not merely "some path".
	lastPathAckID atomic.Uint64

	// multipathOut is the send-side multipath orchestration state (5f): the
	// per-PathID validation/scheduling owned exclusively by the run goroutine.
	// It is nil until the first Conn.OpenPath. All access happens in the run
	// loop, so it needs no lock; OpenPath hands work to the run loop over
	// openPathQueue. See multipath_outgoing.go.
	multipathOut *multipathOutgoing
	// openPathQueue carries OpenPath requests from application goroutines into
	// the run goroutine, the only safe place to touch sentPacketHandler /
	// receivedPacketHandler / connIDGenerator (none are mutex-guarded). Buffered
	// so OpenPath never blocks the caller before scheduleSending wakes the loop.
	openPathQueue chan *openPathRequest
	// pathDatagramQueue carries per-path DATAGRAM sends (MultipathPath.SendDatagram)
	// into the run goroutine, where they are appended to the target path's
	// sendData and packed by sendOnPath over that path specifically.
	pathDatagramQueue chan pathDatagram
	// pathStatsQueue carries live per-path recovery-stat queries from a test
	// goroutine into the run goroutine, the only goroutine that may read the
	// (lock-free) sentPacketHandler. It exists purely so the multipath e2e test
	// can confirm path-1 packets really flowed in path 1's own number space and
	// controller. It is never used on a production connection.
	pathStatsQueue chan *pathStatsRequest
	// pathSnapshotQueue carries application-facing path-observability queries
	// into the run goroutine, where the real multipathOut path-open state lives.
	// It deliberately reports qng path state only; socket path events need a
	// later address-bearing adapter instead of fabricated RemoteAddr values.
	pathSnapshotQueue chan *pathSnapshotRequest
	// setMigrationFallbackQueue carries a best-effort relay fallback for QNT
	// active migration into the run goroutine.
	setMigrationFallbackQueue chan *setMigrationFallbackRequest
	// qnt holds local and remote n0 NAT traversal candidate addresses. It is
	// mutex-protected because socket can hand candidates to qng from application
	// goroutines while the eventual QNT receive path will run on the connection
	// goroutine.
	qnt qntLocalState

	// nextObservedAddrSeqNo is the sequence number for the next OBSERVED_ADDRESS
	// frame this endpoint emits (QUIC Address Discovery). It increments once per
	// emitted frame, mirroring next_observed_addr_seq_no (mod.rs:238,6196-6197).
	// Run goroutine only.
	nextObservedAddrSeqNo uint64
	// observedAddr holds the most recent reflexive address the peer reported to
	// us via OBSERVED_ADDRESS, kept under observedAddrMu so a QAD client
	// (netreport) can read it from another goroutine. observedAddrSeqNo records
	// the highest seq_no seen so a stale report is ignored (highest-seq_no wins),
	// mirroring update_observed_addr_report (paths.rs:615-640). observedAddrValid
	// distinguishes "no report yet" from a zero AddrPort.
	observedAddrMu     sync.Mutex
	observedAddr       netip.AddrPort
	observedAddrSeqNo  uint64
	observedAddrValid  bool
	observedAddrSeqSet bool
	// observedAddrReadyCh is closed at the first report so a reader can wait
	// instead of polling; created lazily under observedAddrMu.
	observedAddrReadyCh chan struct{}

	streamsMap      *streamsMap
	connIDManager   *connIDManager
	connIDGenerator *connIDGenerator

	rttStats  *utils.RTTStats
	connStats utils.ConnectionStats

	cryptoStreamManager   *cryptoStreamManager
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	retransmissionQueue   *retransmissionQueue
	framer                *framer
	connFlowController    flowcontrol.ConnectionFlowController
	tokenStoreKey         string                    // only set for the client
	tokenGenerator        *handshake.TokenGenerator // only set for the server

	unpacker      unpacker
	frameParser   wire.FrameParser
	packer        packer
	mtuDiscoverer mtuDiscoverer // initialized when the transport parameters are received

	currentMTUEstimate atomic.Uint32

	initialStream       *initialCryptoStream
	handshakeStream     *cryptoStream
	oneRTTStream        *cryptoStream // only set for the server
	cryptoStreamHandler cryptoStreamHandler

	notifyReceivedPacket chan struct{}
	sendingScheduled     chan struct{}
	receivedPacketMx     sync.Mutex
	receivedPackets      ringbuffer.RingBuffer[receivedPacket]

	// closeChan is used to notify the run loop that it should terminate
	closeChan chan struct{}
	closeErr  atomic.Pointer[closeError]

	ctx                   context.Context
	ctxCancel             context.CancelCauseFunc
	handshakeCompleteChan chan struct{}

	undecryptablePackets          []receivedPacketWithDatagramID // undecryptable packets, waiting for a change in encryption level
	undecryptablePacketsToProcess []receivedPacketWithDatagramID

	earlyConnReadyChan chan struct{}
	sentFirstPacket    bool
	droppedInitialKeys bool
	handshakeComplete  bool
	handshakeConfirmed bool

	receivedRetry       bool
	versionNegotiated   bool
	receivedFirstPacket bool
	remoteAddrValidated bool

	blocked blockMode

	// the minimum of the max_idle_timeout values advertised by both endpoints
	idleTimeout  time.Duration
	creationTime monotime.Time
	// The idle timeout is set based on the max of the time we received the last packet...
	lastPacketReceivedTime monotime.Time
	// ... and the time we sent a new ack-eliciting packet after receiving a packet.
	firstAckElicitingPacketAfterIdleSentTime monotime.Time
	// pacingDeadline is the time when the next packet should be sent
	pacingDeadline monotime.Time

	// peerParams holds the peer's transport parameters. It is written only on
	// the run goroutine, but read from application goroutines (e.g. when a
	// stream opened on a 0-RTT connection creates its flow controller before
	// the handshake has delivered the authoritative parameters), so all access
	// goes through the atomic pointer.
	peerParams atomic.Pointer[wire.TransportParameters]

	timer *time.Timer
	// keepAlivePingSent stores whether a keep alive PING is in flight.
	// It is reset as soon as we receive a packet from the peer.
	keepAlivePingSent bool
	keepAliveInterval time.Duration

	datagramQueue *datagramQueue

	connStateMutex sync.Mutex
	connState      ConnectionState

	logID     string
	qlogTrace qlogwriter.Trace
	qlogger   qlogwriter.Recorder
	logger    utils.Logger
}

var _ streamSender = &Conn{}

type connTestHooks struct {
	run                     func() error
	earlyConnReady          func() <-chan struct{}
	context                 func() context.Context
	handshakeComplete       func() <-chan struct{}
	closeWithTransportError func(TransportErrorCode)
	destroy                 func(error)
	handlePacket            func(receivedPacket)
}

type wrappedConn struct {
	testHooks *connTestHooks
	*Conn
}

var newConnection = func(
	ctx context.Context,
	ctxCancel context.CancelCauseFunc,
	conn sendConn,
	runner connRunner,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID *protocol.ConnectionID,
	clientDestConnID protocol.ConnectionID,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	tokenGenerator *handshake.TokenGenerator,
	clientAddressValidated bool,
	rtt time.Duration,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
) *wrappedConn {
	s := &Conn{
		ctx:                 ctx,
		ctxCancel:           ctxCancel,
		conn:                conn,
		config:              conf,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		tokenGenerator:      tokenGenerator,
		oneRTTStream:        newCryptoStream(),
		perspective:         protocol.PerspectiveServer,
		qlogTrace:           qlogTrace,
		logger:              logger,
		version:             v,
		remoteAddrValidated: clientAddressValidated,
	}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	if origDestConnID.Len() > 0 {
		s.logID = origDestConnID.String()
	} else {
		s.logID = destConnID.String()
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		&clientDestConnID,
		statelessResetter,
		connRunnerCallbacks{
			AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, s) },
			RemoveConnectionID: runner.Remove,
			ReplaceWithClosed:  runner.ReplaceWithClosed,
		},
		s.queueControlFrame,
		connIDGenerator,
	)
	s.preSetup()
	if rtt > 0 {
		s.rttStats.SetInitialRTT(rtt)
	}
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(
		0,
		protocol.ByteCount(s.config.InitialPacketSize),
		s.rttStats,
		&s.connStats,
		clientAddressValidated,
		s.conn.capabilities().ECN,
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		s.qlogger,
		s.logger,
	)
	s.currentMTUEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))
	statelessResetToken := statelessResetter.GetStatelessResetToken(srcConnID)
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:         protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                  protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                  s.config.MaxIdleTimeout,
		MaxBidiStreamNum:                protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                 protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                     protocol.MaxAckDelayInclGranularity,
		AckDelayExponent:                protocol.AckDelayExponent,
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		StatelessResetToken:             &statelessResetToken,
		OriginalDestinationConnectionID: origDestConnID,
		// For interoperability with quic-go versions before May 2023, this value must be set to a value
		// different from protocol.DefaultActiveConnectionIDLimit.
		// If set to the default value, it will be omitted from the transport parameters, which will make
		// old quic-go versions interpret it as 0, instead of the default value of 2.
		// See https://github.com/quic-go/quic-go/pull/3806.
		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		RetrySourceConnectionID:   retrySrcConnID,
		EnableResetStreamAt:       conf.EnableStreamResetPartialDelivery,
		InitialMaxPathID:          initialMaxPathIDParam(s.config.InitialMaxPathID),
		MaxRemoteNATTraversalAddresses: maxRemoteNATTraversalAddressesParam(
			s.config.MaxRemoteNATTraversalAddresses,
		),
		AddressDiscoveryRole: addressDiscoveryRole(s.config),
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveServer, false)
	}
	cs := handshake.NewCryptoSetupServer(
		clientDestConnID,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		params,
		tlsConf,
		conf.Allow0RTT,
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
	)
	s.cryptoStreamHandler = cs
	s.packer = newPacketPacker(srcConnID, s.connIDManager.Get, s.destConnIDForPath, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, s.oneRTTStream)
	return &wrappedConn{Conn: s}
}

// declare this as a variable, such that we can it mock it in the tests
var newClientConnection = func(
	ctx context.Context,
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetter *statelessResetter,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	qlogTrace qlogwriter.Trace,
	logger utils.Logger,
	v protocol.Version,
) *wrappedConn {
	s := &Conn{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		qlogTrace:           qlogTrace,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
	}
	if qlogTrace != nil {
		s.qlogger = qlogTrace.AddProducer()
	}
	if s.qlogger != nil {
		var srcAddr, destAddr *net.UDPAddr
		if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			srcAddr = addr
		}
		if addr, ok := conn.RemoteAddr().(*net.UDPAddr); ok {
			destAddr = addr
		}
		s.qlogger.RecordEvent(startedConnectionEvent(srcAddr, destAddr))
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	s.connIDGenerator = newConnIDGenerator(
		runner,
		srcConnID,
		nil,
		statelessResetter,
		connRunnerCallbacks{
			AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, s) },
			RemoveConnectionID: runner.Remove,
			ReplaceWithClosed:  runner.ReplaceWithClosed,
		},
		s.queueControlFrame,
		connIDGenerator,
	)
	s.ctx, s.ctxCancel = context.WithCancelCause(ctx)
	s.preSetup()
	s.sentPacketHandler = ackhandler.NewSentPacketHandler(
		initialPacketNumber,
		protocol.ByteCount(s.config.InitialPacketSize),
		s.rttStats,
		&s.connStats,
		false, // has no effect
		s.conn.capabilities().ECN,
		s.receivedPacketHandler.IgnorePacketsBelow,
		s.perspective,
		s.qlogger,
		s.logger,
	)
	s.currentMTUEstimate.Store(uint32(estimateMaxPayloadSize(protocol.ByteCount(s.config.InitialPacketSize))))
	oneRTTStream := newCryptoStream()
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:        protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                 protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                 s.config.MaxIdleTimeout,
		MaxBidiStreamNum:               protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                    protocol.MaxAckDelayInclGranularity,
		MaxUDPPayloadSize:              protocol.MaxPacketBufferSize,
		AckDelayExponent:               protocol.AckDelayExponent,
		// For interoperability with quic-go versions before May 2023, this value must be set to a value
		// different from protocol.DefaultActiveConnectionIDLimit.
		// If set to the default value, it will be omitted from the transport parameters, which will make
		// old quic-go versions interpret it as 0, instead of the default value of 2.
		// See https://github.com/quic-go/quic-go/pull/3806.
		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		EnableResetStreamAt:       conf.EnableStreamResetPartialDelivery,
		InitialMaxPathID:          initialMaxPathIDParam(s.config.InitialMaxPathID),
		MaxRemoteNATTraversalAddresses: maxRemoteNATTraversalAddressesParam(
			s.config.MaxRemoteNATTraversalAddresses,
		),
		AddressDiscoveryRole: addressDiscoveryRole(s.config),
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	if s.qlogger != nil {
		s.qlogTransportParameters(params, protocol.PerspectiveClient, false)
	}
	cs := handshake.NewCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		s.qlogger,
		logger,
		s.version,
	)
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newPacketPacker(srcConnID, s.connIDManager.Get, s.destConnIDForPath, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, &s.receivedPacketHandler, s.datagramQueue, s.perspective)
	if len(tlsConf.ServerName) > 0 {
		s.tokenStoreKey = tlsConf.ServerName
	} else {
		s.tokenStoreKey = conn.RemoteAddr().String()
	}
	if s.config.TokenStore != nil {
		if token := s.config.TokenStore.Pop(s.tokenStoreKey); token != nil {
			s.packer.SetToken(token.data)
			s.rttStats.SetInitialRTT(token.rtt)
		}
	}
	return &wrappedConn{Conn: s}
}

func (c *Conn) preSetup() {
	c.largestRcvdAppData = protocol.InvalidPacketNumber
	c.multipathManager = newMultipathManager()
	c.perPathDestConnIDs = make(map[protocol.PathID]protocol.ConnectionID)
	c.openPathQueue = make(chan *openPathRequest, 4)
	c.pathDatagramQueue = make(chan pathDatagram, maxDatagramSendQueueLen)
	c.pathStatsQueue = make(chan *pathStatsRequest, 4)
	c.pathSnapshotQueue = make(chan *pathSnapshotRequest, 4)
	c.setMigrationFallbackQueue = make(chan *setMigrationFallbackRequest, 4)
	c.initialStream = newInitialCryptoStream(c.perspective == protocol.PerspectiveClient)
	c.handshakeStream = newCryptoStream()
	c.sendQueue = newSendQueue(c.conn)
	c.retransmissionQueue = newRetransmissionQueue()
	c.frameParser = *wire.NewFrameParser(
		c.config.EnableDatagrams,
		c.config.EnableStreamResetPartialDelivery,
		false, // ACK_FREQUENCY is not supported yet
		false, // multipath is not negotiated yet (Stage 3)
	)
	c.rttStats = utils.NewRTTStats()
	if c.config.InitialRTT > 0 {
		c.rttStats.SetInitialRTT(c.config.InitialRTT)
	}
	c.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.ByteCount(c.config.InitialConnectionReceiveWindow),
		protocol.ByteCount(c.config.MaxConnectionReceiveWindow),
		func(size protocol.ByteCount) bool {
			if c.config.AllowConnectionWindowIncrease == nil {
				return true
			}
			return c.config.AllowConnectionWindowIncrease(c, uint64(size))
		},
		c.rttStats,
		c.logger,
	)
	c.earlyConnReadyChan = make(chan struct{})
	c.streamsMap = newStreamsMap(
		c.ctx,
		c,
		c.queueControlFrame,
		c.newFlowController,
		uint64(c.config.MaxIncomingStreams),
		uint64(c.config.MaxIncomingUniStreams),
		c.perspective,
	)
	c.framer = newFramer(c.connFlowController)
	c.receivedPackets.Init(8)
	c.notifyReceivedPacket = make(chan struct{}, 1)
	c.closeChan = make(chan struct{}, 1)
	c.sendingScheduled = make(chan struct{}, 1)
	c.handshakeCompleteChan = make(chan struct{})

	now := monotime.Now()
	c.lastPacketReceivedTime = now
	c.creationTime = now

	c.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(c.logger)

	c.datagramQueue = newDatagramQueue(c.scheduleSending, c.logger)
	c.connState.Version = c.version
}

// run the connection main loop
func (c *Conn) run() (err error) {
	defer func() { c.ctxCancel(err) }()

	defer func() {
		// drain queued packets that will never be processed
		c.receivedPacketMx.Lock()
		defer c.receivedPacketMx.Unlock()

		for !c.receivedPackets.Empty() {
			p := c.receivedPackets.PopFront()
			p.buffer.Decrement()
			p.buffer.MaybeRelease()
		}
	}()

	c.timer = time.NewTimer(monotime.Until(c.idleTimeoutStartTime().Add(c.config.HandshakeIdleTimeout)))

	if err := c.cryptoStreamHandler.StartHandshake(c.ctx); err != nil {
		return err
	}
	if err := c.handleHandshakeEvents(monotime.Now()); err != nil {
		return err
	}
	go func() {
		if err := c.sendQueue.Run(); err != nil {
			c.destroyImpl(err)
		}
	}()

	if c.perspective == protocol.PerspectiveClient {
		c.scheduleSending() // so the ClientHello actually gets sent
	}

	var sendQueueAvailable <-chan struct{}

runLoop:
	for {
		if c.framer.QueuedTooManyControlFrames() {
			c.setCloseError(&closeError{err: &qerr.TransportError{ErrorCode: InternalError}})
			break runLoop
		}
		// Close immediately if requested
		select {
		case <-c.closeChan:
			break runLoop
		default:
		}

		// no need to set a timer if we can send packets immediately
		if c.pacingDeadline != deadlineSendImmediately {
			c.maybeResetTimer()
		}

		// 1st: handle undecryptable packets, if any.
		// This can only occur before completion of the handshake.
		if len(c.undecryptablePacketsToProcess) > 0 {
			var processedUndecryptablePacket bool
			queue := c.undecryptablePacketsToProcess
			c.undecryptablePacketsToProcess = nil
			for _, p := range queue {
				processed, err := c.handleOnePacket(p.receivedPacket, p.datagramID)
				if err != nil {
					c.setCloseError(&closeError{err: err})
					break runLoop
				}
				if processed {
					processedUndecryptablePacket = true
				}
			}
			if processedUndecryptablePacket {
				// if we processed any undecryptable packets, jump to the resetting of the timers directly
				continue
			}
		}

		// 2nd: receive packets.
		processed, err := c.handlePackets() // don't check receivedPackets.Len() in the run loop to avoid locking the mutex
		if err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}

		// We don't need to wait for new events if:
		// * we processed packets: we probably need to send an ACK, and potentially more data
		// * the pacer allows us to send more packets immediately
		shouldProceedImmediately := sendQueueAvailable == nil && (processed || c.pacingDeadline.Equal(deadlineSendImmediately))
		if !shouldProceedImmediately {
			// 3rd: wait for something to happen:
			// * closing of the connection
			// * timer firing
			// * sending scheduled
			// * send queue available
			// * received packets
			select {
			case <-c.closeChan:
				break runLoop
			case <-c.timer.C:
			case <-c.sendingScheduled:
			case <-sendQueueAvailable:
			case <-c.notifyReceivedPacket:
				wasProcessed, err := c.handlePackets()
				if err != nil {
					c.setCloseError(&closeError{err: err})
					break runLoop
				}
				// if we processed any undecryptable packets, jump to the resetting of the timers directly
				if !wasProcessed {
					continue
				}
			}
		}

		// Check for loss detection timeout.
		// This could cause packets to be declared lost, and retransmissions to be enqueued.
		now := monotime.Now()
		if timeout := c.sentPacketHandler.GetLossDetectionTimeout(); !timeout.IsZero() && !timeout.After(now) {
			if err := c.sentPacketHandler.OnLossDetectionTimeout(now); err != nil {
				c.setCloseError(&closeError{err: err})
				break runLoop
			}
			c.maybeRevertQNTMigrationOnPTO(now)
		}
		c.maybeRevertQNTMigrationOnIdle(now)
		if c.qntHandleRetryDeadline(now) {
			c.scheduleSending()
		}

		if keepAliveTime := c.nextKeepAliveTime(); !keepAliveTime.IsZero() && !now.Before(keepAliveTime) {
			// send a PING frame since there is no activity in the connection
			c.logger.Debugf("Sending a keep-alive PING to keep the connection alive.")
			c.framer.QueueControlFrame(&wire.PingFrame{})
			c.keepAlivePingSent = true
		} else if !c.handshakeComplete && now.Sub(c.creationTime) >= c.config.handshakeTimeout() {
			c.destroyImpl(qerr.ErrHandshakeTimeout)
			break runLoop
		} else {
			idleTimeoutStartTime := c.idleTimeoutStartTime()
			if (!c.handshakeComplete && now.Sub(idleTimeoutStartTime) >= c.config.HandshakeIdleTimeout) ||
				(c.handshakeComplete && !now.Before(c.nextIdleTimeoutTime())) {
				c.destroyImpl(qerr.ErrIdleTimeout)
				break runLoop
			}
		}

		c.connIDGenerator.RemoveRetiredConnIDs(now)

		if c.perspective == protocol.PerspectiveClient {
			pm := c.pathManagerOutgoing.Load()
			if pm != nil {
				tr, ok := pm.ShouldSwitchPath()
				if ok {
					c.switchToNewPath(tr, now)
				}
			}
		}

		if c.sendQueue.WouldBlock() {
			// The send queue is still busy sending out packets. Wait until there's space to enqueue new packets.
			sendQueueAvailable = c.sendQueue.Available()
			// Cancel the pacing timer, as we can't send any more packets until the send queue is available again.
			c.pacingDeadline = 0
			c.blocked = blockModeHardBlocked
			continue
		}

		if c.closeErr.Load() != nil {
			break runLoop
		}

		c.blocked = blockModeNone // sending might set it back to true if we're congestion limited
		if err := c.triggerSending(now); err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}
		// Multipath (draft-ietf-quic-multipath) send scheduling (5f). Provision
		// any path the application asked to open, then drive PATH_CHALLENGE
		// validation and per-path 1-RTT sends for every open non-zero path. This
		// runs in the run goroutine, after the ordinary path-0 send, so it never
		// races the sentPacketHandler / packer. It is a no-op until OpenPath.
		if err := c.processOpenPathRequests(); err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}
		c.processSetMigrationFallbackRequests()
		if err := c.processQNTValidatedPathOpen(now); err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}
		c.processPathStatsRequests()
		c.processPathSnapshotRequests()
		c.drainPathDatagrams()
		if err := c.driveMultipath(now); err != nil {
			c.setCloseError(&closeError{err: err})
			break runLoop
		}
		if c.sendQueue.WouldBlock() {
			// The send queue is still busy sending out packets. Wait until there's space to enqueue new packets.
			sendQueueAvailable = c.sendQueue.Available()
			// Cancel the pacing timer, as we can't send any more packets until the send queue is available again.
			c.pacingDeadline = 0
			c.blocked = blockModeHardBlocked
		} else {
			sendQueueAvailable = nil
		}
	}

	closeErr := c.closeErr.Load()
	c.cryptoStreamHandler.Close()
	c.sendQueue.Close() // close the send queue before sending the CONNECTION_CLOSE
	c.handleCloseError(closeErr)
	if c.qlogger != nil {
		if e := (&errCloseForRecreating{}); !errors.As(closeErr.err, &e) {
			c.qlogger.Close()
		}
	}
	c.logger.Infof("Connection %s closed.", c.logID)
	c.timer.Stop()
	return closeErr.err
}

// blocks until the early connection can be used
func (c *Conn) earlyConnReady() <-chan struct{} {
	return c.earlyConnReadyChan
}

// Context returns a context that is cancelled when the connection is closed.
// The cancellation cause is set to the error that caused the connection to close.
func (c *Conn) Context() context.Context {
	return c.ctx
}

func (c *Conn) supportsDatagrams() bool {
	params := c.peerParams.Load()
	return params != nil && params.MaxDatagramFrameSize > 0
}

// ConnectionState returns basic details about the QUIC connection.
func (c *Conn) ConnectionState() ConnectionState {
	c.connStateMutex.Lock()
	defer c.connStateMutex.Unlock()

	cs := c.cryptoStreamHandler.ConnectionState()
	c.connState.TLS = cs.ConnectionState
	c.connState.Used0RTT = cs.Used0RTT
	if params := c.peerParams.Load(); params != nil {
		c.connState.SupportsDatagrams.Remote = params.MaxDatagramFrameSize > 0
		c.connState.SupportsStreamResetPartialDelivery.Remote = params.EnableResetStreamAt
	}
	c.connState.SupportsDatagrams.Local = c.config.EnableDatagrams
	c.connState.SupportsStreamResetPartialDelivery.Local = c.config.EnableStreamResetPartialDelivery
	c.connState.MultipathNegotiated = c.multipathNegotiated()
	c.connState.GSO = c.conn.capabilities().GSO
	return c.connState
}

// ConnectionStats contains statistics about the QUIC connection
type ConnectionStats struct {
	// MinRTT is the estimate of the minimum RTT observed on the active network
	// path.
	MinRTT time.Duration
	// LatestRTT is the last RTT sample observed on the active network path.
	LatestRTT time.Duration
	// SmoothedRTT is an exponentially weighted moving average of an endpoint's
	// RTT samples. See https://www.rfc-editor.org/rfc/rfc9002#section-5.3
	SmoothedRTT time.Duration
	// MeanDeviation estimates the variation in the RTT samples using a mean
	// variation. See https://www.rfc-editor.org/rfc/rfc9002#section-5.3
	MeanDeviation time.Duration

	// BytesSent is the number of bytes sent on the underlying connection,
	// including retransmissions. Does not include UDP or any other outer
	// framing.
	BytesSent uint64
	// PacketsSent is the number of packets sent on the underlying connection,
	// including those that are determined to have been lost.
	PacketsSent uint64
	// BytesReceived is the number of total bytes received on the underlying
	// connection, including duplicate data for streams. Does not include UDP or
	// any other outer framing.
	BytesReceived uint64
	// PacketsReceived is the number of total packets received on the underlying
	// connection, including packets that were not processable.
	PacketsReceived uint64
	// BytesLost is the number of bytes lost on the underlying connection (does
	// not monotonically increase, because packets that are declared lost can
	// subsequently be received). Does not include UDP or any other outer
	// framing.
	BytesLost uint64
	// PacketsLost is the number of packets lost on the underlying connection
	// (does not monotonically increase, because packets that are declared lost
	// can subsequently be received).
	PacketsLost uint64
}

func (c *Conn) ConnectionStats() ConnectionStats {
	return ConnectionStats{
		MinRTT:        c.rttStats.MinRTT(),
		LatestRTT:     c.rttStats.LatestRTT(),
		SmoothedRTT:   c.rttStats.SmoothedRTT(),
		MeanDeviation: c.rttStats.MeanDeviation(),

		BytesSent:       c.connStats.BytesSent.Load(),
		PacketsSent:     c.connStats.PacketsSent.Load(),
		BytesReceived:   c.connStats.BytesReceived.Load(),
		PacketsReceived: c.connStats.PacketsReceived.Load(),
		BytesLost:       c.connStats.BytesLost.Load(),
		PacketsLost:     c.connStats.PacketsLost.Load(),
	}
}

// Time when the connection should time out
func (c *Conn) nextIdleTimeoutTime() monotime.Time {
	idleTimeout := max(c.idleTimeout, c.rttStats.PTO(true)*3)
	return c.idleTimeoutStartTime().Add(idleTimeout)
}

// Time when the next keep-alive packet should be sent.
// It returns a zero time if no keep-alive should be sent.
func (c *Conn) nextKeepAliveTime() monotime.Time {
	if c.config.KeepAlivePeriod == 0 || c.keepAlivePingSent {
		return 0
	}
	keepAliveInterval := max(c.keepAliveInterval, c.rttStats.PTO(true)*3/2)
	return c.lastPacketReceivedTime.Add(keepAliveInterval)
}

func (c *Conn) maybeResetTimer() {
	var deadline monotime.Time
	if !c.handshakeComplete {
		deadline = c.creationTime.Add(c.config.handshakeTimeout())
		if t := c.idleTimeoutStartTime().Add(c.config.HandshakeIdleTimeout); t.Before(deadline) {
			deadline = t
		}
	} else {
		// A keep-alive packet is ack-eliciting, so it can only be sent if the connection is
		// neither congestion limited nor hard-blocked.
		if c.blocked != blockModeNone {
			deadline = c.nextIdleTimeoutTime()
		} else {
			if keepAliveTime := c.nextKeepAliveTime(); !keepAliveTime.IsZero() {
				deadline = keepAliveTime
			} else {
				deadline = c.nextIdleTimeoutTime()
			}
		}
	}
	// If the connection is hard-blocked, we can't even send acknowledgments,
	// nor can we send PTO probe packets.
	if t := c.qntMigrationFallbackDeadline(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if c.blocked == blockModeHardBlocked {
		c.timer.Reset(monotime.Until(deadline))
		return
	}

	if t := c.receivedPacketHandler.GetAlarmTimeout(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if t := c.sentPacketHandler.GetLossDetectionTimeout(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if t := c.qntNextRetryDeadline(); !t.IsZero() && t.Before(deadline) {
		deadline = t
	}
	if c.blocked == blockModeCongestionLimited {
		c.timer.Reset(monotime.Until(deadline))
		return
	}

	if !c.pacingDeadline.IsZero() && c.pacingDeadline.Before(deadline) {
		deadline = c.pacingDeadline
	}
	c.timer.Reset(monotime.Until(deadline))
}

func (c *Conn) idleTimeoutStartTime() monotime.Time {
	startTime := c.lastPacketReceivedTime
	if t := c.firstAckElicitingPacketAfterIdleSentTime; !t.IsZero() && t.After(startTime) {
		startTime = t
	}
	return startTime
}

func (c *Conn) switchToNewPath(tr *Transport, now monotime.Time) {
	initialPacketSize := protocol.ByteCount(c.config.InitialPacketSize)
	c.sentPacketHandler.MigratedPath(now, initialPacketSize)
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if params := c.peerParams.Load(); params.MaxUDPPayloadSize > 0 && params.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = params.MaxUDPPayloadSize
	}
	c.mtuDiscoverer.Reset(now, initialPacketSize, maxPacketSize)
	c.conn = newSendConn(tr.conn, c.conn.RemoteAddr(), packetInfo{}, utils.DefaultLogger) // TODO: find a better way
	c.sendQueue.Close()
	c.sendQueue = newSendQueue(c.conn)
	go func() {
		if err := c.sendQueue.Run(); err != nil {
			c.destroyImpl(err)
		}
	}()
}

func (c *Conn) handleHandshakeComplete(now monotime.Time) error {
	defer close(c.handshakeCompleteChan)
	// Once the handshake completes, we have derived 1-RTT keys.
	// There's no point in queueing undecryptable packets for later decryption anymore.
	c.undecryptablePackets = nil

	c.connIDManager.SetHandshakeComplete()
	c.connIDGenerator.SetHandshakeComplete(now.Add(3 * c.rttStats.PTO(false)))

	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.ALPNInformation{
			ChosenALPN: c.cryptoStreamHandler.ConnectionState().NegotiatedProtocol,
		})
	}

	// The server applies transport parameters right away, but the client side has to wait for handshake completion.
	// During a 0-RTT connection, the client is only allowed to use the new transport parameters for 1-RTT packets.
	if c.perspective == protocol.PerspectiveClient {
		c.applyTransportParameters()
		return nil
	}

	// All these only apply to the server side.
	if err := c.handleHandshakeConfirmed(now); err != nil {
		return err
	}

	ticket, err := c.cryptoStreamHandler.GetSessionTicket()
	if err != nil {
		return err
	}
	if ticket != nil { // may be nil if session tickets are disabled via tls.Config.SessionTicketsDisabled
		c.oneRTTStream.Write(ticket)
		for c.oneRTTStream.HasData() {
			if cf := c.oneRTTStream.PopCryptoFrame(protocol.MaxPostHandshakeCryptoFrameSize); cf != nil {
				c.queueControlFrame(cf)
			}
		}
	}
	token, err := c.tokenGenerator.NewToken(c.conn.RemoteAddr(), c.rttStats.SmoothedRTT())
	if err != nil {
		return err
	}
	c.queueControlFrame(&wire.NewTokenFrame{Token: token})
	c.queueControlFrame(&wire.HandshakeDoneFrame{})
	return nil
}

func (c *Conn) handleHandshakeConfirmed(now monotime.Time) error {
	// Drop initial keys.
	// On the client side, this should have happened when sending the first Handshake packet,
	// but this is not guaranteed if the server misbehaves.
	// See CVE-2025-59530 for more details.
	if err := c.dropEncryptionLevel(protocol.EncryptionInitial, now); err != nil {
		return err
	}
	if err := c.dropEncryptionLevel(protocol.EncryptionHandshake, now); err != nil {
		return err
	}

	c.handshakeConfirmed = true
	c.cryptoStreamHandler.SetHandshakeConfirmed()

	if !c.config.DisablePathMTUDiscovery && c.conn.capabilities().DF {
		c.mtuDiscoverer.Start(now)
	}

	// Advertise the largest PathID we will accept now that 1-RTT keys are
	// confirmed (MAX_PATH_ID is a 1-RTT-only frame). With multipath
	// un-negotiated this queues nothing, so the single-path send loop is
	// unchanged. handleHandshakeConfirmed runs exactly once per connection
	// (gated by !c.handshakeConfirmed at every call site), so the frame is
	// queued exactly once.
	c.queueMaxPathID()
	return nil
}

// ourLocalMaxPathID returns the largest PathID we will accept, i.e. the value
// advertised in our initial_max_path_id transport parameter (Config.InitialMaxPathID,
// transport_parameters.rs:121). MAX_PATH_ID frames raise this initial value; in
// this sub-increment we only advertise the initial value and never raise it, so
// the local max equals the configured value. Caller must hold multipath
// negotiated (Config.InitialMaxPathID != nil).
func (c *Conn) ourLocalMaxPathID() protocol.PathID {
	return protocol.PathID(*c.config.InitialMaxPathID)
}

// queueMaxPathID queues a MAX_PATH_ID frame (frame.rs:1407-1432, type 0x3e7a)
// advertising the largest PathID we will accept (ourLocalMaxPathID). It is a
// no-op unless multipath was negotiated, so a single-path connection never
// emits a MAX_PATH_ID frame and its send loop is byte-identical. MAX_PATH_ID is
// admitted only at 1-RTT (frame_type.go isAllowedAtEncLevel), which is why this
// is called from handleHandshakeConfirmed rather than earlier.
func (c *Conn) queueMaxPathID() {
	if !c.multipathNegotiated() {
		return
	}
	c.queueControlFrame(&wire.MaxPathIDFrame{PathID: c.ourLocalMaxPathID()})
}

// canOpenPath reports whether we may open the path identified by pid. A path may
// be opened only when multipath was negotiated and pid is within both the peer's
// advertised max (the initial_max_path_id transport parameter, raised by
// MAX_PATH_ID frames) and our own advertised max (ourLocalMaxPathID).
// PathIDZero is the always-present initial path and is never "opened" through
// this gate. This is a guard only; this sub-increment does not open any path.
func (c *Conn) canOpenPath(pid protocol.PathID) bool {
	if !c.multipathNegotiated() {
		return false
	}
	if pid == protocol.PathIDZero {
		return false
	}
	peerMax := *c.peerParams.Load().InitialMaxPathID
	if raised, ok := c.multipathManager.peerMax(); ok && raised > peerMax {
		peerMax = raised
	}
	if pid > peerMax {
		return false
	}
	return pid <= c.ourLocalMaxPathID()
}

const maxPacketsToProcess = 32

func (c *Conn) handlePackets() (wasProcessed bool, _ error) {
	// Process packets from the receivedPackets queue.
	// Limit the number of packets to process to maxPacketsToProcess,
	// so we eventually get a chance to send out an ACK when receiving a lot of packets.
	c.receivedPacketMx.Lock()

	if c.receivedPackets.Empty() {
		c.receivedPacketMx.Unlock()
		return false, nil
	}

	var hasMorePackets bool
	for range maxPacketsToProcess {
		p := c.receivedPackets.PopFront()
		c.receivedPacketMx.Unlock()

		var datagramID qlog.DatagramID
		if c.qlogger != nil && wire.IsLongHeaderPacket(p.data[0]) {
			datagramID = qlog.CalculateDatagramID(p.data)
		}
		processed, err := c.handleOnePacket(p, datagramID)
		if err != nil {
			return false, err
		}
		if processed {
			wasProcessed = true
		}
		c.receivedPacketMx.Lock()
		hasMorePackets = !c.receivedPackets.Empty()
		if !hasMorePackets {
			break
		}
		// Prioritize sending of new CRYPTO data.
		// This is especially relevant when processing 0-RTT packets.
		if !c.handshakeComplete && (c.initialStream.HasData() || c.handshakeStream.HasData()) {
			break
		}
	}
	c.receivedPacketMx.Unlock()

	if hasMorePackets {
		select {
		case c.notifyReceivedPacket <- struct{}{}:
		default:
		}
	}
	return wasProcessed, nil
}

func (c *Conn) handleOnePacket(rp receivedPacket, datagramID qlog.DatagramID) (wasProcessed bool, _ error) {
	c.sentPacketHandler.ReceivedBytes(rp.Size(), rp.rcvTime)

	if wire.IsVersionNegotiationPacket(rp.data) {
		return false, c.handleVersionNegotiationPacket(rp)
	}

	var counter uint8
	var lastConnID protocol.ConnectionID
	data := rp.data
	p := rp
	for len(data) > 0 {
		if counter > 0 {
			p = *(p.Clone())
			p.data = data

			destConnID, err := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			if err != nil {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Raw:        qlog.RawInfo{Length: len(data)},
						DatagramID: datagramID,
						Trigger:    qlog.PacketDropHeaderParseError,
					})
				}
				c.logger.Debugf("error parsing packet, couldn't parse connection ID: %s", err)
				break
			}
			if destConnID != lastConnID {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Header:     qlog.PacketHeader{DestConnectionID: destConnID},
						Raw:        qlog.RawInfo{Length: len(data)},
						DatagramID: datagramID,
						Trigger:    qlog.PacketDropUnknownConnectionID,
					})
				}
				c.logger.Debugf("coalesced packet has different destination connection ID: %s, expected %s", destConnID, lastConnID)
				break
			}
		}

		if wire.IsLongHeaderPacket(p.data[0]) {
			hdr, packetData, rest, err := wire.ParsePacket(p.data)
			if err != nil {
				if c.qlogger != nil {
					if err == wire.ErrUnsupportedVersion {
						c.qlogger.RecordEvent(qlog.PacketDropped{
							Header:     qlog.PacketHeader{Version: hdr.Version},
							Raw:        qlog.RawInfo{Length: len(data)},
							DatagramID: datagramID,
							Trigger:    qlog.PacketDropUnsupportedVersion,
						})
					} else {
						c.qlogger.RecordEvent(qlog.PacketDropped{
							Raw:        qlog.RawInfo{Length: len(data)},
							DatagramID: datagramID,
							Trigger:    qlog.PacketDropHeaderParseError,
						})
					}
				}
				c.logger.Debugf("error parsing packet: %s", err)
				break
			}
			lastConnID = hdr.DestConnectionID

			if hdr.Version != c.version {
				if c.qlogger != nil {
					c.qlogger.RecordEvent(qlog.PacketDropped{
						Raw:        qlog.RawInfo{Length: len(data)},
						DatagramID: datagramID,
						Trigger:    qlog.PacketDropUnexpectedVersion,
					})
				}
				c.logger.Debugf("Dropping packet with version %x. Expected %x.", hdr.Version, c.version)
				break
			}

			if counter > 0 {
				p.buffer.Split()
			}
			counter++

			// only log if this actually a coalesced packet
			if c.logger.Debug() && (counter > 1 || len(rest) > 0) {
				c.logger.Debugf("Parsed a coalesced packet. Part %d: %d bytes. Remaining: %d bytes.", counter, len(packetData), len(rest))
			}

			p.data = packetData

			processed, err := c.handleLongHeaderPacket(p, hdr, datagramID)
			if err != nil {
				return false, err
			}
			if processed {
				wasProcessed = true
			}
			data = rest
		} else {
			if counter > 0 {
				p.buffer.Split()
			}
			processed, err := c.handleShortHeaderPacket(p, counter > 0, datagramID)
			if err != nil {
				return false, err
			}
			if processed {
				wasProcessed = true
			}
			break
		}
	}

	p.buffer.MaybeRelease()
	c.blocked = blockModeNone
	return wasProcessed, nil
}

func (c *Conn) handleShortHeaderPacket(
	p receivedPacket,
	isCoalesced bool,
	datagramID qlog.DatagramID, // only for logging
) (wasProcessed bool, _ error) {
	var wasQueued bool

	defer func() {
		// Put back the packet buffer if the packet wasn't queued for later decryption.
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	destConnID, err := wire.ParseConnectionID(p.data, c.srcConnIDLen)
	if err != nil {
		c.qlogger.RecordEvent(qlog.PacketDropped{
			Header: qlog.PacketHeader{
				PacketType:   qlog.PacketType1RTT,
				PacketNumber: protocol.InvalidPacketNumber,
			},
			Raw:        qlog.RawInfo{Length: len(p.data)},
			DatagramID: datagramID,
			Trigger:    qlog.PacketDropHeaderParseError,
		})
		return false, nil
	}
	// Resolve which multipath PathID this 1-RTT packet arrived on, from its
	// destination connection ID. With multipath off this is always PathIDZero,
	// so duplicate detection and received-packet tracking are byte-identical to
	// single-path.
	pid := c.pathForReceivedConnID(destConnID)
	pn, pnLen, keyPhase, data, err := c.unpacker.UnpackShortHeader(p.rcvTime, pid, p.data)
	if err != nil {
		// Stateless reset packets (see RFC 9000, section 10.3):
		// * fill the entire UDP datagram (i.e. they cannot be part of a coalesced packet)
		// * are short header packets (first bit is 0)
		// * have the QUIC bit set (second bit is 1)
		// * are at least 21 bytes long
		if !isCoalesced && len(p.data) >= protocol.MinReceivedStatelessResetSize && p.data[0]&0b11000000 == 0b01000000 {
			token := protocol.StatelessResetToken(p.data[len(p.data)-16:])
			if c.connIDManager.IsActiveStatelessResetToken(token) {
				return false, &StatelessResetError{}
			}
		}
		wasQueued, err = c.handleUnpackError(err, p, qlog.PacketType1RTT, datagramID)
		return false, err
	}
	c.largestRcvdAppData = max(c.largestRcvdAppData, pn)

	if c.logger.Debug() {
		c.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, 1-RTT", pn, p.Size(), destConnID)
		wire.LogShortHeader(c.logger, destConnID, pn, pnLen, keyPhase)
	}

	if c.isPotentiallyDuplicate1RTT(pn, pid) {
		c.logger.Debugf("Dropping (potentially) duplicate packet.")
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType1RTT,
					PacketNumber: pn,
				},
				Raw:        qlog.RawInfo{Length: int(p.Size())},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropDuplicate,
			})
		}
		return false, nil
	}

	var log func([]qlog.Frame)
	if c.qlogger != nil {
		log = func(frames []qlog.Frame) {
			c.qlogger.RecordEvent(qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketType1RTT,
					DestConnectionID: destConnID,
					PacketNumber:     pn,
					KeyPhaseBit:      keyPhase,
				},
				Raw: qlog.RawInfo{
					Length:        int(p.Size()),
					PayloadLength: int(p.Size() - wire.ShortHeaderLen(destConnID, pnLen)),
				},
				DatagramID: datagramID,
				Frames:     frames,
				ECN:        toQlogECN(p.ecn),
			})
		}
	}
	isNonProbing, pathChallenge, err := c.handleUnpackedShortHeaderPacket(destConnID, pn, data, protocol.ByteCount(p.Size()), packetSourceAddrPort(p.remoteAddr), p.ecn, p.rcvTime, log)
	if err != nil {
		return false, err
	}

	// QUIC Address Discovery: report the source address of this 1-RTT packet
	// back to the peer so it learns its reflexive address. This is a no-op
	// unless address discovery was negotiated to report, so it is inert (and
	// byte-identical) on a connection that did not negotiate QAD.
	c.maybeQueueObservedAddr(p.remoteAddr)

	// QNT probes are PATH_CHALLENGE packets sent to advertised candidate
	// addresses. Answer here so the peer can match the PATH_RESPONSE to its QNT
	// probe. Two cases arrive on this path:
	//   - loopback: the candidate is the existing 4-tuple, so p.remoteAddr equals
	//     c.RemoteAddr() and the migration path manager below will not run;
	//   - cross-host: the candidate is a NEW direct 4-tuple distinct from the
	//     (possibly relayed) existing remote. RFC 9000 migration rules would let
	//     only the server answer, and only for the existing path, so a direct
	//     candidate would never be validated. QNT is a symmetric holepunch: both
	//     perspectives must answer a challenge that arrives from a known QNT
	//     candidate, on that same 4-tuple.
	// This runs before the RFC 9000 client-migration early-return below so the
	// client also answers QNT probes on new candidate paths.
	if pathChallenge != nil && c.qntNegotiated() &&
		(addrsEqual(p.remoteAddr, c.RemoteAddr()) || c.qntKnownCandidate(packetSourceAddrPort(p.remoteAddr))) {
		probe, buf, err := c.packer.PackPathProbePacket(c.connIDManager.Get(), []ackhandler.Frame{
			{Frame: &wire.PathResponseFrame{Data: pathChallenge.Data}},
		}, c.version)
		if err != nil {
			return true, err
		}
		c.logger.Debugf("sending QNT path response packet to %s", p.remoteAddr)
		c.logShortHeaderPacketWithDatagramID(probe, protocol.ECNNon, buf.Len(), false, datagramID)
		c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, p.rcvTime)
		c.sendQNTProbeBufferWithInfo(buf, p.remoteAddr, p.info)
	}

	// In RFC 9000, only the client can migrate between paths.
	if c.perspective == protocol.PerspectiveClient {
		return true, nil
	}
	if addrsEqual(p.remoteAddr, c.RemoteAddr()) {
		return true, nil
	}

	var shouldSwitchPath bool
	if c.pathManager == nil {
		c.pathManager = newPathManager(
			c.connIDManager.GetConnIDForPath,
			c.connIDManager.RetireConnIDForPath,
			c.logger,
		)
	}
	destConnID, frames, shouldSwitchPath := c.pathManager.HandlePacket(p.remoteAddr, p.rcvTime, pathChallenge, isNonProbing)
	if len(frames) > 0 {
		probe, buf, err := c.packer.PackPathProbePacket(destConnID, frames, c.version)
		if err != nil {
			return true, err
		}
		c.logger.Debugf("sending path probe packet to %s", p.remoteAddr)
		c.logShortHeaderPacketWithDatagramID(probe, protocol.ECNNon, buf.Len(), false, datagramID)
		c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, p.rcvTime)
		c.sendQNTProbeBufferWithInfo(buf, p.remoteAddr, p.info)
	}
	// We only switch paths in response to the highest-numbered non-probing packet,
	// see section 9.3 of RFC 9000.
	if !shouldSwitchPath || pn != c.largestRcvdAppData {
		return true, nil
	}
	c.pathManager.SwitchToPath(p.remoteAddr)
	c.sentPacketHandler.MigratedPath(p.rcvTime, protocol.ByteCount(c.config.InitialPacketSize))
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if params := c.peerParams.Load(); params.MaxUDPPayloadSize > 0 && params.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = params.MaxUDPPayloadSize
	}
	c.mtuDiscoverer.Reset(
		p.rcvTime,
		protocol.ByteCount(c.config.InitialPacketSize),
		maxPacketSize,
	)
	c.conn.ChangeRemoteAddr(p.remoteAddr, p.info)
	return true, nil
}

func (c *Conn) handleLongHeaderPacket(p receivedPacket, hdr *wire.Header, datagramID qlog.DatagramID) (wasProcessed bool, _ error) {
	var wasQueued bool

	defer func() {
		// Put back the packet buffer if the packet wasn't queued for later decryption.
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	if hdr.Type == protocol.PacketTypeRetry {
		return c.handleRetryPacket(hdr, p.data, p.rcvTime), nil
	}

	// The server can change the source connection ID with the first Handshake packet.
	// After this, all packets with a different source connection have to be ignored.
	if c.receivedFirstPacket && hdr.Type == protocol.PacketTypeInitial && hdr.SrcConnectionID != c.handshakeDestConnID {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketTypeInitial,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:        qlog.RawInfo{Length: int(p.Size())},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropUnknownConnectionID,
			})
		}
		c.logger.Debugf("Dropping Initial packet (%d bytes) with unexpected source connection ID: %s (expected %s)", p.Size(), hdr.SrcConnectionID, c.handshakeDestConnID)
		return false, nil
	}
	// drop 0-RTT packets, if we are a client
	if c.perspective == protocol.PerspectiveClient && hdr.Type == protocol.PacketType0RTT {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:        qlog.RawInfo{Length: int(p.Size())},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropUnexpectedPacket,
			})
		}
		return false, nil
	}

	packet, err := c.unpacker.UnpackLongHeader(hdr, p.data)
	if err != nil {
		wasQueued, err = c.handleUnpackError(err, p, toQlogPacketType(hdr.Type), datagramID)
		return false, err
	}

	if c.logger.Debug() {
		c.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, %s", packet.hdr.PacketNumber, p.Size(), hdr.DestConnectionID, packet.encryptionLevel)
		packet.hdr.Log(c.logger)
	}

	if pn := packet.hdr.PacketNumber; c.receivedPacketHandler.IsPotentiallyDuplicate(pn, packet.encryptionLevel) {
		c.logger.Debugf("Dropping (potentially) duplicate packet.")
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       toQlogPacketType(packet.hdr.Type),
					DestConnectionID: hdr.DestConnectionID,
					SrcConnectionID:  hdr.SrcConnectionID,
					PacketNumber:     pn,
					Version:          packet.hdr.Version,
				},
				Raw:        qlog.RawInfo{Length: int(p.Size()), PayloadLength: int(packet.hdr.Length)},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropDuplicate,
			})
		}
		return false, nil
	}

	if err := c.handleUnpackedLongHeaderPacket(packet, p.ecn, p.rcvTime, datagramID, p.Size()); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Conn) handleUnpackError(err error, p receivedPacket, pt qlog.PacketType, datagramID qlog.DatagramID) (wasQueued bool, _ error) {
	switch err {
	case handshake.ErrKeysDropped:
		if c.qlogger != nil {
			connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       pt,
					DestConnectionID: connID,
					PacketNumber:     protocol.InvalidPacketNumber,
				},
				Raw:        qlog.RawInfo{Length: int(p.Size())},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropKeyUnavailable,
			})
		}
		c.logger.Debugf("Dropping %s packet (%d bytes) because we already dropped the keys.", pt, p.Size())
		return false, nil
	case handshake.ErrKeysNotYetAvailable:
		// Sealer for this encryption level not yet available.
		// Try again later.
		c.tryQueueingUndecryptablePacket(p, pt, datagramID)
		return true, nil
	case wire.ErrInvalidReservedBits:
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: err.Error(),
		}
	case handshake.ErrDecryptionFailed:
		// This might be a packet injected by an attacker. Drop it.
		if c.qlogger != nil {
			connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       pt,
					DestConnectionID: connID,
					PacketNumber:     protocol.InvalidPacketNumber,
				},
				Raw:        qlog.RawInfo{Length: int(p.Size())},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropPayloadDecryptError,
			})
		}
		c.logger.Debugf("Dropping %s packet (%d bytes) that could not be unpacked. Error: %s", pt, p.Size(), err)
		return false, nil
	default:
		var headerErr *headerParseError
		if errors.As(err, &headerErr) {
			// This might be a packet injected by an attacker. Drop it.
			if c.qlogger != nil {
				connID, _ := wire.ParseConnectionID(p.data, c.srcConnIDLen)
				c.qlogger.RecordEvent(qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:       pt,
						DestConnectionID: connID,
						PacketNumber:     protocol.InvalidPacketNumber,
					},
					Raw:        qlog.RawInfo{Length: int(p.Size())},
					DatagramID: datagramID,
					Trigger:    qlog.PacketDropHeaderParseError,
				})
			}
			c.logger.Debugf("Dropping %s packet (%d bytes) for which we couldn't unpack the header. Error: %s", pt, p.Size(), err)
			return false, nil
		}
		// This is an error returned by the AEAD (other than ErrDecryptionFailed).
		// For example, a PROTOCOL_VIOLATION due to key updates.
		return false, err
	}
}

func (c *Conn) handleRetryPacket(hdr *wire.Header, data []byte, rcvTime monotime.Time) bool /* was this a valid Retry */ {
	if c.perspective == protocol.PerspectiveServer {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry.")
		return false
	}
	if c.receivedFirstPacket {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry, since we already received a packet.")
		return false
	}
	destConnID := c.connIDManager.Get()
	if hdr.SrcConnectionID == destConnID {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		c.logger.Debugf("Ignoring Retry, since the server didn't change the Source Connection ID.")
		return false
	}
	// If a token is already set, this means that we already received a Retry from the server.
	// Ignore this Retry packet.
	if c.receivedRetry {
		c.logger.Debugf("Ignoring Retry, since a Retry was already received.")
		return false
	}

	tag := handshake.GetRetryIntegrityTag(data[:len(data)-16], destConnID, hdr.Version)
	if !bytes.Equal(data[len(data)-16:], tag[:]) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  hdr.SrcConnectionID,
					DestConnectionID: hdr.DestConnectionID,
					Version:          hdr.Version,
				},
				Raw:     qlog.RawInfo{Length: len(data)},
				Trigger: qlog.PacketDropPayloadDecryptError,
			})
		}
		c.logger.Debugf("Ignoring spoofed Retry. Integrity Tag doesn't match.")
		return false
	}

	newDestConnID := hdr.SrcConnectionID
	c.receivedRetry = true
	c.sentPacketHandler.ResetForRetry(rcvTime)
	c.handshakeDestConnID = newDestConnID
	c.retrySrcConnID = &newDestConnID
	c.cryptoStreamHandler.ChangeConnectionID(newDestConnID)
	c.packer.SetToken(hdr.Token)
	c.connIDManager.ChangeInitialConnID(newDestConnID)

	if c.logger.Debug() {
		c.logger.Debugf("<- Received Retry:")
		(&wire.ExtendedHeader{Header: *hdr}).Log(c.logger)
		c.logger.Debugf("Switching destination connection ID to: %s", hdr.SrcConnectionID)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.PacketReceived{
			Header: qlog.PacketHeader{
				PacketType:       qlog.PacketTypeRetry,
				DestConnectionID: destConnID,
				SrcConnectionID:  newDestConnID,
				Version:          hdr.Version,
				Token:            &qlog.Token{Raw: hdr.Token},
			},
			Raw: qlog.RawInfo{Length: len(data)},
		})
	}

	c.scheduleSending()
	return true
}

func (c *Conn) handleVersionNegotiationPacket(p receivedPacket) error {
	if c.perspective == protocol.PerspectiveServer || // servers never receive version negotiation packets
		c.receivedFirstPacket || c.versionNegotiated { // ignore delayed / duplicated version negotiation packets
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			})
		}
		return nil
	}

	src, dest, supportedVersions, err := wire.ParseVersionNegotiationPacket(p.data)
	if err != nil {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropHeaderParseError,
			})
		}
		c.logger.Debugf("Error parsing Version Negotiation packet: %s", err)
		return nil
	}

	if slices.Contains(supportedVersions, c.version) {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropUnexpectedVersion,
			})
		}
		// The Version Negotiation packet contains the version that we offered.
		// This might be a packet sent by an attacker, or it was corrupted.
		return nil
	}

	c.logger.Infof("Received a Version Negotiation packet. Supported Versions: %s", supportedVersions)
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.VersionNegotiationReceived{
			Header: qlog.PacketHeaderVersionNegotiation{
				DestConnectionID: dest,
				SrcConnectionID:  src,
			},
			SupportedVersions: supportedVersions,
		})
	}
	newVersion, ok := protocol.ChooseSupportedVersion(c.config.Versions, supportedVersions)
	if !ok {
		c.destroyImpl(&VersionNegotiationError{
			Ours:   c.config.Versions,
			Theirs: supportedVersions,
		})
		c.logger.Infof("No compatible QUIC version found.")
		return nil
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.VersionInformation{
			ChosenVersion:  newVersion,
			ClientVersions: c.config.Versions,
			ServerVersions: supportedVersions,
		})
	}

	c.logger.Infof("Switching to QUIC version %s.", newVersion)
	nextPN, _ := c.sentPacketHandler.PeekPacketNumber(protocol.EncryptionInitial)
	return &errCloseForRecreating{
		nextPacketNumber: nextPN,
		nextVersion:      newVersion,
	}
}

func (c *Conn) handleUnpackedLongHeaderPacket(
	packet *unpackedPacket,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	datagramID qlog.DatagramID, // only for logging
	packetSize protocol.ByteCount, // only for logging
) error {
	if !c.receivedFirstPacket {
		c.receivedFirstPacket = true
		if !c.versionNegotiated && c.qlogger != nil {
			var clientVersions, serverVersions []Version
			switch c.perspective {
			case protocol.PerspectiveClient:
				clientVersions = c.config.Versions
			case protocol.PerspectiveServer:
				serverVersions = c.config.Versions
			}
			c.qlogger.RecordEvent(qlog.VersionInformation{
				ChosenVersion:  c.version,
				ClientVersions: clientVersions,
				ServerVersions: serverVersions,
			})
		}
		// The server can change the source connection ID with the first Handshake packet.
		if c.perspective == protocol.PerspectiveClient && packet.hdr.SrcConnectionID != c.handshakeDestConnID {
			cid := packet.hdr.SrcConnectionID
			c.logger.Debugf("Received first packet. Switching destination connection ID to: %s", cid)
			c.handshakeDestConnID = cid
			c.connIDManager.ChangeInitialConnID(cid)
		}
		// We create the connection as soon as we receive the first packet from the client.
		// We do that before authenticating the packet.
		// That means that if the source connection ID was corrupted,
		// we might have created a connection with an incorrect source connection ID.
		// Once we authenticate the first packet, we need to update it.
		if c.perspective == protocol.PerspectiveServer {
			if packet.hdr.SrcConnectionID != c.handshakeDestConnID {
				c.handshakeDestConnID = packet.hdr.SrcConnectionID
				c.connIDManager.ChangeInitialConnID(packet.hdr.SrcConnectionID)
			}
			if c.qlogger != nil {
				var srcAddr, destAddr *net.UDPAddr
				if addr, ok := c.conn.LocalAddr().(*net.UDPAddr); ok {
					srcAddr = addr
				}
				if addr, ok := c.conn.RemoteAddr().(*net.UDPAddr); ok {
					destAddr = addr
				}
				c.qlogger.RecordEvent(startedConnectionEvent(srcAddr, destAddr))
			}
		}
	}

	if c.perspective == protocol.PerspectiveServer && packet.encryptionLevel == protocol.EncryptionHandshake &&
		!c.droppedInitialKeys {
		// On the server side, Initial keys are dropped as soon as the first Handshake packet is received.
		// See Section 4.9.1 of RFC 9001.
		if err := c.dropEncryptionLevel(protocol.EncryptionInitial, rcvTime); err != nil {
			return err
		}
	}

	c.lastPacketReceivedTime = rcvTime
	c.firstAckElicitingPacketAfterIdleSentTime = 0
	c.keepAlivePingSent = false

	if packet.hdr.Type == protocol.PacketType0RTT {
		c.largestRcvdAppData = max(c.largestRcvdAppData, packet.hdr.PacketNumber)
	}

	var log func([]qlog.Frame)
	if c.qlogger != nil {
		log = func(frames []qlog.Frame) {
			var token *qlog.Token
			if len(packet.hdr.Token) > 0 {
				token = &qlog.Token{Raw: packet.hdr.Token}
			}
			c.qlogger.RecordEvent(qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       toQlogPacketType(packet.hdr.Type),
					DestConnectionID: packet.hdr.DestConnectionID,
					SrcConnectionID:  packet.hdr.SrcConnectionID,
					PacketNumber:     packet.hdr.PacketNumber,
					Version:          packet.hdr.Version,
					Token:            token,
				},
				Raw: qlog.RawInfo{
					Length:        int(packetSize),
					PayloadLength: int(packet.hdr.Length),
				},
				DatagramID: datagramID,
				Frames:     frames,
				ECN:        toQlogECN(ecn),
			})
		}
	}
	isAckEliciting, _, _, err := c.handleFrames(packet.data, packet.hdr.DestConnectionID, packet.encryptionLevel, log, rcvTime, netip.AddrPort{})
	if err != nil {
		return err
	}
	c.sentPacketHandler.ReceivedPacket(packet.encryptionLevel, rcvTime)
	return c.receivedPacketHandler.ReceivedPacket(packet.hdr.PacketNumber, ecn, packet.encryptionLevel, rcvTime, isAckEliciting)
}

func (c *Conn) handleUnpackedShortHeaderPacket(
	destConnID protocol.ConnectionID,
	pn protocol.PacketNumber,
	data []byte,
	packetSize protocol.ByteCount,
	source netip.AddrPort,
	ecn protocol.ECN,
	rcvTime monotime.Time,
	log func([]qlog.Frame),
) (isNonProbing bool, pathChallenge *wire.PathChallengeFrame, _ error) {
	c.lastPacketReceivedTime = rcvTime
	c.firstAckElicitingPacketAfterIdleSentTime = 0
	c.keepAlivePingSent = false

	// Resolve which multipath PathID this packet arrived on from its destination
	// connection ID. With multipath off this is always PathIDZero, so the receive
	// bookkeeping below is byte-identical to single-path.
	pid := c.pathForReceivedConnID(destConnID)
	if pid != protocol.PathIDZero {
		// Ensure the path is provisioned before we account a received packet on
		// it. It normally already is (we joined when the peer issued its path CID),
		// but guard against a packet that races the join.
		if !c.maybeJoinPath(pid) {
			pid = protocol.PathIDZero
		}
	}

	isAckEliciting, isNonProbing, pathChallenge, err := c.handleFrames(data, destConnID, protocol.Encryption1RTT, log, rcvTime, source)
	if err != nil {
		return false, nil, err
	}
	c.sentPacketHandler.ReceivedPacketForPath(pid, packetSize, rcvTime)
	if pid == protocol.PathIDZero {
		if err := c.receivedPacketHandler.ReceivedPacket(pn, ecn, protocol.Encryption1RTT, rcvTime, isAckEliciting); err != nil {
			return false, nil, err
		}
	} else {
		// Track the packet in pid's own received-packet space so it is
		// acknowledged as a PATH_ACK{pid} (5e), not folded into path 0's ACK.
		if err := c.receivedPacketHandler.ReceivedPacketForPath(pn, ecn, pid, rcvTime, isAckEliciting); err != nil {
			return false, nil, err
		}
		// A PATH_CHALLENGE that arrived on a non-zero path validates that path for
		// the peer; respond with a PATH_RESPONSE. We send it on the same non-zero
		// path so the response rides pid's connection ID. RFC 9000 §8.2 allows the
		// response on any path, but keeping it on pid keeps the two paths'
		// signaling self-contained (paths.rs:505-506). The RFC 9000 single-path
		// migration responder (pathManager) is bypassed for non-zero paths.
		if pathChallenge != nil {
			c.queueMultipathPathResponse(pid, pathChallenge.Data)
			// consume it so the single-path migration logic in
			// handleShortHeaderPacket does not also act on it.
			pathChallenge = nil
		}
		c.scheduleSending()
	}
	return isNonProbing, pathChallenge, nil
}

// queueMultipathPathResponse records a PATH_RESPONSE to send on a non-zero
// multipath path. It is driven out by driveMultipath (sendOnPath does not carry
// it; PATH_RESPONSE must echo the challenge promptly, so it goes through a
// dedicated per-path response queue). Run goroutine only.
func (c *Conn) queueMultipathPathResponse(pid protocol.PathID, data [8]byte) {
	if c.multipathOut == nil {
		c.multipathOut = newMultipathOutgoing()
	}
	c.multipathOut.queuePathResponse(pid, data)
}

// handleFrames parses the frames, one after the other, and handles them.
// It returns the last PATH_CHALLENGE frame contained in the packet, if any.
func (c *Conn) handleFrames(
	data []byte,
	destConnID protocol.ConnectionID,
	encLevel protocol.EncryptionLevel,
	log func([]qlog.Frame),
	rcvTime monotime.Time,
	source netip.AddrPort,
) (isAckEliciting, isNonProbing bool, pathChallenge *wire.PathChallengeFrame, _ error) {
	// Only used for tracing.
	// If we're not tracing, this slice will always remain empty.
	var frames []qlog.Frame
	if log != nil {
		frames = make([]qlog.Frame, 0, 4)
	}
	handshakeWasComplete := c.handshakeComplete
	var handleErr error
	var skipHandling bool

	for len(data) > 0 {
		frameType, l, err := c.frameParser.ParseType(data, encLevel)
		if err != nil {
			// The frame parser skips over PADDING frames, and returns an io.EOF if the PADDING
			// frames were the last frames in this packet.
			if err == io.EOF {
				break
			}
			return false, false, nil, err
		}
		data = data[l:]

		if ackhandler.IsFrameTypeAckEliciting(frameType) {
			isAckEliciting = true
		}
		if !wire.IsProbingFrameType(frameType) {
			isNonProbing = true
		}

		// We're inlining common cases, to avoid using interfaces
		// Fast path: STREAM, DATAGRAM and ACK
		if frameType.IsStreamFrameType() {
			streamFrame, l, err := c.frameParser.ParseStreamFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(streamFrame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, streamFrame, false)
			handleErr = c.streamsMap.HandleStreamFrame(streamFrame, rcvTime)
		} else if frameType.IsAckFrameType() {
			ackFrame, l, err := c.frameParser.ParseAckFrame(frameType, data, encLevel, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]
			if log != nil {
				frames = append(frames, toQlogFrame(ackFrame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, ackFrame, false)
			handleErr = c.handleAckFrame(ackFrame, encLevel, rcvTime)
		} else if frameType.IsDatagramFrameType() {
			datagramFrame, l, err := c.frameParser.ParseDatagramFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(datagramFrame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			wire.LogFrame(c.logger, datagramFrame, false)
			handleErr = c.handleDatagramFrame(datagramFrame)
		} else if frameType == wire.FrameTypeMaxData {
			maximumData, l, err := wire.ParseMaxDataFrame(data)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil || c.logger.Debug() {
				frame := wire.MaxDataFrame{MaximumData: maximumData}
				if log != nil {
					frames = append(frames, toQlogFrame(&frame))
				}
				if !skipHandling {
					wire.LogFrame(c.logger, &frame, false)
				}
			}
			if skipHandling {
				continue
			}
			if c.connFlowController.UpdateSendWindow(maximumData) {
				c.streamsMap.OnConnectionSendWindowUpdated()
				c.scheduleSending()
			}
		} else if frameType == wire.FrameTypeMaxStreamData {
			id, maximumStreamData, l, err := wire.ParseMaxStreamDataFrame(data)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil || c.logger.Debug() {
				frame := wire.MaxStreamDataFrame{StreamID: id, MaximumStreamData: maximumStreamData}
				if log != nil {
					frames = append(frames, toQlogFrame(&frame))
				}
				if !skipHandling {
					wire.LogFrame(c.logger, &frame, false)
				}
			}
			if skipHandling {
				continue
			}
			handleErr = c.streamsMap.HandleMaxStreamDataFrameFields(id, maximumStreamData)
		} else {
			frame, l, err := c.frameParser.ParseLessCommonFrame(frameType, data, c.version)
			if err != nil {
				return false, false, nil, err
			}
			data = data[l:]

			if log != nil {
				frames = append(frames, toQlogFrame(frame))
			}
			// an error occurred handling a previous frame, don't handle the current frame
			if skipHandling {
				continue
			}
			pc, err := c.handleFrame(frame, encLevel, destConnID, rcvTime, source)
			if pc != nil {
				pathChallenge = pc
			}
			handleErr = err
		}

		if handleErr != nil {
			// if we're logging, we need to keep parsing (but not handling) all frames
			skipHandling = true
			if log == nil {
				return false, false, nil, handleErr
			}
		}
	}

	if log != nil {
		log(frames)
		if handleErr != nil {
			return false, false, nil, handleErr
		}
	}

	// Handle completion of the handshake after processing all the frames.
	// This ensures that we correctly handle the following case on the server side:
	// We receive a Handshake packet that contains the CRYPTO frame that allows us to complete the handshake,
	// and an ACK serialized after that CRYPTO frame. In this case, we still want to process the ACK frame.
	if !handshakeWasComplete && c.handshakeComplete {
		if err := c.handleHandshakeComplete(rcvTime); err != nil {
			return false, false, nil, err
		}
	}
	return
}

func (c *Conn) handleFrame(
	f wire.Frame,
	encLevel protocol.EncryptionLevel,
	destConnID protocol.ConnectionID,
	rcvTime monotime.Time,
	source netip.AddrPort,
) (pathChallenge *wire.PathChallengeFrame, _ error) {
	var err error
	wire.LogFrame(c.logger, f, false)
	switch frame := f.(type) {
	case *wire.CryptoFrame:
		err = c.handleCryptoFrame(frame, encLevel, rcvTime)
	case *wire.ConnectionCloseFrame:
		err = c.handleConnectionCloseFrame(frame)
	case *wire.ResetStreamFrame:
		err = c.streamsMap.HandleResetStreamFrame(frame, rcvTime)
	case *wire.MaxDataFrame:
		if c.connFlowController.UpdateSendWindow(frame.MaximumData) {
			c.streamsMap.OnConnectionSendWindowUpdated()
			c.scheduleSending()
		}
	case *wire.MaxStreamDataFrame:
		err = c.streamsMap.HandleMaxStreamDataFrame(frame)
	case *wire.MaxStreamsFrame:
		c.streamsMap.HandleMaxStreamsFrame(frame)
	case *wire.DataBlockedFrame:
	case *wire.StreamDataBlockedFrame:
		err = c.streamsMap.HandleStreamDataBlockedFrame(frame)
	case *wire.StreamsBlockedFrame:
	case *wire.StopSendingFrame:
		err = c.streamsMap.HandleStopSendingFrame(frame)
	case *wire.PingFrame:
	case *wire.PathChallengeFrame:
		c.handlePathChallengeFrame(frame)
		pathChallenge = frame
	case *wire.PathResponseFrame:
		err = c.handlePathResponseFrame(frame, source)
	case *wire.NewTokenFrame:
		err = c.handleNewTokenFrame(frame)
	case *wire.NewConnectionIDFrame:
		err = c.handleNewConnectionIDFrame(frame)
	case *wire.RetireConnectionIDFrame:
		err = c.handleRetireConnectionIDFrame(frame, destConnID, rcvTime.Add(3*c.rttStats.PTO(false)))
	case *wire.HandshakeDoneFrame:
		err = c.handleHandshakeDoneFrame(rcvTime)
	case *wire.PathAckFrame:
		err = c.handlePathAckFrame(frame, rcvTime)
	case *wire.PathStatusBackupFrame:
		err = c.handlePathStatusBackupFrame(frame)
	case *wire.PathStatusAvailableFrame:
		err = c.handlePathStatusAvailableFrame(frame)
	case *wire.PathAbandonFrame:
		err = c.handlePathAbandonFrame(frame)
	case *wire.MaxPathIDFrame:
		err = c.handleMaxPathIDFrame(frame)
	case *wire.PathsBlockedFrame:
		err = c.handlePathsBlockedFrame(frame)
	case *wire.PathCIDsBlockedFrame:
		err = c.handlePathCIDsBlockedFrame(frame)
	case *wire.ObservedAddrFrame:
		err = c.handleObservedAddrFrame(frame)
	case *wire.AddAddressFrame:
		err = c.handleAddAddressFrame(frame)
	case *wire.ReachOutFrame:
		err = c.handleReachOutFrame(frame)
	case *wire.RemoveAddressFrame:
		err = c.handleRemoveAddressFrame(frame)
	default:
		err = fmt.Errorf("unexpected frame type: %s", reflect.ValueOf(&frame).Elem().Type().Name())
	}
	return pathChallenge, err
}

// handleNewConnectionIDFrame routes a NEW_CONNECTION_ID frame. A plain frame
// (PathID == nil, the RFC 9000 0x18 form) and a path-qualified PathID 0 frame
// both feed the connection-level connIDManager. Rust/noq's multipath frame model
// treats Some(PathID 0) and no path id as the same issued path-zero CID
// (frame.rs:2005-2012). A path-qualified non-zero frame is the peer issuing a
// DCID for that QUIC multipath path; we record it in perPathDestConnIDs for the
// send side and do NOT feed it to connIDManager.
func (c *Conn) handleNewConnectionIDFrame(frame *wire.NewConnectionIDFrame) error {
	if frame.PathID == nil {
		return c.connIDManager.Add(frame)
	}
	if err := c.rejectIfMultipathOff("PATH_NEW_CONNECTION_ID"); err != nil {
		return err
	}
	if *frame.PathID == protocol.PathIDZero {
		return c.connIDManager.Add(frame)
	}
	pid := *frame.PathID
	c.perPathDestConnIDs[pid] = frame.ConnectionID
	return nil
}

func (c *Conn) handleRetireConnectionIDFrame(frame *wire.RetireConnectionIDFrame, destConnID protocol.ConnectionID, expiry monotime.Time) error {
	if frame.PathID == nil {
		return c.connIDGenerator.Retire(frame.SequenceNumber, destConnID, expiry)
	}
	if err := c.rejectIfMultipathOff("PATH_RETIRE_CONNECTION_ID"); err != nil {
		return err
	}
	// Match noq's path-qualified CID model: nil and PathID 0 both address the
	// connection-level CID sequence space; non-zero path ids address per-path
	// CID sequence spaces.
	if *frame.PathID == protocol.PathIDZero {
		return c.connIDGenerator.Retire(frame.SequenceNumber, destConnID, expiry)
	}
	return c.connIDGenerator.RetirePath(*frame.PathID, frame.SequenceNumber, destConnID, expiry)
}

// maybeJoinPath provisions the local send/recv recovery state for a non-zero
// multipath path and issues one of our connection IDs for it (if we have not
// already), so the peer can address the path to us. It is idempotent and a
// no-op unless the path is within our gate (canOpenPath). It runs in the run
// goroutine. It is the join point for the peer that did not initiate the path
// via OpenPath. It reports whether the path is now provisioned.
func (c *Conn) maybeJoinPath(pid protocol.PathID) bool {
	if pid == protocol.PathIDZero {
		return false
	}
	if c.multipathOut == nil {
		c.multipathOut = newMultipathOutgoing()
	}
	if _, ok := c.multipathOut.paths[pid]; ok {
		return true // already provisioned (we initiated, or a duplicate frame)
	}
	if !c.canOpenPath(pid) {
		return false
	}
	if err := c.sentPacketHandler.AddPath(pid); err != nil {
		return false
	}
	if err := c.receivedPacketHandler.AddPath(pid, c.logger); err != nil {
		return false
	}
	if _, err := c.issuePathConnID(pid); err != nil {
		return false
	}
	// A path joined by the peer is open from our perspective: we answer its
	// PATH_CHALLENGEs and may carry data + PATH_ACKs on it. Only the initiator
	// runs the local PATH_CHALLENGE validation, so this side is marked validated.
	st := &pathOpenState{id: pid, validated: true, validatedChan: make(chan struct{})}
	close(st.validatedChan)
	c.multipathOut.paths[pid] = st
	if c.multipathOut.nextPathID <= pid {
		c.multipathOut.nextPathID = pid + 1
	}
	c.scheduleSending()
	return true
}

// destConnIDForPath returns the destination connection ID to use when sending a
// 1-RTT packet on path pid. For PathIDZero it returns connIDManager.Get — the
// single connection-level DCID — so every single-path send is byte-identical to
// today. For a non-zero path it returns the DCID the peer issued via
// PATH_NEW_CONNECTION_ID (perPathDestConnIDs); ok is false until the peer has
// issued one. This is consumed by the packer's per-path send path (5d).
func (c *Conn) destConnIDForPath(pid protocol.PathID) (protocol.ConnectionID, bool) {
	if pid == protocol.PathIDZero {
		return c.connIDManager.Get(), true
	}
	connID, ok := c.perPathDestConnIDs[pid]
	return connID, ok
}

// isPotentiallyDuplicate1RTT reports whether a 1-RTT packet number pn on path
// pid was already received. Duplicate detection is per-path: each PathID has its
// own packet-number space, so path 1's pn=0 is NOT a duplicate of path 0's pn=0
// (Stage 4 spec risk #1). For PathIDZero it is identical to the former
// connection-level IsPotentiallyDuplicate(Encryption1RTT).
func (c *Conn) isPotentiallyDuplicate1RTT(pn protocol.PacketNumber, pid protocol.PathID) bool {
	if pid == protocol.PathIDZero {
		return c.receivedPacketHandler.IsPotentiallyDuplicate(pn, protocol.Encryption1RTT)
	}
	return c.receivedPacketHandler.IsPotentiallyDuplicateForPath(pn, pid)
}

// pathForReceivedConnID resolves the multipath PathID an inbound 1-RTT packet
// belongs to from its destination connection ID (one of OUR issued source CIDs).
// PathIDZero's CIDs flow through the connection-level connIDGenerator;
// non-zero-path CIDs are issued by issuePathConnID. With multipath off, or for
// any CID we did not issue for a non-zero path, this returns PathIDZero, so the
// receive routing is byte-identical to single-path. It runs in the run
// goroutine (called from packet handling), so touching connIDGenerator is safe.
func (c *Conn) pathForReceivedConnID(connID protocol.ConnectionID) protocol.PathID {
	if !c.multipathNegotiated() {
		return protocol.PathIDZero
	}
	pid, ok := c.connIDGenerator.pathForLocalConnID(connID)
	if !ok {
		return protocol.PathIDZero
	}
	return pid
}

// issuePathConnID issues one of our connection IDs for the QUIC multipath path
// pid and queues a PATH_NEW_CONNECTION_ID frame (0x3e78) advertising it to the
// peer, so the peer can address pid's packets to it. It is the local
// counterpart of the peer-issued CIDs recorded in perPathDestConnIDs, and is
// driven by the path-open orchestration (5f). It must not be called for
// PathIDZero, whose CIDs are issued through the connection-level connIDGenerator
// (issueNewConnID), and only after multipath is negotiated.
func (c *Conn) issuePathConnID(pid protocol.PathID) (protocol.ConnectionID, error) {
	return c.connIDGenerator.issuePathConnID(pid)
}

// rejectIfMultipathOff returns a ProtocolViolation TransportError unless
// multipath has been negotiated. The frame parser already refuses to admit
// multipath frames when multipath is off (it is constructed with
// SetSupportsMultipath(c.multipathNegotiated())), so reaching handleFrame
// already implies negotiation. This is a defensive double-guard, matching the
// perspective guard in handleHandshakeDoneFrame: a multipath frame on a
// single-path connection is a protocol violation.
func (c *Conn) rejectIfMultipathOff(frameName string) error {
	if c.multipathNegotiated() {
		return nil
	}
	return &qerr.TransportError{
		ErrorCode:    qerr.ProtocolViolation,
		ErrorMessage: "received a " + frameName + " frame without multipath negotiated",
	}
}

func (c *Conn) handlePathAckFrame(frame *wire.PathAckFrame, rcvTime monotime.Time) error {
	if err := c.rejectIfMultipathOff("PATH_ACK"); err != nil {
		return err
	}
	c.pathAcksReceived.Add(1)
	c.lastPathAckID.Store(uint64(frame.PathID) + 1)
	return c.handleAckFrameForPath(&frame.Ack, frame.PathID, rcvTime)
}

func (c *Conn) handlePathStatusBackupFrame(frame *wire.PathStatusBackupFrame) error {
	if err := c.rejectIfMultipathOff("PATH_STATUS_BACKUP"); err != nil {
		return err
	}
	c.multipathManager.handleStatusBackup(frame.PathID, frame.SeqNo)
	return nil
}

func (c *Conn) handlePathStatusAvailableFrame(frame *wire.PathStatusAvailableFrame) error {
	if err := c.rejectIfMultipathOff("PATH_STATUS_AVAILABLE"); err != nil {
		return err
	}
	c.multipathManager.handleStatusAvailable(frame.PathID, frame.SeqNo)
	return nil
}

func (c *Conn) handlePathAbandonFrame(frame *wire.PathAbandonFrame) error {
	if err := c.rejectIfMultipathOff("PATH_ABANDON"); err != nil {
		return err
	}
	c.multipathManager.handleAbandon(frame.PathID, frame.ErrorCode)
	return nil
}

func (c *Conn) handleMaxPathIDFrame(frame *wire.MaxPathIDFrame) error {
	if err := c.rejectIfMultipathOff("MAX_PATH_ID"); err != nil {
		return err
	}
	c.multipathManager.handleMaxPathID(frame.PathID)
	return nil
}

func (c *Conn) handlePathsBlockedFrame(frame *wire.PathsBlockedFrame) error {
	if err := c.rejectIfMultipathOff("PATHS_BLOCKED"); err != nil {
		return err
	}
	c.multipathManager.handlePathsBlocked(frame.MaxPathID)
	return nil
}

func (c *Conn) handlePathCIDsBlockedFrame(frame *wire.PathCIDsBlockedFrame) error {
	if err := c.rejectIfMultipathOff("PATH_CIDS_BLOCKED"); err != nil {
		return err
	}
	c.multipathManager.handlePathCIDsBlocked(frame.PathID, frame.NextSeq)
	if frame.PathID == protocol.PathIDZero || !c.canOpenPath(frame.PathID) || c.connIDGenerator == nil {
		return nil
	}
	highestNext := uint64(0)
	if c.connIDGenerator.pathHighestSeq != nil {
		highestNext = c.connIDGenerator.pathHighestSeq[frame.PathID]
	}
	if highestNext > frame.NextSeq {
		return nil
	}
	_, err := c.issuePathConnID(frame.PathID)
	return err
}

// handlePacket is called by the server with a new packet
func (c *Conn) handlePacket(p receivedPacket) {
	c.receivedPacketMx.Lock()
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxConnUnprocessedPackets
	if c.receivedPackets.Len() >= protocol.MaxConnUnprocessedPackets {
		if c.qlogger != nil {
			var datagramID qlog.DatagramID
			if wire.IsLongHeaderPacket(p.data[0]) {
				datagramID = qlog.CalculateDatagramID(p.data)
			}
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Raw:        qlog.RawInfo{Length: int(p.Size())},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropDOSPrevention,
			})
		}
		c.receivedPacketMx.Unlock()
		return
	}
	c.receivedPackets.PushBack(p)
	c.receivedPacketMx.Unlock()

	select {
	case c.notifyReceivedPacket <- struct{}{}:
	default:
	}
}

func (c *Conn) handleConnectionCloseFrame(frame *wire.ConnectionCloseFrame) error {
	if frame.IsApplicationError {
		return &qerr.ApplicationError{
			Remote:       true,
			ErrorCode:    qerr.ApplicationErrorCode(frame.ErrorCode),
			ErrorMessage: frame.ReasonPhrase,
		}
	}
	return &qerr.TransportError{
		Remote:       true,
		ErrorCode:    qerr.TransportErrorCode(frame.ErrorCode),
		FrameType:    frame.FrameType,
		ErrorMessage: frame.ReasonPhrase,
	}
}

func (c *Conn) handleCryptoFrame(frame *wire.CryptoFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) error {
	if err := c.cryptoStreamManager.HandleCryptoFrame(frame, encLevel); err != nil {
		return err
	}
	for {
		data := c.cryptoStreamManager.GetCryptoData(encLevel)
		if data == nil {
			break
		}
		if err := c.cryptoStreamHandler.HandleMessage(data, encLevel); err != nil {
			return err
		}
	}
	return c.handleHandshakeEvents(rcvTime)
}

func (c *Conn) handleHandshakeEvents(now monotime.Time) error {
	for {
		ev := c.cryptoStreamHandler.NextEvent()
		var err error
		switch ev.Kind {
		case handshake.EventNoEvent:
			return nil
		case handshake.EventHandshakeComplete:
			// Don't call handleHandshakeComplete yet.
			// It's advantageous to process ACK frames that might be serialized after the CRYPTO frame first.
			c.handshakeComplete = true
		case handshake.EventReceivedTransportParameters:
			err = c.handleTransportParameters(ev.TransportParameters)
		case handshake.EventRestoredTransportParameters:
			c.restoreTransportParameters(ev.TransportParameters)
			close(c.earlyConnReadyChan)
		case handshake.EventReceivedReadKeys:
			// queue all previously undecryptable packets
			c.undecryptablePacketsToProcess = append(c.undecryptablePacketsToProcess, c.undecryptablePackets...)
			c.undecryptablePackets = nil
		case handshake.EventDiscard0RTTKeys:
			err = c.dropEncryptionLevel(protocol.Encryption0RTT, now)
		case handshake.EventWriteInitialData:
			_, err = c.initialStream.Write(ev.Data)
		case handshake.EventWriteHandshakeData:
			_, err = c.handshakeStream.Write(ev.Data)
		}
		if err != nil {
			return err
		}
	}
}

func (c *Conn) handlePathChallengeFrame(f *wire.PathChallengeFrame) {
	if c.perspective == protocol.PerspectiveClient {
		c.queueControlFrame(&wire.PathResponseFrame{Data: f.Data})
	}
}

func (c *Conn) handlePathResponseFrame(f *wire.PathResponseFrame, source netip.AddrPort) error {
	if c.handleQNTPathResponseFrame(f, source) {
		return nil
	}

	// A PATH_RESPONSE might validate an outgoing multipath path (5f) rather than
	// an RFC 9000 single-path migration. Check multipath first; if it matched, we
	// are done. This keeps the two validators (draft-multipath vs RFC 9000
	// migration) cleanly separated.
	if c.handleMultipathPathResponse(f) {
		return nil
	}
	switch c.perspective {
	case protocol.PerspectiveClient:
		if c.qntNegotiated() && c.pathManagerOutgoing.Load() == nil && c.qntAcceptsUnmatchedPathResponse(source) {
			return nil
		}
		return c.handlePathResponseFrameClient(f, source)
	case protocol.PerspectiveServer:
		if c.qntNegotiated() && c.pathManager == nil && c.qntAcceptsUnmatchedPathResponse(source) {
			return nil
		}
		return c.handlePathResponseFrameServer(f, source)
	default:
		panic("unreachable")
	}
}

func (c *Conn) handleQNTPathResponseFrame(f *wire.PathResponseFrame, source netip.AddrPort) bool {
	if addr, ok := c.qntConsumePathResponse(f, source); ok {
		c.qntQueueValidatedProbe(addr)
		return true
	}
	return false
}

func (c *Conn) handlePathResponseFrameClient(f *wire.PathResponseFrame, source netip.AddrPort) error {
	pm := c.pathManagerOutgoing.Load()
	if pm == nil {
		if c.pathResponseFromCurrentPeer(source) {
			return nil
		}
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "unexpected PATH_RESPONSE frame",
		}
	}
	pm.HandlePathResponseFrame(f)
	return nil
}

func (c *Conn) handlePathResponseFrameServer(f *wire.PathResponseFrame, source netip.AddrPort) error {
	if c.pathManager == nil {
		if c.pathResponseFromCurrentPeer(source) {
			return nil
		}
		// since we didn't send PATH_CHALLENGEs yet, we don't expect PATH_RESPONSEs
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "unexpected PATH_RESPONSE frame",
		}
	}
	c.pathManager.HandlePathResponseFrame(f)
	return nil
}

func (c *Conn) pathResponseFromCurrentPeer(source netip.AddrPort) bool {
	if !source.IsValid() || c.conn == nil {
		return false
	}
	return addrPortEqual(c.RemoteAddr(), source)
}

func addrPortEqual(addr net.Addr, ap netip.AddrPort) bool {
	if addr == nil || !ap.IsValid() {
		return false
	}
	if a, ok := addr.(interface{ AddrPort() netip.AddrPort }); ok {
		return a.AddrPort() == ap
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		return udp.AddrPort() == ap
	}
	return false
}

func (c *Conn) handleNewTokenFrame(frame *wire.NewTokenFrame) error {
	if c.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_TOKEN frame from the client",
		}
	}
	if c.config.TokenStore != nil {
		c.config.TokenStore.Put(c.tokenStoreKey, &ClientToken{data: frame.Token, rtt: c.rttStats.SmoothedRTT()})
	}
	return nil
}

func (c *Conn) handleHandshakeDoneFrame(rcvTime monotime.Time) error {
	if c.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received a HANDSHAKE_DONE frame",
		}
	}
	if !c.handshakeConfirmed {
		return c.handleHandshakeConfirmed(rcvTime)
	}
	return nil
}

func (c *Conn) handleAckFrame(frame *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) error {
	acked1RTTPacket, err := c.sentPacketHandler.ReceivedAck(frame, encLevel, c.lastPacketReceivedTime)
	if err != nil {
		return err
	}
	if !acked1RTTPacket {
		return nil
	}
	// On the client side: If the packet acknowledged a 1-RTT packet, this confirms the handshake.
	// This is only possible if the ACK was sent in a 1-RTT packet.
	// This is an optimization over simply waiting for a HANDSHAKE_DONE frame, see section 4.1.2 of RFC 9001.
	if c.perspective == protocol.PerspectiveClient && !c.handshakeConfirmed {
		if err := c.handleHandshakeConfirmed(rcvTime); err != nil {
			return err
		}
	}
	// If one of the acknowledged packets was a Path MTU probe packet, this might have increased the Path MTU estimate.
	if c.mtuDiscoverer != nil {
		if mtu := c.mtuDiscoverer.CurrentSize(); mtu > protocol.ByteCount(c.currentMTUEstimate.Load()) {
			c.currentMTUEstimate.Store(uint32(mtu))
			c.sentPacketHandler.SetMaxDatagramSize(mtu)
		}
	}
	return c.cryptoStreamHandler.SetLargest1RTTAcked(frame.LargestAcked())
}

// handleAckFrameForPath processes a PATH_ACK frame's ACK against the
// application-data packet number space identified by pid. It routes to
// ReceivedAckForPath, which rejects an unknown pid with a ProtocolViolation
// rather than mis-attributing the ACK to PathIDZero (Stage 4 spec risk #1).
// Until a second path is opened on the send side (Stage 5), only PathIDZero
// exists, so any non-zero pid is rejected there.
//
// Multipath ACKs are 1-RTT only by construction (the parser admits them only
// from the application-data space), so the post-ACK handling mirrors the 1-RTT
// branch of handleAckFrame.
func (c *Conn) handleAckFrameForPath(frame *wire.AckFrame, pid protocol.PathID, rcvTime monotime.Time) error {
	acked1RTTPacket, err := c.sentPacketHandler.ReceivedAckForPath(frame, pid, c.lastPacketReceivedTime)
	if err != nil {
		return err
	}
	if !acked1RTTPacket {
		return nil
	}
	if c.perspective == protocol.PerspectiveClient && !c.handshakeConfirmed {
		if err := c.handleHandshakeConfirmed(rcvTime); err != nil {
			return err
		}
	}
	if c.mtuDiscoverer != nil {
		if mtu := c.mtuDiscoverer.CurrentSize(); mtu > protocol.ByteCount(c.currentMTUEstimate.Load()) {
			c.currentMTUEstimate.Store(uint32(mtu))
			c.sentPacketHandler.SetMaxDatagramSize(mtu)
		}
	}
	return c.cryptoStreamHandler.SetLargest1RTTAcked(frame.LargestAcked())
}

func (c *Conn) handleDatagramFrame(f *wire.DatagramFrame) error {
	if f.Length(c.version) > wire.MaxDatagramSize {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "DATAGRAM frame too large",
		}
	}
	c.datagramQueue.HandleDatagramFrame(f)
	return nil
}

func (c *Conn) setCloseError(e *closeError) {
	c.closeErr.CompareAndSwap(nil, e)
	select {
	case c.closeChan <- struct{}{}:
	default:
	}
}

// closeLocal closes the connection and send a CONNECTION_CLOSE containing the error
func (c *Conn) closeLocal(e error) {
	c.setCloseError(&closeError{err: e, immediate: false})
}

// destroy closes the connection without sending the error on the wire
func (c *Conn) destroy(e error) {
	c.destroyImpl(e)
	<-c.ctx.Done()
}

func (c *Conn) destroyImpl(e error) {
	c.setCloseError(&closeError{err: e, immediate: true})
}

// CloseWithError closes the connection with an error.
// The error string will be sent to the peer.
func (c *Conn) CloseWithError(code ApplicationErrorCode, desc string) error {
	c.closeLocal(&qerr.ApplicationError{
		ErrorCode:    code,
		ErrorMessage: desc,
	})
	<-c.ctx.Done()
	return nil
}

func (c *Conn) closeWithTransportError(code TransportErrorCode) {
	c.closeLocal(&qerr.TransportError{ErrorCode: code})
	<-c.ctx.Done()
}

func (c *Conn) handleCloseError(closeErr *closeError) {
	if closeErr.immediate {
		if nerr, ok := closeErr.err.(net.Error); ok && nerr.Timeout() {
			c.logger.Errorf("Destroying connection: %s", closeErr.err)
		} else {
			c.logger.Errorf("Destroying connection with error: %s", closeErr.err)
		}
	} else {
		if closeErr.err == nil {
			c.logger.Infof("Closing connection.")
		} else {
			c.logger.Errorf("Closing connection with error: %s", closeErr.err)
		}
	}

	e := closeErr.err
	if e == nil {
		e = &qerr.ApplicationError{}
	} else {
		defer func() { closeErr.err = e }()
	}

	var (
		statelessResetErr     *StatelessResetError
		versionNegotiationErr *VersionNegotiationError
		recreateErr           *errCloseForRecreating
		applicationErr        *ApplicationError
		transportErr          *TransportError
	)
	var isRemoteClose bool
	var trigger qlog.ConnectionCloseTrigger
	var reason string
	var transportErrorCode *qlog.TransportErrorCode
	var applicationErrorCode *qlog.ApplicationErrorCode
	switch {
	case errors.Is(e, qerr.ErrIdleTimeout),
		errors.Is(e, qerr.ErrHandshakeTimeout):
		trigger = qlog.ConnectionCloseTriggerIdleTimeout
	case errors.As(e, &statelessResetErr):
		trigger = qlog.ConnectionCloseTriggerStatelessReset
	case errors.As(e, &versionNegotiationErr):
		trigger = qlog.ConnectionCloseTriggerVersionMismatch
	case errors.As(e, &recreateErr):
	case errors.As(e, &applicationErr):
		isRemoteClose = applicationErr.Remote
		reason = applicationErr.ErrorMessage
		applicationErrorCode = &applicationErr.ErrorCode
	case errors.As(e, &transportErr):
		isRemoteClose = transportErr.Remote
		reason = transportErr.ErrorMessage
		transportErrorCode = &transportErr.ErrorCode
	case closeErr.immediate:
		e = closeErr.err
	default:
		te := &qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: e.Error(),
		}
		e = te
		reason = te.ErrorMessage
		code := te.ErrorCode
		transportErrorCode = &code
	}

	c.streamsMap.CloseWithError(e)
	if c.datagramQueue != nil {
		c.datagramQueue.CloseWithError(e)
	}

	// In rare instances, the connection ID manager might switch to a new connection ID
	// when sending the CONNECTION_CLOSE frame.
	// The connection ID manager removes the active stateless reset token from the packet
	// handler map when it is closed, so we need to make sure that this happens last.
	defer c.connIDManager.Close()

	if c.qlogger != nil && !errors.As(e, &recreateErr) {
		initiator := qlog.InitiatorLocal
		if isRemoteClose {
			initiator = qlog.InitiatorRemote
		}
		c.qlogger.RecordEvent(qlog.ConnectionClosed{
			Initiator:        initiator,
			ConnectionError:  transportErrorCode,
			ApplicationError: applicationErrorCode,
			Trigger:          trigger,
			Reason:           reason,
		})
	}

	// If this is a remote close we're done here
	if isRemoteClose {
		c.connIDGenerator.ReplaceWithClosed(nil, 3*c.rttStats.PTO(false))
		return
	}
	if closeErr.immediate {
		c.connIDGenerator.RemoveAll()
		return
	}
	// Don't send out any CONNECTION_CLOSE if this is an error that occurred
	// before we even sent out the first packet.
	if c.perspective == protocol.PerspectiveClient && !c.sentFirstPacket {
		c.connIDGenerator.RemoveAll()
		return
	}
	connClosePacket, err := c.sendConnectionClose(e)
	if err != nil {
		c.logger.Debugf("Error sending CONNECTION_CLOSE: %s", err)
	}
	c.connIDGenerator.ReplaceWithClosed(connClosePacket, 3*c.rttStats.PTO(false))
}

func (c *Conn) dropEncryptionLevel(encLevel protocol.EncryptionLevel, now monotime.Time) error {
	c.sentPacketHandler.DropPackets(encLevel, now)
	c.receivedPacketHandler.DropPackets(encLevel)
	//nolint:exhaustive // only Initial and 0-RTT need special treatment
	switch encLevel {
	case protocol.EncryptionInitial:
		c.droppedInitialKeys = true
		c.cryptoStreamHandler.DiscardInitialKeys()
	case protocol.Encryption0RTT:
		c.streamsMap.ResetFor0RTT()
		c.framer.Handle0RTTRejection()
		return c.connFlowController.Reset()
	}
	return c.cryptoStreamManager.Drop(encLevel)
}

// is called for the client, when restoring transport parameters saved for 0-RTT
func (c *Conn) restoreTransportParameters(params *wire.TransportParameters) {
	if c.logger.Debug() {
		c.logger.Debugf("Restoring Transport Parameters: %s", params)
	}
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.ParametersSet{
			Restore:                         true,
			Initiator:                       qlog.InitiatorRemote,
			SentBy:                          c.perspective,
			OriginalDestinationConnectionID: params.OriginalDestinationConnectionID,
			InitialSourceConnectionID:       params.InitialSourceConnectionID,
			RetrySourceConnectionID:         params.RetrySourceConnectionID,
			StatelessResetToken:             params.StatelessResetToken,
			DisableActiveMigration:          params.DisableActiveMigration,
			MaxIdleTimeout:                  params.MaxIdleTimeout,
			MaxUDPPayloadSize:               params.MaxUDPPayloadSize,
			AckDelayExponent:                params.AckDelayExponent,
			MaxAckDelay:                     params.MaxAckDelay,
			ActiveConnectionIDLimit:         params.ActiveConnectionIDLimit,
			InitialMaxData:                  params.InitialMaxData,
			InitialMaxStreamDataBidiLocal:   params.InitialMaxStreamDataBidiLocal,
			InitialMaxStreamDataBidiRemote:  params.InitialMaxStreamDataBidiRemote,
			InitialMaxStreamDataUni:         params.InitialMaxStreamDataUni,
			InitialMaxStreamsBidi:           int64(params.MaxBidiStreamNum),
			InitialMaxStreamsUni:            int64(params.MaxUniStreamNum),
			MaxDatagramFrameSize:            params.MaxDatagramFrameSize,
			EnableResetStreamAt:             params.EnableResetStreamAt,
		})
	}

	c.peerParams.Store(params)
	c.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	c.connFlowController.UpdateSendWindow(params.InitialMaxData)
	c.streamsMap.HandleTransportParameters(params)
}

func (c *Conn) handleTransportParameters(params *wire.TransportParameters) error {
	if c.qlogger != nil {
		c.qlogTransportParameters(params, c.perspective.Opposite(), false)
	}
	if err := c.checkTransportParameters(params); err != nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: err.Error(),
		}
	}

	if prev := c.peerParams.Load(); c.perspective == protocol.PerspectiveClient && prev != nil && c.ConnectionState().Used0RTT && !params.ValidForUpdate(prev) {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "server sent reduced limits after accepting 0-RTT data",
		}
	}

	c.peerParams.Store(params)
	// On the client side we have to wait for handshake completion.
	// During a 0-RTT connection, we are only allowed to use the new transport parameters for 1-RTT packets.
	if c.perspective == protocol.PerspectiveServer {
		c.applyTransportParameters()
		// On the server side, the early connection is ready as soon as we processed
		// the client's transport parameters.
		close(c.earlyConnReadyChan)
	}
	return nil
}

func (c *Conn) checkTransportParameters(params *wire.TransportParameters) error {
	if c.logger.Debug() {
		c.logger.Debugf("Processed Transport Parameters: %s", params)
	}

	// check the initial_source_connection_id
	if params.InitialSourceConnectionID != c.handshakeDestConnID {
		return fmt.Errorf("expected initial_source_connection_id to equal %s, is %s", c.handshakeDestConnID, params.InitialSourceConnectionID)
	}

	if c.perspective == protocol.PerspectiveServer {
		return nil
	}
	// check the original_destination_connection_id
	if params.OriginalDestinationConnectionID != c.origDestConnID {
		return fmt.Errorf("expected original_destination_connection_id to equal %s, is %s", c.origDestConnID, params.OriginalDestinationConnectionID)
	}
	if c.retrySrcConnID != nil { // a Retry was performed
		if params.RetrySourceConnectionID == nil {
			return errors.New("missing retry_source_connection_id")
		}
		if *params.RetrySourceConnectionID != *c.retrySrcConnID {
			return fmt.Errorf("expected retry_source_connection_id to equal %s, is %s", c.retrySrcConnID, *params.RetrySourceConnectionID)
		}
	} else if params.RetrySourceConnectionID != nil {
		return errors.New("received retry_source_connection_id, although no Retry was performed")
	}
	return nil
}

func (c *Conn) applyTransportParameters() {
	params := c.peerParams.Load()
	// Our local idle timeout will always be > 0.
	c.idleTimeout = c.config.MaxIdleTimeout
	// If the peer advertised an idle timeout, take the minimum of the values.
	if params.MaxIdleTimeout > 0 {
		c.idleTimeout = min(c.idleTimeout, params.MaxIdleTimeout)
	}
	c.keepAliveInterval = min(c.config.KeepAlivePeriod, c.idleTimeout/2)
	c.streamsMap.HandleTransportParameters(params)
	c.frameParser.SetAckDelayExponent(params.AckDelayExponent)
	// Admit QUIC multipath frames only once both peers advertised the
	// initial_max_path_id transport parameter. Until then the parser stays in
	// single-path mode, so multipath frame types are rejected as unknown.
	c.frameParser.SetSupportsMultipath(c.multipathNegotiated())
	// Admit OBSERVED_ADDRESS frames only once the peer's address-discovery role
	// permits it to report to us and ours permits receiving. Until then the
	// parser rejects them as unknown, keeping un-negotiated connections
	// byte-identical.
	c.frameParser.SetSupportsAddressDiscovery(c.acceptsObservedAddr())
	// Admit n0 NAT traversal frames only once both peers advertised the
	// n0_nat_traversal transport parameter.
	c.frameParser.SetSupportsNATTraversal(c.qntNegotiated())
	c.connFlowController.UpdateSendWindow(params.InitialMaxData)
	c.rttStats.SetMaxAckDelay(params.MaxAckDelay)
	c.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	if params.StatelessResetToken != nil {
		c.connIDManager.SetStatelessResetToken(*params.StatelessResetToken)
	}
	// We don't support connection migration yet, so we don't have any use for the preferred_address.
	if params.PreferredAddress != nil {
		// Retire the connection ID.
		c.connIDManager.AddFromPreferredAddress(params.PreferredAddress.ConnectionID, params.PreferredAddress.StatelessResetToken)
	}
	maxPacketSize := protocol.ByteCount(protocol.MaxPacketBufferSize)
	if params.MaxUDPPayloadSize > 0 && params.MaxUDPPayloadSize < maxPacketSize {
		maxPacketSize = params.MaxUDPPayloadSize
	}
	c.mtuDiscoverer = newMTUDiscoverer(
		c.rttStats,
		protocol.ByteCount(c.config.InitialPacketSize),
		maxPacketSize,
		c.qlogger,
	)
}

// multipathNegotiated reports whether the QUIC multipath extension
// (draft-ietf-quic-multipath) was negotiated. This is the case only when both
// peers advertised the initial_max_path_id transport parameter: the local side
// via Config.InitialMaxPathID, and the peer in its received parameters. It must
// be called only after the peer's transport parameters have been processed.
func (c *Conn) multipathNegotiated() bool {
	params := c.peerParams.Load()
	return c.config.InitialMaxPathID != nil &&
		params != nil &&
		params.InitialMaxPathID != nil
}

// qntNegotiated reports whether n0 QUIC NAT traversal was negotiated. This is
// the case only when both peers advertised the n0_nat_traversal transport
// parameter with a non-zero address limit. It must be called only after the
// peer's transport parameters have been processed.
func (c *Conn) qntNegotiated() bool {
	params := c.peerParams.Load()
	return maxRemoteNATTraversalAddressesParam(c.config.MaxRemoteNATTraversalAddresses) != nil &&
		params != nil &&
		params.MaxRemoteNATTraversalAddresses != nil &&
		*params.MaxRemoteNATTraversalAddresses != 0
}

// initialMaxPathIDParam converts a Config.InitialMaxPathID (*uint32) to the
// transport parameter representation (*protocol.PathID). A nil value leaves the
// parameter unset, keeping multipath disabled.
func initialMaxPathIDParam(v *uint32) *protocol.PathID {
	if v == nil {
		return nil
	}
	id := protocol.PathID(*v)
	return &id
}

// maxRemoteNATTraversalAddressesParam converts Config.MaxRemoteNATTraversalAddresses
// to the n0_nat_traversal transport parameter representation. A nil or zero
// value leaves the parameter unset, matching the Rust NonZeroU8 requirement.
func maxRemoteNATTraversalAddressesParam(v *uint8) *uint8 {
	if v == nil || *v == 0 {
		return nil
	}
	limit := *v
	return &limit
}

// addressDiscoveryRole derives the QUIC Address Discovery role to advertise from
// the two config flags, mirroring noq's
// send_observed_address_reports/receive_observed_address_reports setters
// (config/transport.rs:372-388, address_discovery.rs Role transitions). Neither
// flag set leaves the role Disabled, so the observed_address transport parameter
// is omitted and QAD stays un-negotiated (byte-identical default).
func addressDiscoveryRole(config *Config) wire.AddressDiscoveryRole {
	switch {
	case config.SendObservedAddressReports && config.ReceiveObservedAddressReports:
		return wire.AddressDiscoveryBoth
	case config.SendObservedAddressReports:
		return wire.AddressDiscoverySendOnly
	case config.ReceiveObservedAddressReports:
		return wire.AddressDiscoveryReceiveOnly
	default:
		return wire.AddressDiscoveryDisabled
	}
}

// reportsObservedAddr reports whether this endpoint should emit OBSERVED_ADDRESS
// frames to the peer: our role must be a reporter and the peer's role must
// accept reports, i.e. local.should_report(peer) (address_discovery.rs:54-56,
// the send-side gate at mod.rs:6184-6188). It must be called only after the
// peer's transport parameters have been processed.
func (c *Conn) reportsObservedAddr() bool {
	params := c.peerParams.Load()
	if params == nil {
		return false
	}
	return addressDiscoveryRole(c.config).ShouldReport(params.AddressDiscoveryRole)
}

// acceptsObservedAddr reports whether this endpoint should admit OBSERVED_ADDRESS
// frames from the peer: the peer's role must be a reporter and our role must
// accept reports, i.e. peer.should_report(local) (the receive-side gate at
// mod.rs:5333-5341). It must be called only after the peer's transport
// parameters have been processed.
func (c *Conn) acceptsObservedAddr() bool {
	params := c.peerParams.Load()
	if params == nil {
		return false
	}
	return params.AddressDiscoveryRole.ShouldReport(addressDiscoveryRole(c.config))
}

// handleObservedAddrFrame records a reflexive address the peer reported for us.
// It rejects the frame as a protocol violation if address discovery was not
// negotiated in this direction (mod.rs:5333-5341) and applies highest-seq_no
// wins: a frame whose seq_no does not exceed the last recorded one is ignored
// (paths.rs:615-640). The recorded address is surfaced via Conn.ObservedAddr.
func (c *Conn) handleObservedAddrFrame(frame *wire.ObservedAddrFrame) error {
	if !c.acceptsObservedAddr() {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received OBSERVED_ADDRESS frame when not negotiated",
		}
	}
	c.observedAddrMu.Lock()
	defer c.observedAddrMu.Unlock()
	if c.observedAddrSeqSet && frame.SeqNo <= c.observedAddrSeqNo {
		// Stale or duplicate report; ignore (paths.rs:621-622).
		return nil
	}
	first := !c.observedAddrValid
	c.observedAddrSeqNo = frame.SeqNo
	c.observedAddrSeqSet = true
	c.observedAddr = netip.AddrPortFrom(frame.Addr.Unmap(), frame.Port)
	c.observedAddrValid = true
	if first {
		close(c.observedAddrReadyLocked())
	}
	return nil
}

// maybeQueueObservedAddr queues an OBSERVED_ADDRESS frame reporting remote (the
// source address of a packet just received from the peer) when address
// discovery permits this endpoint to report. The sequence number increments per
// emitted frame, mirroring the send-side logic (mod.rs:6189-6198). remote must
// be a *net.UDPAddr; any other address type (e.g. a relay's virtual address) is
// skipped, as only UDP source addresses are meaningful reflexive addresses.
// Run goroutine only.
func (c *Conn) maybeQueueObservedAddr(remote net.Addr) {
	if !c.reportsObservedAddr() {
		return
	}
	udp, ok := remote.(*net.UDPAddr)
	if !ok {
		return
	}
	ap := udp.AddrPort()
	if !ap.IsValid() {
		return
	}
	c.queueControlFrame(&wire.ObservedAddrFrame{
		SeqNo: c.nextObservedAddrSeqNo,
		Addr:  ap.Addr().Unmap(),
		Port:  ap.Port(),
	})
	c.nextObservedAddrSeqNo++
}

// ObservedAddr returns the most recent reflexive address the peer reported via
// the QUIC Address Discovery OBSERVED_ADDRESS extension and whether one has been
// received. It returns ok=false when address discovery was not negotiated to
// receive reports, or when no report has arrived yet.
func (c *Conn) ObservedAddr() (netip.AddrPort, bool) {
	c.observedAddrMu.Lock()
	defer c.observedAddrMu.Unlock()
	if !c.observedAddrValid {
		return netip.AddrPort{}, false
	}
	return c.observedAddr, true
}

// observedAddrReadyLocked returns the channel closed on the first report,
// creating it on demand. observedAddrMu must be held.
func (c *Conn) observedAddrReadyLocked() chan struct{} {
	if c.observedAddrReadyCh == nil {
		c.observedAddrReadyCh = make(chan struct{})
	}
	return c.observedAddrReadyCh
}

// AwaitObservedAddr returns the reflexive address the peer reported via the
// QUIC Address Discovery OBSERVED_ADDRESS extension, waiting for the first
// report if none has arrived yet (reports are sent after the handshake, so an
// immediate read misses). Returns ok=false without waiting when address
// discovery was not negotiated to receive reports, and when ctx ends or the
// connection closes first.
func (c *Conn) AwaitObservedAddr(ctx context.Context) (netip.AddrPort, bool) {
	c.observedAddrMu.Lock()
	if c.observedAddrValid {
		addr := c.observedAddr
		c.observedAddrMu.Unlock()
		return addr, true
	}
	ready := c.observedAddrReadyLocked()
	c.observedAddrMu.Unlock()

	if !c.acceptsObservedAddr() {
		return netip.AddrPort{}, false
	}
	select {
	case <-ready:
		return c.ObservedAddr()
	case <-ctx.Done():
		return netip.AddrPort{}, false
	case <-c.Context().Done():
		return netip.AddrPort{}, false
	}
}

func (c *Conn) triggerSending(now monotime.Time) error {
	c.pacingDeadline = 0

	sendMode := c.sentPacketHandler.SendMode(now)
	switch sendMode {
	case ackhandler.SendAny:
		return c.sendPackets(now)
	case ackhandler.SendNone:
		c.blocked = blockModeHardBlocked
		return nil
	case ackhandler.SendPacingLimited:
		deadline := c.sentPacketHandler.TimeUntilSend()
		if deadline.IsZero() {
			deadline = deadlineSendImmediately
		}
		c.pacingDeadline = deadline
		// Allow sending of an ACK if we're pacing limit.
		// This makes sure that a peer that is mostly receiving data (and thus has an inaccurate cwnd estimate)
		// sends enough ACKs to allow its peer to utilize the bandwidth.
		return c.maybeSendAckOnlyPacket(now)
	case ackhandler.SendAck:
		// We can at most send a single ACK only packet.
		// There will only be a new ACK after receiving new packets.
		// SendAck is only returned when we're congestion limited, so we don't need to set the pacing timer.
		c.blocked = blockModeCongestionLimited
		return c.maybeSendAckOnlyPacket(now)
	case ackhandler.SendPTOInitial, ackhandler.SendPTOHandshake, ackhandler.SendPTOAppData:
		if err := c.sendProbePacket(sendMode, now); err != nil {
			return err
		}
		if c.sendQueue.WouldBlock() {
			c.scheduleSending()
			return nil
		}
		return c.triggerSending(now)
	default:
		return fmt.Errorf("BUG: invalid send mode %d", sendMode)
	}
}

func (c *Conn) sendPackets(now monotime.Time) error {
	if c.perspective == protocol.PerspectiveClient && c.handshakeConfirmed {
		if pm := c.pathManagerOutgoing.Load(); pm != nil {
			connID, frame, tr, ok := pm.NextPathToProbe()
			if ok {
				probe, buf, err := c.packer.PackPathProbePacket(connID, []ackhandler.Frame{frame}, c.version)
				if err != nil {
					return err
				}
				c.logger.Debugf("sending path probe packet from %s", c.LocalAddr())
				c.logShortHeaderPacket(probe, protocol.ECNNon, buf.Len())
				c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
				tr.WriteTo(buf.Data, c.conn.RemoteAddr())
				// There's (likely) more data to send. Loop around again.
				c.scheduleSending()
				return nil
			}
		}
	}

	if c.handshakeConfirmed {
		remote, probe, buf, ok, err := c.qntPackNextProbe(c.connIDManager.Get(), c.version)
		if err != nil {
			return err
		}
		if ok {
			addr := qntProbeUDPAddr(remote)
			if addr != nil {
				c.logger.Debugf("sending QNT probe packet to %s", addr)
				c.logShortHeaderPacket(probe, protocol.ECNNon, buf.Len())
				c.registerPackedShortHeaderPacket(probe, protocol.ECNNon, now)
				c.sendQNTProbeBuffer(buf, addr)
				c.qntArmNextRetry(now, c.rttStats.SmoothedRTT())
				c.scheduleSending()
				return nil
			}
		}
	}

	// Path MTU Discovery
	// Can't use GSO, since we need to send a single packet that's larger than our current maximum size.
	// Performance-wise, this doesn't matter, since we only send a very small (<10) number of
	// MTU probe packets per connection.
	if c.handshakeConfirmed && c.mtuDiscoverer != nil && c.mtuDiscoverer.ShouldSendProbe(now) {
		ping, size := c.mtuDiscoverer.GetPing(now)
		p, buf, err := c.packer.PackMTUProbePacket(ping, size, c.version)
		if err != nil {
			return err
		}
		ecn := c.sentPacketHandler.ECNMode(true)
		c.logShortHeaderPacket(p, ecn, buf.Len())
		c.registerPackedShortHeaderPacket(p, ecn, now)
		c.sendQueue.Send(buf, 0, ecn)
		// There's (likely) more data to send. Loop around again.
		c.scheduleSending()
		return nil
	}

	if offset := c.connFlowController.GetWindowUpdate(now); offset > 0 {
		c.framer.QueueMaxDataFrame(offset)
	}
	if cf := c.cryptoStreamManager.GetPostHandshakeData(protocol.MaxPostHandshakeCryptoFrameSize); cf != nil {
		c.queueControlFrame(cf)
	}

	if !c.handshakeConfirmed {
		packet, err := c.packer.PackCoalescedPacket(false, c.maxPacketSize(), now, c.version)
		if err != nil || packet == nil {
			return err
		}
		c.sentFirstPacket = true
		if err := c.sendPackedCoalescedPacket(packet, c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now); err != nil {
			return err
		}
		//nolint:exhaustive // only need to handle pacing-related events here
		switch c.sentPacketHandler.SendMode(now) {
		case ackhandler.SendPacingLimited:
			c.resetPacingDeadline()
		case ackhandler.SendAny:
			c.pacingDeadline = deadlineSendImmediately
		}
		return nil
	}

	if c.conn.capabilities().GSO {
		return c.sendPacketsWithGSO(now)
	}
	return c.sendPacketsWithoutGSO(now)
}

func (c *Conn) sendQNTProbeBuffer(buf *packetBuffer, addr net.Addr) {
	defer buf.Release()
	c.sendQueue.SendProbe(buf, addr)
}

func (c *Conn) sendQNTProbeBufferWithInfo(buf *packetBuffer, addr net.Addr, info packetInfo) {
	defer buf.Release()
	if err := c.conn.WriteToInfo(buf.Data, addr, info); err != nil {
	}
}

func (c *Conn) sendPacketsWithoutGSO(now monotime.Time) error {
	for {
		buf := getPacketBuffer()
		ecn := c.sentPacketHandler.ECNMode(true)
		if _, err := c.appendOneShortHeaderPacket(buf, c.maxPacketSize(), ecn, now); err != nil {
			if err == errNothingToPack {
				buf.Release()
				return nil
			}
			return err
		}

		c.sendQueue.Send(buf, 0, ecn)

		if c.sendQueue.WouldBlock() {
			return nil
		}
		sendMode := c.sentPacketHandler.SendMode(now)
		if sendMode == ackhandler.SendPacingLimited {
			c.resetPacingDeadline()
			return nil
		}
		if sendMode != ackhandler.SendAny {
			return nil
		}
		// Prioritize receiving of packets over sending out more packets.
		c.receivedPacketMx.Lock()
		hasPackets := !c.receivedPackets.Empty()
		c.receivedPacketMx.Unlock()
		if hasPackets {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}
	}
}

func (c *Conn) sendPacketsWithGSO(now monotime.Time) error {
	buf := getLargePacketBuffer()
	maxSize := c.maxPacketSize()

	ecn := c.sentPacketHandler.ECNMode(true)
	for {
		var dontSendMore bool
		size, err := c.appendOneShortHeaderPacket(buf, maxSize, ecn, now)
		if err != nil {
			if err != errNothingToPack {
				return err
			}
			if buf.Len() == 0 {
				buf.Release()
				return nil
			}
			dontSendMore = true
		}

		if !dontSendMore {
			sendMode := c.sentPacketHandler.SendMode(now)
			if sendMode == ackhandler.SendPacingLimited {
				c.resetPacingDeadline()
			}
			if sendMode != ackhandler.SendAny {
				dontSendMore = true
			}
		}

		// Don't send more packets in this batch if they require a different ECN marking than the previous ones.
		nextECN := c.sentPacketHandler.ECNMode(true)

		// Append another packet if
		// 1. The congestion controller and pacer allow sending more
		// 2. The last packet appended was a full-size packet
		// 3. The next packet will have the same ECN marking
		// 4. We still have enough space for another full-size packet in the buffer
		if !dontSendMore && size == maxSize && nextECN == ecn && buf.Len()+maxSize <= buf.Cap() {
			continue
		}

		c.sendQueue.Send(buf, uint16(maxSize), ecn)

		if dontSendMore {
			return nil
		}
		if c.sendQueue.WouldBlock() {
			return nil
		}

		// Prioritize receiving of packets over sending out more packets.
		c.receivedPacketMx.Lock()
		hasPackets := !c.receivedPackets.Empty()
		c.receivedPacketMx.Unlock()
		if hasPackets {
			c.pacingDeadline = deadlineSendImmediately
			return nil
		}

		ecn = nextECN
		buf = getLargePacketBuffer()
	}
}

func (c *Conn) resetPacingDeadline() {
	deadline := c.sentPacketHandler.TimeUntilSend()
	if deadline.IsZero() {
		deadline = deadlineSendImmediately
	}
	c.pacingDeadline = deadline
}

func (c *Conn) maybeSendAckOnlyPacket(now monotime.Time) error {
	if !c.handshakeConfirmed {
		ecn := c.sentPacketHandler.ECNMode(false)
		packet, err := c.packer.PackCoalescedPacket(true, c.maxPacketSize(), now, c.version)
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		return c.sendPackedCoalescedPacket(packet, ecn, now)
	}

	ecn := c.sentPacketHandler.ECNMode(true)
	p, buf, err := c.packer.PackAckOnlyPacket(c.maxPacketSize(), now, c.version)
	if err != nil {
		if err == errNothingToPack {
			return nil
		}
		return err
	}
	c.logShortHeaderPacket(p, ecn, buf.Len())
	c.registerPackedShortHeaderPacket(p, ecn, now)
	c.sendQueue.Send(buf, 0, ecn)
	return nil
}

func (c *Conn) sendProbePacket(sendMode ackhandler.SendMode, now monotime.Time) error {
	var encLevel protocol.EncryptionLevel
	//nolint:exhaustive // We only need to handle the PTO send modes here.
	switch sendMode {
	case ackhandler.SendPTOInitial:
		encLevel = protocol.EncryptionInitial
	case ackhandler.SendPTOHandshake:
		encLevel = protocol.EncryptionHandshake
	case ackhandler.SendPTOAppData:
		encLevel = protocol.Encryption1RTT
	default:
		return fmt.Errorf("connection BUG: unexpected send mode: %d", sendMode)
	}
	// Queue probe packets until we actually send out a packet,
	// or until there are no more packets to queue.
	var packet *coalescedPacket
	for packet == nil {
		if wasQueued := c.sentPacketHandler.QueueProbePacket(encLevel); !wasQueued {
			break
		}
		var err error
		packet, err = c.packer.PackPTOProbePacket(encLevel, c.maxPacketSize(), false, now, c.version)
		if err != nil {
			return err
		}
	}
	if packet == nil {
		var err error
		packet, err = c.packer.PackPTOProbePacket(encLevel, c.maxPacketSize(), true, now, c.version)
		if err != nil {
			return err
		}
	}
	if packet == nil || (len(packet.longHdrPackets) == 0 && packet.shortHdrPacket == nil) {
		return fmt.Errorf("connection BUG: couldn't pack %s probe packet: %v", encLevel, packet)
	}
	return c.sendPackedCoalescedPacket(packet, c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now)
}

// appendOneShortHeaderPacket appends a new packet to the given packetBuffer.
// If there was nothing to pack, the returned size is 0.
func (c *Conn) appendOneShortHeaderPacket(buf *packetBuffer, maxSize protocol.ByteCount, ecn protocol.ECN, now monotime.Time) (protocol.ByteCount, error) {
	startLen := buf.Len()
	p, err := c.packer.AppendPacket(buf, maxSize, now, c.version)
	if err != nil {
		return 0, err
	}
	size := buf.Len() - startLen
	c.logShortHeaderPacket(p, ecn, size)
	c.registerPackedShortHeaderPacket(p, ecn, now)
	return size, nil
}

func (c *Conn) registerPackedShortHeaderPacket(p shortHeaderPacket, ecn protocol.ECN, now monotime.Time) {
	if p.IsPathProbePacket {
		c.sentPacketHandler.SentPacket(
			now,
			p.PacketNumber,
			protocol.InvalidPacketNumber,
			p.StreamFrames,
			p.Frames,
			protocol.Encryption1RTT,
			ecn,
			p.Length,
			p.IsPathMTUProbePacket,
			true,
		)
		return
	}
	if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
		c.firstAckElicitingPacketAfterIdleSentTime = now
	}

	largestAcked := protocol.InvalidPacketNumber
	if p.Ack != nil {
		largestAcked = p.Ack.LargestAcked()
	}
	// A packet packed for a non-zero multipath path is recorded against that
	// path's own send state (its number space + congestion controller). For
	// PathIDZero this is identical to the SentPacket call above.
	if p.PathID != protocol.PathIDZero {
		c.sentPacketHandler.SentPacketForPath(
			now,
			p.PacketNumber,
			largestAcked,
			p.PathID,
			p.StreamFrames,
			p.Frames,
			ecn,
			p.Length,
			p.IsPathMTUProbePacket,
		)
		return
	}
	if p.HasStreamFrame && len(p.StreamFrames) == 0 {
		c.sentPacketHandler.SentPacketOneStream(
			now,
			p.PacketNumber,
			largestAcked,
			p.StreamFrame,
			p.Frames,
			ecn,
			p.Length,
			p.IsPathMTUProbePacket,
		)
		c.connIDManager.SentPacket()
		return
	}
	c.sentPacketHandler.SentPacket(
		now,
		p.PacketNumber,
		largestAcked,
		p.StreamFrames,
		p.Frames,
		protocol.Encryption1RTT,
		ecn,
		p.Length,
		p.IsPathMTUProbePacket,
		false,
	)
	c.connIDManager.SentPacket()
}

func (c *Conn) sendPackedCoalescedPacket(packet *coalescedPacket, ecn protocol.ECN, now monotime.Time) error {
	c.logCoalescedPacket(packet, ecn)
	for _, p := range packet.longHdrPackets {
		if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			c.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked := protocol.InvalidPacketNumber
		if p.ack != nil {
			largestAcked = p.ack.LargestAcked()
		}
		c.sentPacketHandler.SentPacket(
			now,
			p.header.PacketNumber,
			largestAcked,
			p.streamFrames,
			p.frames,
			p.EncryptionLevel(),
			ecn,
			p.length,
			false,
			false,
		)
		if c.perspective == protocol.PerspectiveClient && p.EncryptionLevel() == protocol.EncryptionHandshake &&
			!c.droppedInitialKeys {
			// On the client side, Initial keys are dropped as soon as the first Handshake packet is sent.
			// See Section 4.9.1 of RFC 9001.
			if err := c.dropEncryptionLevel(protocol.EncryptionInitial, now); err != nil {
				return err
			}
		}
	}
	if p := packet.shortHdrPacket; p != nil {
		if c.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			c.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked := protocol.InvalidPacketNumber
		if p.Ack != nil {
			largestAcked = p.Ack.LargestAcked()
		}
		if p.HasStreamFrame && len(p.StreamFrames) == 0 {
			c.sentPacketHandler.SentPacketOneStream(
				now,
				p.PacketNumber,
				largestAcked,
				p.StreamFrame,
				p.Frames,
				ecn,
				p.Length,
				p.IsPathMTUProbePacket,
			)
		} else {
			c.sentPacketHandler.SentPacket(
				now,
				p.PacketNumber,
				largestAcked,
				p.StreamFrames,
				p.Frames,
				protocol.Encryption1RTT,
				ecn,
				p.Length,
				p.IsPathMTUProbePacket,
				false,
			)
		}
	}
	c.connIDManager.SentPacket()
	c.sendQueue.Send(packet.buffer, 0, ecn)
	return nil
}

func (c *Conn) sendConnectionClose(e error) ([]byte, error) {
	var packet *coalescedPacket
	var err error
	var transportErr *qerr.TransportError
	var applicationErr *qerr.ApplicationError
	if errors.As(e, &transportErr) {
		packet, err = c.packer.PackConnectionClose(transportErr, c.maxPacketSize(), c.version)
	} else if errors.As(e, &applicationErr) {
		packet, err = c.packer.PackApplicationClose(applicationErr, c.maxPacketSize(), c.version)
	} else {
		packet, err = c.packer.PackConnectionClose(&qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: fmt.Sprintf("connection BUG: unspecified error type (msg: %s)", e.Error()),
		}, c.maxPacketSize(), c.version)
	}
	if err != nil {
		return nil, err
	}
	ecn := c.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket())
	c.logCoalescedPacket(packet, ecn)
	return packet.buffer.Data, c.conn.Write(packet.buffer.Data, 0, ecn)
}

func (c *Conn) maxPacketSize() protocol.ByteCount {
	if c.mtuDiscoverer == nil {
		// Use the configured packet size on the client side.
		// If the server sends a max_udp_payload_size that's smaller than this size, we can ignore this:
		// Apparently the server still processed the (fully padded) Initial packet anyway.
		if c.perspective == protocol.PerspectiveClient {
			return protocol.ByteCount(c.config.InitialPacketSize)
		}
		// On the server side, there's no downside to using 1200 bytes until we received the client's transport
		// parameters:
		// * If the first packet didn't contain the entire ClientHello, all we can do is ACK that packet. We don't
		//   need a lot of bytes for that.
		// * If it did, we will have processed the transport parameters and initialized the MTU discoverer.
		return protocol.MinInitialPacketSize
	}
	return c.mtuDiscoverer.CurrentSize()
}

// AcceptStream returns the next stream opened by the peer, blocking until one is available.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	return c.streamsMap.AcceptStream(ctx)
}

// AcceptUniStream returns the next unidirectional stream opened by the peer, blocking until one is available.
func (c *Conn) AcceptUniStream(ctx context.Context) (*ReceiveStream, error) {
	return c.streamsMap.AcceptUniStream(ctx)
}

// OpenStream opens a new bidirectional QUIC stream.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
// When reaching the peer's stream limit, it is not possible to open a new stream until the
// peer raises the stream limit. In that case, a [StreamLimitReachedError] is returned.
func (c *Conn) OpenStream() (*Stream, error) {
	return c.streamsMap.OpenStream()
}

// OpenStreamSync opens a new bidirectional QUIC stream.
// It blocks until a new stream can be opened.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
func (c *Conn) OpenStreamSync(ctx context.Context) (*Stream, error) {
	return c.streamsMap.OpenStreamSync(ctx)
}

// OpenUniStream opens a new outgoing unidirectional QUIC stream.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
// When reaching the peer's stream limit, it is not possible to open a new stream until the
// peer raises the stream limit. In that case, a [StreamLimitReachedError] is returned.
func (c *Conn) OpenUniStream() (*SendStream, error) {
	return c.streamsMap.OpenUniStream()
}

// OpenUniStreamSync opens a new outgoing unidirectional QUIC stream.
// It blocks until a new stream can be opened.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream,
// or the stream has been reset or closed.
func (c *Conn) OpenUniStreamSync(ctx context.Context) (*SendStream, error) {
	return c.streamsMap.OpenUniStreamSync(ctx)
}

func (c *Conn) newFlowController(id protocol.StreamID) flowcontrol.StreamFlowController {
	peerParams := c.peerParams.Load()
	initialSendWindow := peerParams.InitialMaxStreamDataUni
	if id.Type() == protocol.StreamTypeBidi {
		if id.InitiatedBy() == c.perspective {
			initialSendWindow = peerParams.InitialMaxStreamDataBidiRemote
		} else {
			initialSendWindow = peerParams.InitialMaxStreamDataBidiLocal
		}
	}
	return flowcontrol.NewStreamFlowController(
		id,
		c.connFlowController,
		protocol.ByteCount(c.config.InitialStreamReceiveWindow),
		protocol.ByteCount(c.config.MaxStreamReceiveWindow),
		initialSendWindow,
		c.rttStats,
		c.logger,
	)
}

// scheduleSending signals that we have data for sending
func (c *Conn) scheduleSending() {
	select {
	case c.sendingScheduled <- struct{}{}:
	default:
	}
}

// tryQueueingUndecryptablePacket queues a packet for which we're missing the decryption keys.
// The qlogevents.PacketType is only used for logging purposes.
func (c *Conn) tryQueueingUndecryptablePacket(p receivedPacket, pt qlog.PacketType, datagramID qlog.DatagramID) {
	if c.handshakeComplete {
		panic("shouldn't queue undecryptable packets after handshake completion")
	}
	if len(c.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		if c.qlogger != nil {
			c.qlogger.RecordEvent(qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   pt,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:        qlog.RawInfo{Length: int(p.Size())},
				DatagramID: datagramID,
				Trigger:    qlog.PacketDropDOSPrevention,
			})
		}
		c.logger.Infof("Dropping undecryptable packet (%d bytes). Undecryptable packet queue full.", p.Size())
		return
	}
	c.logger.Infof("Queueing packet (%d bytes) for later decryption", p.Size())
	if c.qlogger != nil {
		c.qlogger.RecordEvent(qlog.PacketBuffered{
			Header: qlog.PacketHeader{
				PacketType:   pt,
				PacketNumber: protocol.InvalidPacketNumber,
			},
			Raw:        qlog.RawInfo{Length: int(p.Size())},
			DatagramID: datagramID,
		})
	}
	c.undecryptablePackets = append(c.undecryptablePackets, receivedPacketWithDatagramID{receivedPacket: p, datagramID: datagramID})
}

func (c *Conn) queueControlFrame(f wire.Frame) {
	c.framer.QueueControlFrame(f)
	c.scheduleSending()
}

func (c *Conn) onHasConnectionData() { c.scheduleSending() }

func (c *Conn) onHasStreamData(id protocol.StreamID, str *SendStream) {
	c.framer.AddActiveStream(id, str)
	c.scheduleSending()
}

func (c *Conn) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	c.framer.AddStreamWithControlFrames(id, str)
	c.scheduleSending()
}

func (c *Conn) onStreamCompleted(id protocol.StreamID) {
	if err := c.streamsMap.DeleteStream(id); err != nil {
		c.closeLocal(err)
	}
	c.framer.RemoveActiveStream(id)
}

// SendDatagram sends a message using a QUIC datagram, as specified in RFC 9221,
// if the peer enabled datagram support.
// There is no delivery guarantee for DATAGRAM frames, they are not retransmitted if lost.
// The payload of the datagram needs to fit into a single QUIC packet.
// In addition, a datagram may be dropped before being sent out if the available packet size suddenly decreases.
// If the payload is too large to be sent at the current time, a DatagramTooLargeError is returned.
func (c *Conn) SendDatagram(p []byte) error {
	if !c.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	maxDataLen, _ := c.MaxDatagramSize()
	if int64(len(p)) > maxDataLen {
		return &DatagramTooLargeError{MaxDatagramPayloadSize: maxDataLen}
	}
	f := &wire.DatagramFrame{DataLenPresent: true}
	f.Data = make([]byte, len(p))
	copy(f.Data, p)
	return c.datagramQueue.Add(f)
}

// MaxDatagramSize returns the largest payload currently accepted by
// SendDatagram. The size may change as the path MTU estimate changes.
func (c *Conn) MaxDatagramSize() (int64, bool) {
	if !c.supportsDatagrams() {
		return 0, false
	}
	f := &wire.DatagramFrame{DataLenPresent: true}
	// The payload size estimate is conservative. Under many circumstances we
	// could send a few more bytes.
	maxDataLen := min(
		f.MaxDataLen(c.peerParams.Load().MaxDatagramFrameSize, c.version),
		protocol.ByteCount(c.currentMTUEstimate.Load()),
	)
	return int64(maxDataLen), true
}

// ReceiveDatagram gets a message received in a QUIC datagram, as specified in RFC 9221.
func (c *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if !c.config.EnableDatagrams {
		return nil, errors.New("datagram support disabled")
	}
	return c.datagramQueue.Receive(ctx)
}

// LocalAddr returns the local address of the QUIC connection.
func (c *Conn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the remote address of the QUIC connection.
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// RemoteAddrValidated reports whether the peer's transport address was
// validated by a QUIC address-validation token before this connection was
// accepted. It is only meaningful on server-side early connections.
func (c *Conn) RemoteAddrValidated() bool { return c.remoteAddrValidated }

// getPathManager lazily initializes the Conn's pathManagerOutgoing.
// May create multiple pathManagerOutgoing objects if called concurrently.
func (c *Conn) getPathManager() *pathManagerOutgoing {
	old := c.pathManagerOutgoing.Load()
	if old != nil {
		// Path manager is already initialized
		return old
	}

	// Initialize the path manager
	new := newPathManagerOutgoing(
		c.connIDManager.GetConnIDForPath,
		c.connIDManager.RetireConnIDForPath,
		c.scheduleSending,
	)
	if c.pathManagerOutgoing.CompareAndSwap(old, new) {
		return new
	}

	// Swap failed. A concurrent writer wrote first, use their value.
	return c.pathManagerOutgoing.Load()
}

func (c *Conn) AddPath(t *Transport) (*Path, error) {
	if c.perspective == protocol.PerspectiveServer {
		return nil, errors.New("server cannot initiate connection migration")
	}
	if c.peerParams.Load().DisableActiveMigration {
		return nil, errors.New("server disabled connection migration")
	}
	if err := t.init(false); err != nil {
		return nil, err
	}
	return c.getPathManager().NewPath(
		t,
		200*time.Millisecond, // initial RTT estimate
		func() {
			runner := (*packetHandlerMap)(t)
			c.connIDGenerator.AddConnRunner(
				runner,
				connRunnerCallbacks{
					AddConnectionID:    func(connID protocol.ConnectionID) { runner.Add(connID, c) },
					RemoveConnectionID: runner.Remove,
					ReplaceWithClosed:  runner.ReplaceWithClosed,
				},
			)
		},
	), nil
}

// HandshakeComplete blocks until the handshake completes (or fails).
// For the client, data sent before completion of the handshake is encrypted with 0-RTT keys.
// For the server, data sent before completion of the handshake is encrypted with 1-RTT keys,
// however the client's identity is only verified once the handshake completes.
func (c *Conn) HandshakeComplete() <-chan struct{} {
	return c.handshakeCompleteChan
}

// QlogTrace returns the qlog trace of the QUIC connection.
// It is nil if qlog is not enabled.
func (c *Conn) QlogTrace() qlogwriter.Trace {
	return c.qlogTrace
}

// NextConnection transitions a connection to be usable after a 0-RTT rejection.
// It waits for the handshake to complete and then enables the connection for normal use.
// This should be called when the server rejects 0-RTT and the application receives
// [Err0RTTRejected] errors.
//
// Note that 0-RTT rejection invalidates all data sent in 0-RTT packets. It is the
// application's responsibility to handle this (for example by resending the data).
func (c *Conn) NextConnection(ctx context.Context) (*Conn, error) {
	// The handshake might fail after the server rejected 0-RTT.
	// This could happen if the Finished message is malformed or never received.
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.Context().Done():
	case <-c.HandshakeComplete():
		c.streamsMap.UseResetMaps()
	}
	return c, nil
}

// estimateMaxPayloadSize estimates the maximum payload size for short header packets.
// It is not very sophisticated: it just subtracts the size of header (assuming the maximum
// connection ID length), and the size of the encryption tag.
func estimateMaxPayloadSize(mtu protocol.ByteCount) protocol.ByteCount {
	return mtu - 1 /* type byte */ - 20 /* maximum connection ID length */ - 16 /* tag size */
}
