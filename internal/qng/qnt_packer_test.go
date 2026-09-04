package quic

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/handshake"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestQNTPackerPullsQueuedAddAddressFrame(t *testing.T) {
	f := newFramer(noopConnFC())
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
	f.QueueControlFrame(&wire.AddAddressFrame{
		SeqNo: 7,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})

	p := &packetPacker{
		framer:              f,
		acks:                noAckFrameSource{},
		retransmissionQueue: newRetransmissionQueue(),
	}
	pl := p.composeNextPacket(1200, false, true, monotime.Now(), protocol.Version1)
	if len(pl.frames) != 1 {
		t.Fatalf("packed %d control frames, want 1", len(pl.frames))
	}
	got, ok := pl.frames[0].Frame.(*wire.AddAddressFrame)
	if !ok {
		t.Fatalf("packed frame = %T, want *wire.AddAddressFrame", pl.frames[0].Frame)
	}
	if got.SeqNo != 7 || netip.AddrPortFrom(got.Addr, got.Port) != addr {
		t.Fatalf("ADD_ADDRESS = seq %d %s:%d, want seq 7 %v", got.SeqNo, got.Addr, got.Port, addr)
	}
	if pl.frames[0].Handler == nil {
		t.Fatal("ADD_ADDRESS frame has no retransmission handler")
	}
	if f.HasData() {
		t.Fatal("framer still has data after packer pulled ADD_ADDRESS")
	}
}

func TestQNTPackerPullsQueuedReachOutFrame(t *testing.T) {
	f := newFramer(noopConnFC())
	addr := netip.MustParseAddrPort("[2001:db8::1]:5678")
	f.QueueControlFrame(&wire.ReachOutFrame{
		Round: 9,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})

	p := &packetPacker{
		framer:              f,
		acks:                noAckFrameSource{},
		retransmissionQueue: newRetransmissionQueue(),
	}
	pl := p.composeNextPacket(1200, false, true, monotime.Now(), protocol.Version1)
	if len(pl.frames) != 1 {
		t.Fatalf("packed %d control frames, want 1", len(pl.frames))
	}
	got, ok := pl.frames[0].Frame.(*wire.ReachOutFrame)
	if !ok {
		t.Fatalf("packed frame = %T, want *wire.ReachOutFrame", pl.frames[0].Frame)
	}
	if got.Round != 9 || netip.AddrPortFrom(got.Addr, got.Port) != addr {
		t.Fatalf("REACH_OUT = round %d %s:%d, want round 9 %v", got.Round, got.Addr, got.Port, addr)
	}
	if pl.frames[0].Handler == nil {
		t.Fatal("REACH_OUT frame has no retransmission handler")
	}
	if f.HasData() {
		t.Fatal("framer still has data after packer pulled REACH_OUT")
	}
}

func TestQNTPackNextProbePacksPathChallenge(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.version = protocol.Version1
	c.packer = newQNTProbeTestPacker()
	remote := netip.MustParseAddrPort("198.51.100.7:4433")
	c.qntLocalState().pendingProbes = []netip.AddrPort{remote}

	got, packet, buf, ok, err := c.qntPackNextProbe(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), protocol.Version1)
	if err != nil {
		t.Fatalf("qntPackNextProbe: %v", err)
	}
	if !ok {
		t.Fatal("qntPackNextProbe ok = false, want true")
	}
	defer buf.Release()
	if got != remote {
		t.Fatalf("qntPackNextProbe remote = %v, want %v", got, remote)
	}
	if !packet.IsPathProbePacket {
		t.Fatal("packed packet IsPathProbePacket = false, want true")
	}
	if packet.PacketNumber != 1 {
		t.Fatalf("packet number = %d, want 1", packet.PacketNumber)
	}
	if len(packet.Frames) != 1 {
		t.Fatalf("packed frames = %d, want 1", len(packet.Frames))
	}
	challenge, ok := packet.Frames[0].Frame.(*wire.PathChallengeFrame)
	if !ok {
		t.Fatalf("packed frame = %T, want *wire.PathChallengeFrame", packet.Frames[0].Frame)
	}
	if challenge.Data == ([8]byte{}) {
		t.Fatal("PATH_CHALLENGE data is zero")
	}
	if matched, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge.Data}, remote); !ok || matched != remote {
		t.Fatalf("qntConsumePathResponse = %v, %v, want %v, true", matched, ok, remote)
	}
	if len(buf.Data) < int(protocol.MinInitialPacketSize) {
		t.Fatalf("packed buffer length = %d, want at least %d", len(buf.Data), protocol.MinInitialPacketSize)
	}
}

func TestQNTPackNextProbeReturnsFalseWhenEmpty(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.packer = newQNTProbeTestPacker()

	remote, packet, buf, ok, err := c.qntPackNextProbe(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), protocol.Version1)
	if err != nil {
		t.Fatalf("qntPackNextProbe: %v", err)
	}
	if ok || remote.IsValid() || buf != nil || packet.IsPathProbePacket {
		t.Fatalf("qntPackNextProbe empty = %v, %+v, %v, %v, want zero packet nil false", remote, packet, buf, ok)
	}
}

func TestQNTPackNextProbeInvalidStateNoop(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.packer = newQNTProbeTestPacker()
	c.qntLocalState().pendingProbes = []netip.AddrPort{netip.AddrPort{}}

	remote, packet, buf, ok, err := c.qntPackNextProbe(protocol.ParseConnectionID([]byte{1, 2, 3, 4}), protocol.Version1)
	if err != nil {
		t.Fatalf("qntPackNextProbe: %v", err)
	}
	if ok || remote.IsValid() || buf != nil || packet.IsPathProbePacket {
		t.Fatalf("qntPackNextProbe invalid = %v, %+v, %v, %v, want zero packet nil false", remote, packet, buf, ok)
	}
}

func TestQNTSendProbeBufferReleasesPacketBuffer(t *testing.T) {
	buf := getPacketBuffer()
	buf.Data = append(buf.Data, 1, 2, 3)
	s := &qntProbeTestSender{available: make(chan struct{})}
	c := &Conn{sendQueue: s}
	addr := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4433}

	c.sendQNTProbeBuffer(buf, addr)

	if s.probes != 1 {
		t.Fatalf("SendProbe calls = %d, want 1", s.probes)
	}
	if !s.addr.IP.Equal(addr.IP) || s.addr.Port != addr.Port {
		t.Fatalf("SendProbe addr = %v, want %v", s.addr, addr)
	}
	if string(s.data) != string([]byte{1, 2, 3}) {
		t.Fatalf("SendProbe data = %v, want [1 2 3]", s.data)
	}
	if buf.refCount != 0 {
		t.Fatalf("packet buffer refCount = %d, want 0 after synchronous probe send", buf.refCount)
	}
}

func TestSendPathBufferUsesDefaultQueueForOrdinaryPath(t *testing.T) {
	buf := getPacketBuffer()
	buf.Data = append(buf.Data, 1, 2, 3)
	s := &qntProbeTestSender{available: make(chan struct{})}
	c := &Conn{sendQueue: s}

	c.sendPathBuffer(buf, protocol.ECNNon, &pathOpenState{})

	if s.sends != 1 {
		t.Fatalf("Send calls = %d, want 1", s.sends)
	}
	if s.probes != 0 {
		t.Fatalf("SendProbe calls = %d, want 0", s.probes)
	}
	if string(s.data) != string([]byte{1, 2, 3}) {
		t.Fatalf("Send data = %v, want [1 2 3]", s.data)
	}
	if s.ecn != protocol.ECNNon {
		t.Fatalf("Send ECN = %v, want ECNNon", s.ecn)
	}
}

func TestSendPathBufferUsesQNTRoute(t *testing.T) {
	buf := getPacketBuffer()
	buf.Data = append(buf.Data, 1, 2, 3)
	s := &qntProbeTestSender{available: make(chan struct{})}
	c := &Conn{sendQueue: s}
	route := netip.MustParseAddrPort("[::ffff:198.51.100.7]:4433")
	want := &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 4433}
	path := &pathOpenState{qntRoute: route}

	c.sendPathBuffer(buf, protocol.ECNNon, path)

	if s.sends != 0 {
		t.Fatalf("Send calls = %d, want 0", s.sends)
	}
	if s.probes != 1 {
		t.Fatalf("SendProbe calls = %d, want 1", s.probes)
	}
	if !s.addr.IP.Equal(want.IP) || s.addr.Port != want.Port {
		t.Fatalf("SendProbe addr = %v, want %v", s.addr, want)
	}
	if string(s.data) != string([]byte{1, 2, 3}) {
		t.Fatalf("SendProbe data = %v, want [1 2 3]", s.data)
	}
	if buf.refCount != 0 {
		t.Fatalf("packet buffer refCount = %d, want 0 after synchronous route send", buf.refCount)
	}
	if path.qntUDPAddr == nil || !path.qntUDPAddr.IP.Equal(want.IP) || path.qntUDPAddr.Port != want.Port {
		t.Fatalf("cached QNT addr = %v, want %v", path.qntUDPAddr, want)
	}
}

func TestSendPathBufferDropsInvalidQNTRoute(t *testing.T) {
	buf := getPacketBuffer()
	buf.Data = append(buf.Data, 1, 2, 3)
	s := &qntProbeTestSender{available: make(chan struct{})}
	c := &Conn{sendQueue: s}

	c.sendPathBuffer(buf, protocol.ECNNon, &pathOpenState{qntRoute: netip.MustParseAddrPort("198.51.100.7:0")})

	if s.sends != 0 {
		t.Fatalf("Send calls = %d, want 0", s.sends)
	}
	if s.probes != 0 {
		t.Fatalf("SendProbe calls = %d, want 0", s.probes)
	}
	if buf.refCount != 0 {
		t.Fatalf("packet buffer refCount = %d, want 0 after invalid route drop", buf.refCount)
	}
}

func TestSendPackedCoalescedPacketPreservesOneStreamFrame(t *testing.T) {
	rtt := utils.NewRTTStats()
	c := &Conn{
		logger: utils.DefaultLogger,
		connIDManager: newConnIDManager(
			protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
			func(protocol.StatelessResetToken) {},
			func(protocol.StatelessResetToken) {},
			func(wire.Frame) {},
		),
		sendQueue: &qntProbeTestSender{available: make(chan struct{})},
		sentPacketHandler: ackhandler.NewSentPacketHandler(
			0,
			protocol.InitialPacketSize,
			rtt,
			&utils.ConnectionStats{},
			true,
			false,
			nil,
			protocol.PerspectiveClient,
			nil,
			utils.DefaultLogger,
		),
	}
	handler := &coalescedStreamLossHandler{}
	packet := &coalescedPacket{
		buffer: getPacketBuffer(),
		shortHdrPacket: &shortHeaderPacket{
			PacketNumber: 1,
			StreamFrame: ackhandler.StreamFrame{
				Frame:   &wire.StreamFrame{StreamID: 0, Offset: 32, Data: []byte("payload")},
				Handler: handler,
			},
			HasStreamFrame: true,
			Length:         1200,
		},
	}

	if err := c.sendPackedCoalescedPacket(packet, protocol.ECNNon, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	for pn := protocol.PacketNumber(2); pn <= 4; pn++ {
		c.sentPacketHandler.SentPacket(
			monotime.Now(),
			pn,
			protocol.InvalidPacketNumber,
			nil,
			[]ackhandler.Frame{{Frame: &wire.PingFrame{}}},
			protocol.Encryption1RTT,
			protocol.ECNNon,
			1200,
			false,
			false,
		)
	}
	if _, err := c.sentPacketHandler.ReceivedAck(&wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: 4, Largest: 4}},
	}, protocol.Encryption1RTT, monotime.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if handler.lost != 1 {
		t.Fatalf("stream loss callbacks = %d; want 1", handler.lost)
	}
}

type coalescedStreamLossHandler struct {
	lost int
}

func (h *coalescedStreamLossHandler) OnAcked(wire.Frame) {}

func (h *coalescedStreamLossHandler) OnLost(wire.Frame) {
	h.lost++
}

func TestSendPathPacketSkipsInvalidQNTRouteBeforePack(t *testing.T) {
	c := &Conn{}
	st := &pathOpenState{qntRoute: netip.MustParseAddrPort("198.51.100.7:0")}
	frame := ackhandler.Frame{Frame: &wire.PathChallengeFrame{}}

	err := c.sendPathPacket(
		protocol.PathID(1),
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		st,
		[]ackhandler.Frame{frame},
		monotime.Now(),
	)
	if err != nil {
		t.Fatalf("sendPathPacket: %v", err)
	}
}

func TestSendPathPacketSkipsOrdinaryPathWhenSendQueueBlocked(t *testing.T) {
	s := &qntProbeTestSender{wouldBlock: true, available: make(chan struct{})}
	c := &Conn{
		sendQueue:        s,
		sendingScheduled: make(chan struct{}, 1),
	}
	frame := ackhandler.Frame{Frame: &wire.PathChallengeFrame{}}

	err := c.sendPathPacket(
		protocol.PathID(1),
		protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		&pathOpenState{},
		[]ackhandler.Frame{frame},
		monotime.Now(),
	)
	if err != nil {
		t.Fatalf("sendPathPacket: %v", err)
	}
	if s.sends != 0 {
		t.Fatalf("Send calls = %d, want 0", s.sends)
	}
	if len(c.sendingScheduled) != 1 {
		t.Fatalf("sendingScheduled length = %d, want 1", len(c.sendingScheduled))
	}
}

func TestSendOnPathSkipsInvalidQNTRouteBeforePack(t *testing.T) {
	data := [][]byte{[]byte("queued")}
	st := &pathOpenState{
		qntRoute: netip.MustParseAddrPort("198.51.100.7:0"),
		sendData: data,
	}

	err := (&Conn{}).sendOnPath(protocol.PathID(1), st, monotime.Now())
	if err != nil {
		t.Fatalf("sendOnPath: %v", err)
	}
	if len(st.sendData) != 1 || string(st.sendData[0]) != "queued" {
		t.Fatalf("sendData = %q, want queued data preserved", st.sendData)
	}
}

func TestSendOnPathSkipsOrdinaryPathWhenSendQueueBlocked(t *testing.T) {
	s := &qntProbeTestSender{wouldBlock: true, available: make(chan struct{})}
	c := &Conn{
		sendQueue:        s,
		sendingScheduled: make(chan struct{}, 1),
	}
	st := &pathOpenState{sendData: [][]byte{[]byte("queued")}}

	if err := c.sendOnPath(protocol.PathID(1), st, monotime.Now()); err != nil {
		t.Fatalf("sendOnPath: %v", err)
	}
	if s.sends != 0 {
		t.Fatalf("Send calls = %d, want 0", s.sends)
	}
	if len(c.sendingScheduled) != 1 {
		t.Fatalf("sendingScheduled length = %d, want 1", len(c.sendingScheduled))
	}
	if len(st.sendData) != 1 || string(st.sendData[0]) != "queued" {
		t.Fatalf("sendData = %q, want queued data preserved", st.sendData)
	}
}

func TestDriveMultipathRequestsPeerCIDWhenMissing(t *testing.T) {
	c, _ := newQNTRoutePathTestConn(t)
	c.handshakeConfirmed = true
	c.multipathOut = newMultipathOutgoing()
	c.multipathOut.paths[protocol.PathID(1)] = &pathOpenState{id: protocol.PathID(1), validatedChan: make(chan struct{})}

	if err := c.driveMultipath(monotime.Now()); err != nil {
		t.Fatalf("driveMultipath: %v", err)
	}
	frames := queuedPathCIDsBlockedFrames(c)
	if len(frames) != 1 {
		t.Fatalf("queued PATH_CIDS_BLOCKED frames = %d, want 1", len(frames))
	}
	if frames[0].PathID != protocol.PathID(1) || frames[0].NextSeq != 0 {
		t.Fatalf("PATH_CIDS_BLOCKED = path %d seq %d, want path 1 seq 0", frames[0].PathID, frames[0].NextSeq)
	}

	if err := c.driveMultipath(monotime.Now()); err != nil {
		t.Fatalf("second driveMultipath: %v", err)
	}
	if frames := queuedPathCIDsBlockedFrames(c); len(frames) != 1 {
		t.Fatalf("queued PATH_CIDS_BLOCKED frames after second drive = %d, want 1", len(frames))
	}
}

func TestQNTDriveMultipathSendsRouteDataViaSendProbe(t *testing.T) {
	c, _ := newQNTRoutePathTestConn(t)
	c.handshakeConfirmed = true
	c.perspective = protocol.PerspectiveClient
	c.config.InitialPacketSize = protocol.InitialPacketSize
	c.version = protocol.Version1
	c.logger = utils.DefaultLogger
	c.conn = qntProbeSendConn{}
	c.multipathManager.handleMaxPathID(protocol.PathID(4))

	s := &qntProbeTestSender{available: make(chan struct{})}
	c.sendQueue = s
	c.perPathDestConnIDs = make(map[protocol.PathID]protocol.ConnectionID)
	packer := newQNTProbeTestPacker()
	packer.getDestConnIDForPath = c.destConnIDForPath
	c.packer = packer

	route := netip.MustParseAddrPort("198.51.100.44:4433")
	c.qntQueueValidatedProbe(route)
	pid, gotRoute, ok, err := c.qntOpenValidatedPathLocked()
	if err != nil {
		t.Fatalf("qntOpenValidatedPathLocked: %v", err)
	}
	if !ok {
		t.Fatal("qntOpenValidatedPathLocked ok = false, want true")
	}
	if gotRoute != route {
		t.Fatalf("qntOpenValidatedPathLocked route = %v, want %v", gotRoute, route)
	}
	c.perPathDestConnIDs[pid] = protocol.ParseConnectionID([]byte{1, 2, 3, 4})

	st := c.multipathOut.paths[pid]
	st.validated = true
	st.sendData = append(st.sendData, []byte("qnt route payload"))

	if err := c.driveMultipath(monotime.Now()); err != nil {
		t.Fatalf("driveMultipath: %v", err)
	}
	if s.probes != 1 || s.sends != 0 {
		t.Fatalf("sender probes/sends = %d/%d, want 1/0", s.probes, s.sends)
	}
	if s.addr == nil || netip.AddrPortFrom(s.addr.AddrPort().Addr(), uint16(s.addr.Port)) != route {
		t.Fatalf("SendProbe addr = %v, want %v", s.addr, route)
	}
	if len(s.data) == 0 {
		t.Fatal("SendProbe packet is empty")
	}
	if len(st.sendData) != 0 {
		t.Fatalf("route path sendData length = %d, want 0", len(st.sendData))
	}

	if err := c.driveMultipath(monotime.Now()); err != nil {
		t.Fatalf("second driveMultipath: %v", err)
	}
	if s.probes != 1 || s.sends != 0 {
		t.Fatalf("second drive probes/sends = %d/%d, want 1/0", s.probes, s.sends)
	}
}

func newQNTProbeTestPacker() *packetPacker {
	return &packetPacker{
		cryptoSetup:         qntProbeCryptoSetup{},
		pnManager:           &qntProbePNManager{pn: 1},
		retransmissionQueue: newRetransmissionQueue(),
		acks:                noAckFrameSource{},
	}
}

type qntProbeCryptoSetup struct{}

func (qntProbeCryptoSetup) GetInitialSealer() (handshake.LongHeaderSealer, error) {
	return nil, errors.New("initial sealer unused")
}

func (qntProbeCryptoSetup) GetHandshakeSealer() (handshake.LongHeaderSealer, error) {
	return nil, errors.New("handshake sealer unused")
}

func (qntProbeCryptoSetup) Get0RTTSealer() (handshake.LongHeaderSealer, error) {
	return nil, errors.New("0-rtt sealer unused")
}

func (qntProbeCryptoSetup) Get1RTTSealer() (handshake.ShortHeaderSealer, error) {
	return qntProbeSealer{}, nil
}

type qntProbeSealer struct{}

func (qntProbeSealer) Seal(dst, src []byte, _ protocol.PathID, _ protocol.PacketNumber, _ []byte) []byte {
	return append(dst, src...)
}

func (qntProbeSealer) EncryptHeader([]byte, *byte, []byte) {}
func (qntProbeSealer) Overhead() int                       { return 0 }
func (qntProbeSealer) KeyPhase() protocol.KeyPhaseBit      { return protocol.KeyPhaseZero }

type qntProbePNManager struct {
	pn protocol.PacketNumber
}

func (m *qntProbePNManager) PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return m.pn, protocol.PacketNumberLen2
}

func (m *qntProbePNManager) PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber {
	pn := m.pn
	m.pn++
	return pn
}

func (m *qntProbePNManager) PeekPacketNumberForPath(protocol.PathID) (protocol.PacketNumber, protocol.PacketNumberLen) {
	return m.PeekPacketNumber(protocol.Encryption1RTT)
}

func (m *qntProbePNManager) PopPacketNumberForPath(protocol.PathID) protocol.PacketNumber {
	return m.PopPacketNumber(protocol.Encryption1RTT)
}

type qntProbeTestSender struct {
	sends      int
	probes     int
	data       []byte
	addr       *net.UDPAddr
	ecn        protocol.ECN
	available  chan struct{}
	wouldBlock bool
}

func (s *qntProbeTestSender) Send(buf *packetBuffer, _ uint16, ecn protocol.ECN) {
	s.sends++
	s.data = append([]byte(nil), buf.Data...)
	s.ecn = ecn
}

func (s *qntProbeTestSender) SendProbe(buf *packetBuffer, addr net.Addr, _ packetInfo) {
	s.probes++
	s.data = append([]byte(nil), buf.Data...)
	if udp, ok := addr.(*net.UDPAddr); ok {
		s.addr = udp
	}
}

func (s *qntProbeTestSender) Run() error                 { return nil }
func (s *qntProbeTestSender) WouldBlock() bool           { return s.wouldBlock }
func (s *qntProbeTestSender) Available() <-chan struct{} { return s.available }
func (s *qntProbeTestSender) Close()                     {}

func queuedPathCIDsBlockedFrames(c *Conn) []*wire.PathCIDsBlockedFrame {
	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	var frames []*wire.PathCIDsBlockedFrame
	for _, f := range c.framer.controlFrames {
		if bf, ok := f.(*wire.PathCIDsBlockedFrame); ok {
			frames = append(frames, bf)
		}
	}
	return frames
}

type qntProbeSendConn struct{}

func (qntProbeSendConn) Write([]byte, uint16, protocol.ECN) error   { return nil }
func (qntProbeSendConn) WriteTo([]byte, net.Addr, packetInfo) error { return nil }
func (qntProbeSendConn) Close() error                               { return nil }
func (qntProbeSendConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (qntProbeSendConn) RemoteAddr() net.Addr                       { return &net.UDPAddr{} }
func (qntProbeSendConn) ChangeRemoteAddr(net.Addr, packetInfo)      {}
func (qntProbeSendConn) capabilities() connCapabilities             { return connCapabilities{} }
func (qntProbeSendConn) SetReadDeadline(time.Time) error            { return nil }

type noAckFrameSource struct{}

func (noAckFrameSource) GetAckFrame(protocol.EncryptionLevel, monotime.Time, bool) *wire.AckFrame {
	return nil
}

func (noAckFrameSource) GetAckFrameForPath(protocol.PathID, monotime.Time, bool) *wire.AckFrame {
	return nil
}

// noopConnFC is a connection flow controller with no credit, for tests that
// never exercise the sending path.
func noopConnFC() *connectionFlowController {
	return newConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
}
