package ackhandler

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/congestion"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/qlog"
	"github.com/tmc/go-iroh/internal/qng/qlogwriter"
)

const (
	// Extra RTT allowance for time-threshold loss detection, in eighths of an RTT.
	defaultTimeThresholdEighths = 1
	maxTimeThresholdEighths     = 8
	// Maximum reordering in packets before packet threshold loss detection considers a packet lost.
	packetThreshold = 3
	// Before validating the client's address, the server won't send more than 3x bytes than it received.
	amplificationFactor = 3
	// We use Retry packets to derive an RTT estimate. Make sure we don't set the RTT to a super low value yet.
	minRTTAfterRetry = 5 * time.Millisecond
	// The PTO duration uses exponential backoff, but is truncated to a maximum value, as allowed by RFC 8961, section 4.4.
	maxPTODuration = 60 * time.Second
)

// Path probe packets are declared lost after this time.
const pathProbePacketLossTimeout = time.Second

type packetNumberSpace struct {
	numOutstanding int

	lossTime                   monotime.Time
	lastAckElicitingPacketTime monotime.Time

	largestAcked protocol.PacketNumber
	largestSent  protocol.PacketNumber
}

func newPacketNumberSpace() *packetNumberSpace {
	return &packetNumberSpace{
		largestSent:  protocol.InvalidPacketNumber,
		largestAcked: protocol.InvalidPacketNumber,
	}
}

type alarmTimer struct {
	Time            monotime.Time
	TimerType       qlog.TimerType
	EncryptionLevel protocol.EncryptionLevel
}

// appDataPath is the per-path state for the application-data (1-RTT/0-RTT)
// packet number space. It mirrors the recovery-relevant subset of
// reference/paths.rs PathData that draft-multipath splits per PathID.
//
// Stage 4b moves the appData recovery state here: the congestion controller
// (paths.rs:167), the RTT estimator (paths.rs:163), bytes-in-flight
// (paths.rs:214 InFlight.bytes), the PTO accounting (paths.rs:236), and the
// ECN tracker (paths.rs:165), in addition to the Stage 4a packet-number
// bookkeeping (the space and its spurious-loss history).
//
// Initial and Handshake recovery stays handler-level (h.bytesInFlight): those
// spaces are not path-scoped and their bytes-in-flight feeds amplification
// accounting during the handshake (Stage 4 spec risk #2).
//
// For PathIDZero — the only path until Stage 5 — congestion, rttStats, pns,
// and hist are the SAME objects the handler was constructed with. Aliasing
// them keeps single-path behavior byte-identical: 1-RTT RTT samples still
// update the connection-level rttStats (used for idle/keepalive/connID timers,
// Stage 4 spec risk #4) and the one shared controller still sees the total
// bytes-in-flight. A genuinely new path (Stage 5) gets its own controller,
// rttStats, pns, and hist.
type appDataPath struct {
	space       *packetNumberSpace
	pns         *packetNumberGenerator
	hist        *sentPacketHistory
	lostPackets lostPacketTracker // spurious-loss history, only for application data
	// send time of the largest acknowledged packet
	largestAckedTime monotime.Time

	rttStats        *utils.RTTStats
	congestion      congestion.SendAlgorithmWithDebugInfos
	bytesInFlight   protocol.ByteCount
	bytesSent       uint64
	bytesReceived   uint64
	lostPacketCount uint64
	lostByteCount   uint64

	// PTO accounting for the application-data space. During the handshake the
	// Initial/Handshake spaces share this single PathIDZero counter, mirroring
	// the reference's PathId::ZERO sharing (paths.rs:154-157), so single-path
	// behavior is identical to the former handler-level ptoCount.
	ptoCount        uint32
	ptoMode         SendMode
	numProbesToSend int

	ecnTracker ecnHandler
}

type pathRef struct {
	id protocol.PathID
	p  *appDataPath
}

type handshakePacketNumbers struct {
	Initial   []protocol.PacketNumber
	Handshake []protocol.PacketNumber
}

func (p *handshakePacketNumbers) Highest() protocol.PacketNumber {
	switch {
	case len(p.Initial) == 0 && len(p.Handshake) == 0:
		return protocol.InvalidPacketNumber
	case len(p.Initial) == 0:
		return p.Handshake[len(p.Handshake)-1]
	case len(p.Handshake) == 0:
		return p.Initial[len(p.Initial)-1]
	default:
		return max(p.Initial[len(p.Initial)-1], p.Handshake[len(p.Handshake)-1])
	}
}
type sentPacketHandler struct {
	// Packet numbers and their history are shared across encryption levels.
	// ACK processing and loss detection still use the state for each space.
	pns  *packetNumberGenerator
	hist sentPacketHistory

	handshakePNs *handshakePacketNumbers

	initialPackets   *packetNumberSpace
	handshakePackets *packetNumberSpace
	// appDataPaths holds the per-path application-data packet number spaces.
	// It always contains exactly the PathIDZero entry until additional paths
	// are opened (Stage 5). With multipath off it stays single-entry, making
	// the path map a behavioral no-op.
	appDataPaths map[protocol.PathID]*appDataPath
	// pathList mirrors appDataPaths for the per-packet fan-out loops.
	pathList []pathRef

	// In the application-data packet number space, packet threshold loss detection is
	// disabled when spurious losses are detected.
	packetThresholdDisabled bool
	timeThresholdEighths    uint8
	// Only packets sent after a time-threshold increase can trigger another one.
	minPNToRelaxReordering protocol.PacketNumber

	// Do we know that the peer completed address validation yet?
	// Always true for the server.
	peerCompletedAddressValidation bool
	bytesReceived                  protocol.ByteCount
	bytesSent                      protocol.ByteCount
	// Have we validated the peer's address yet?
	// Always true for the client.
	peerAddressValidated bool

	handshakeConfirmed bool

	ignorePacketsBelow func(protocol.PacketNumber)

	ackedPackets []packetWithPacketNumber // to avoid allocations in detectAndRemoveAckedPackets

	// bytesInFlight holds the Initial and Handshake bytes in flight. The
	// application-data bytes in flight live per-path on appDataPaths
	// (paths.rs:214). Keeping the handshake portion handler-level preserves
	// amplification accounting during the handshake (Stage 4 spec risk #2).
	bytesInFlight protocol.ByteCount

	// congestion and rttStats are the handshake (Initial/Handshake) recovery
	// state. There is a single congestion controller and a single rttStats;
	// the PathIDZero appData path aliases both, so single-path behavior is
	// byte-identical (Stage 4 spec risk #4: rttStats is the connection's, not
	// repointed).
	congestion congestion.SendAlgorithmWithDebugInfos
	rttStats   *utils.RTTStats
	connStats  *utils.ConnectionStats

	// The alarm timeout
	alarm alarmTimer

	enableECN bool

	// initialMaxDatagramSize is the size NewSentPacketHandler built the
	// connection-level congestion controller with. addPath replays it to build
	// an identical-but-independent controller for a genuinely-new path, so the
	// per-path controller starts from the same initial window the connection's
	// did (mirroring config.get_initial_mtu() in paths.rs:307).
	initialMaxDatagramSize protocol.ByteCount

	perspective protocol.Perspective

	qlogger     qlogwriter.Recorder
	lastMetrics qlog.MetricsUpdated
	logger      utils.Logger
}

var _ SentPacketHandler = &sentPacketHandler{}

// clientAddressValidated indicates whether the address was validated beforehand by an address validation token.
// If the address was validated, the amplification limit doesn't apply. It has no effect for a client.
func NewSentPacketHandler(
	initialPN protocol.PacketNumber,
	initialMaxDatagramSize protocol.ByteCount,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	clientAddressValidated bool,
	enableECN bool,
	ignorePacketsBelow func(protocol.PacketNumber),
	pers protocol.Perspective,
	qlogger qlogwriter.Recorder,
	logger utils.Logger,
) SentPacketHandler {
	congestion := congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		connStats,
		initialMaxDatagramSize,
		true, // use Reno
		qlogger,
	)

	pns := newPacketNumberGenerator(initialPN, skipPacketInitialPeriod, skipPacketMaxPeriod)
	path0 := &appDataPath{
		space:       newPacketNumberSpace(),
		pns:         pns,
		lostPackets: *newLostPacketTracker(),
		// PathIDZero shares the connection's rttStats and the single cubic
		// sender, so 1-RTT RTT samples still update the connection-level
		// rttStats and the one controller sees the total bytes in flight.
		rttStats:   rttStats,
		congestion: congestion,
	}
	h := &sentPacketHandler{
		peerCompletedAddressValidation: pers == protocol.PerspectiveServer,
		peerAddressValidated:           pers == protocol.PerspectiveClient || clientAddressValidated,
		pns:                            pns,
		hist:                           *newSentPacketHistory(),
		timeThresholdEighths:           defaultTimeThresholdEighths,
		minPNToRelaxReordering:         protocol.InvalidPacketNumber,
		handshakePNs: &handshakePacketNumbers{
			Initial:   make([]protocol.PacketNumber, 0, 4),
			Handshake: make([]protocol.PacketNumber, 0, 8),
		},
		initialPackets:   newPacketNumberSpace(),
		handshakePackets: newPacketNumberSpace(),
		appDataPaths: map[protocol.PathID]*appDataPath{
			protocol.PathIDZero: path0,
		},
		pathList:               []pathRef{{protocol.PathIDZero, path0}},
		rttStats:               rttStats,
		connStats:              connStats,
		congestion:             congestion,
		initialMaxDatagramSize: initialMaxDatagramSize,
		ignorePacketsBelow:     ignorePacketsBelow,
		perspective:            pers,
		qlogger:                qlogger,
		logger:                 logger,
	}
	path0.hist = &h.hist
	if enableECN {
		h.enableECN = true
		path0.ecnTracker = newECNTracker(logger, qlogger)
	}
	h.qlogRecoveryParametersSet(true)
	return h
}

// newPathCongestionController builds a congestion controller for a path,
// identical in construction to the one NewSentPacketHandler builds for the
// connection but bound to the supplied rttStats. addPath uses it to give a
// genuinely-new path its own controller (paths.rs:304-307 builds a fresh
// controller per PathData via the congestion-controller factory); PathIDZero
// keeps aliasing the connection's controller.
func (h *sentPacketHandler) newPathCongestionController(rttStats *utils.RTTStats) congestion.SendAlgorithmWithDebugInfos {
	return congestion.NewCubicSender(
		congestion.DefaultClock{},
		rttStats,
		h.connStats,
		h.initialMaxDatagramSize,
		true, // use Reno
		h.qlogger,
	)
}

// AddPath registers a genuinely-new application-data path (pid != PathIDZero)
// so that subsequent send/recovery bookkeeping for that path is tracked
// independently. It gives the path its OWN RTT estimator and its OWN congestion
// controller — never the connection-level h.rttStats / h.congestion that
// PathIDZero aliases — mirroring PathData::new (paths.rs:304-310), which builds
// a fresh controller and a fresh RttEstimator per path. Repointing the
// connection-level rttStats here would leak this path's RTT samples into the
// connection's idle/keepalive/connID-retirement timers (Stage 4 spec risk #4),
// so the per-path controller is constructed against the per-path rttStats.
//
// AddPath is only ever called once multipath is negotiated and a second path is
// opened (Stage 5). With multipath off it is never invoked, so the path map
// stays single-entry and single-path behavior is byte-identical.
//
// AddPath does NOT schedule any send over the new path; the send loop, SendMode
// and SentPacket still operate on PathIDZero until a later sub-increment routes
// them per path. It only provisions the per-path recovery state.
func (h *sentPacketHandler) AddPath(pid protocol.PathID) error {
	return h.addPath(pid)
}

func (h *sentPacketHandler) RemovePath(pid protocol.PathID) {
	if pid == protocol.PathIDZero {
		return
	}
	delete(h.appDataPaths, pid)
	h.pathList = slices.DeleteFunc(h.pathList, func(r pathRef) bool { return r.id == pid })
}

func (h *sentPacketHandler) addPath(pid protocol.PathID) error {
	if pid == protocol.PathIDZero {
		return fmt.Errorf("cannot add path with reserved id %d", protocol.PathIDZero)
	}
	if _, ok := h.appDataPaths[pid]; ok {
		return fmt.Errorf("path %d already exists", pid)
	}
	// A brand-new multipath path gets a fresh RTT estimator (paths.rs:310,
	// RttEstimator::new) and a fresh congestion controller built against it
	// (paths.rs:304-307). Neither is the connection alias.
	rttStats := utils.NewRTTStats()
	path := &appDataPath{
		space:       newPacketNumberSpace(),
		pns:         newPacketNumberGenerator(0, skipPacketInitialPeriod, skipPacketMaxPeriod),
		hist:        newSentPacketHistory(),
		lostPackets: *newLostPacketTracker(),
		rttStats:    rttStats,
		congestion:  h.newPathCongestionController(rttStats),
	}
	if h.enableECN {
		path.ecnTracker = newECNTracker(h.logger, h.qlogger)
	}
	h.appDataPaths[pid] = path
	h.pathList = append(h.pathList, pathRef{pid, path})
	return nil
}

// historyFor returns the sentPacketHistory for (encLevel, pid). For
// Initial/Handshake/0-RTT and PathIDZero 1-RTT this is &h.hist; for a non-zero
// multipath PathID it is that path's independent history.
func (h *sentPacketHandler) historyFor(encLevel protocol.EncryptionLevel, pid protocol.PathID) *sentPacketHistory {
	if encLevel == protocol.Encryption1RTT && pid != protocol.PathIDZero {
		return h.getAppDataPath(pid).hist
	}
	return &h.hist
}

// bytesInFlightFor returns a pointer to the bytes-in-flight counter for
// encLevel: the handler-level counter for Initial/Handshake, the per-path
// counter for application data (0-RTT/1-RTT). The single shared congestion
// controller is fed the total via totalBytesInFlight.
func (h *sentPacketHandler) bytesInFlightFor(encLevel protocol.EncryptionLevel) *protocol.ByteCount {
	switch encLevel {
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return &h.getAppDataPath(protocol.PathIDZero).bytesInFlight
	default:
		return &h.bytesInFlight
	}
}

// bytesInFlightForPacket returns a pointer to the bytes-in-flight counter the
// packet p contributed to: the path's own counter for an application-data
// packet (keyed by p.pathID, which is PathIDZero unless a non-zero path was
// opened), or the handler-level counter for Initial/Handshake.
func (h *sentPacketHandler) bytesInFlightForPacket(p *packet) *protocol.ByteCount {
	switch p.EncryptionLevel {
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		if path := h.getAppDataPath(p.pathID); path != nil {
			return &path.bytesInFlight
		}
		return &h.getAppDataPath(protocol.PathIDZero).bytesInFlight
	default:
		return &h.bytesInFlight
	}
}

// totalBytesInFlight is the sum of the Initial/Handshake bytes in flight and
// the application-data bytes in flight across all paths. The single congestion
// controller operates on this total, so with one path it equals the former
// flat h.bytesInFlight.
func (h *sentPacketHandler) totalBytesInFlight() protocol.ByteCount {
	total := h.bytesInFlight
	for _, r := range h.pathList {
		total += r.p.bytesInFlight
	}
	return total
}

func (h *sentPacketHandler) qlogRecoveryParametersSet(initial bool) {
	if h.qlogger == nil {
		return
	}
	ev := qlog.RecoveryParametersSet{
		EncryptionLevel:         protocol.Encryption1RTT,
		ReorderingThreshold:     packetThreshold,
		PacketThresholdDisabled: h.packetThresholdDisabled,
		TimeThreshold:           float64(8+h.timeThresholdEighths) / 8,
		TimerGranularity:        protocol.TimerGranularity,
	}
	if initial {
		ev.InitialCongestionWindow = h.congestion.GetCongestionWindow()
		ev.InitialRTT = h.rttStats.SmoothedRTT()
	}
	h.qlogger.RecordEvent(ev)
}
func (h *sentPacketHandler) removeFromBytesInFlight(p *packet) {
	if p.includedInBytesInFlight {
		inFlight := h.bytesInFlightForPacket(p)
		if p.Length > *inFlight {
			panic("negative bytes_in_flight")
		}
		*inFlight -= p.Length
		if p.Outstanding() {
			h.getPacketNumberSpaceForPath(p.EncryptionLevel, p.pathID).numOutstanding--
		}
		p.includedInBytesInFlight = false
	}
}

func (h *sentPacketHandler) DropPackets(encLevel protocol.EncryptionLevel, now monotime.Time) {
	if encLevel == protocol.Encryption1RTT {
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
	// The server won't await address validation after the handshake is confirmed.
	// This applies even if we didn't receive an ACK for a Handshake packet.
	if h.perspective == protocol.PerspectiveClient && encLevel == protocol.EncryptionHandshake {
		h.peerCompletedAddressValidation = true
	}
	// remove packets from the history and bytes_in_flight
	pnSpace := h.getPacketNumberSpace(encLevel.PacketNumberSpace())
	// We might already have dropped this packet number space.
	if pnSpace == nil {
		return
	}
	for pn, p := range h.hist.Packets() {
		if pn > pnSpace.largestSent {
			break
		}
		// no 0-RTT packets are sent after the first 1-RTT packet
		if encLevel == protocol.Encryption0RTT && p.EncryptionLevel == protocol.Encryption1RTT {
			break
		}
		if p.EncryptionLevel != encLevel {
			continue
		}
		h.removeFromBytesInFlight(p)
		h.hist.Remove(pn)
	}
	// drop the packet number space
	//nolint:exhaustive // Not every packet number space can be dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		// Dropping the handshake packet number space means that the handshake is confirmed,
		// see section 4.9.2 of RFC 9001.
		h.handshakeConfirmed = true
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// This function is only called when 0-RTT is rejected,
		// and not when the client drops 0-RTT keys when the handshake completes.
	}
	appData := h.getAppDataPath(protocol.PathIDZero)
	if h.qlogger != nil && appData.ptoCount != 0 {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
	}
	appData.ptoCount = 0
	appData.numProbesToSend = 0
	appData.ptoMode = SendNone
	h.setLossDetectionTimer(now)
}

func (h *sentPacketHandler) ReceivedBytes(n protocol.ByteCount, t monotime.Time) {
	h.connStats.BytesReceived.Add(uint64(n))
	wasAmplificationLimit := h.isAmplificationLimited()
	h.bytesReceived += n
	if wasAmplificationLimit && !h.isAmplificationLimited() {
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) ReceivedPacket(l protocol.EncryptionLevel, t monotime.Time) {
	h.connStats.PacketsReceived.Add(1)
	if h.perspective == protocol.PerspectiveServer && l == protocol.EncryptionHandshake && !h.peerAddressValidated {
		h.peerAddressValidated = true
		h.setLossDetectionTimer(t)
	}
}

func (h *sentPacketHandler) ReceivedPacketForPath(pid protocol.PathID, size protocol.ByteCount, t monotime.Time) {
	h.ReceivedPacket(protocol.Encryption1RTT, t)
	if path := h.getAppDataPath(pid); path != nil {
		path.bytesReceived += uint64(size)
	}
}
func (h *sentPacketHandler) SentPacket(
	t monotime.Time,
	pn, largestAcked protocol.PacketNumber,
	streamFrames []StreamFrame,
	frames []Frame,
	encLevel protocol.EncryptionLevel,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isPathMTUProbePacket bool,
	isPathProbePacket bool,
) {
	h.sentPacket(t, pn, largestAcked, protocol.PathIDZero, streamFrames, frames, encLevel, ecn, size, isPathMTUProbePacket, isPathProbePacket)
}

func (h *sentPacketHandler) SentPacketOneStream(
	t monotime.Time,
	pn, largestAcked protocol.PacketNumber,
	streamFrame StreamFrame,
	frames []Frame,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isPathMTUProbePacket bool,
) {
	h.bytesSent += size
	h.connStats.BytesSent.Add(uint64(size))
	h.connStats.PacketsSent.Add(1)

	pnSpace := h.getAppDataPath(protocol.PathIDZero).space
	pnSpace.largestSent = pn
	if h.minPNToRelaxReordering == protocol.InvalidPacketNumber {
		h.minPNToRelaxReordering = pn
	}

	p := getPacket()
	p.SendTime = t
	p.EncryptionLevel = protocol.Encryption1RTT
	p.Length = size
	p.Frames = frames
	p.LargestAcked = largestAcked
	p.StreamFrame = streamFrame
	p.HasStreamFrame = true
	p.IsPathMTUProbePacket = isPathMTUProbePacket

	isAckEliciting := p.IsAckEliciting()
	pathData := h.getAppDataPath(protocol.PathIDZero)
	pathData.bytesSent += uint64(size)
	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = t
		pathData.bytesInFlight += size
		p.includedInBytesInFlight = true
		if pathData.numProbesToSend > 0 {
			pathData.numProbesToSend--
		}
	}
	pathData.congestion.OnPacketSent(t, h.totalBytesInFlight(), pn, size, isAckEliciting)
	if pathData.ecnTracker != nil {
		pathData.ecnTracker.SentPacket(pn, ecn)
	}
	if p.Outstanding() {
		pnSpace.numOutstanding++
	}
	h.hist.SentPacket(pn, p)
	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
	h.setLossDetectionTimer(t)
}

// SentPacketForPath records a 1-RTT packet sent on the application-data path
// pid. It is the multipath counterpart of SentPacket: the packet number, the
// bytes-in-flight, and the per-path send bookkeeping land on pid's own
// appDataPath (its independent number space + congestion controller), never on
// PathIDZero's. For PathIDZero it is byte-identical to SentPacket with
// Encryption1RTT.
func (h *sentPacketHandler) SentPacketForPath(
	t monotime.Time,
	pn, largestAcked protocol.PacketNumber,
	pid protocol.PathID,
	streamFrames []StreamFrame,
	frames []Frame,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isPathMTUProbePacket bool,
) {
	h.sentPacket(t, pn, largestAcked, pid, streamFrames, frames, protocol.Encryption1RTT, ecn, size, isPathMTUProbePacket, false)
}

func (h *sentPacketHandler) sentPacket(
	t monotime.Time,
	pn, largestAcked protocol.PacketNumber,
	pid protocol.PathID,
	streamFrames []StreamFrame,
	frames []Frame,
	encLevel protocol.EncryptionLevel,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isPathMTUProbePacket bool,
	isPathProbePacket bool,
) {
	h.bytesSent += size
	h.connStats.BytesSent.Add(uint64(size))
	h.connStats.PacketsSent.Add(1)

	// pnSpace is the number space the packet was drawn from. For 1-RTT it is the
	// target path's own space; Initial/Handshake/0-RTT are never path-scoped, so
	// pid is PathIDZero there and this resolves to the same space as before.
	pnSpace := h.getPacketNumberSpaceForPath(encLevel, pid)
	hist := h.historyFor(encLevel, pid)
	pnSpace.largestSent = pn
	if encLevel.PacketNumberSpace() == protocol.PacketNumberSpaceAppData &&
		pid == protocol.PathIDZero &&
		h.minPNToRelaxReordering == protocol.InvalidPacketNumber {
		h.minPNToRelaxReordering = pn
	}
	//nolint:exhaustive // Only Initial and Handshake packet numbers are stored separately.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.handshakePNs.Initial = append(h.handshakePNs.Initial, pn)
	case protocol.EncryptionHandshake:
		h.handshakePNs.Handshake = append(h.handshakePNs.Handshake, pn)
	}

	p := getPacket()
	p.SendTime = t
	p.EncryptionLevel = encLevel
	p.Length = size
	p.Frames = frames
	p.LargestAcked = largestAcked
	p.StreamFrames = streamFrames
	p.IsPathMTUProbePacket = isPathMTUProbePacket
	p.isPathProbePacket = isPathProbePacket
	p.pathID = pid
	isAckEliciting := p.IsAckEliciting()

	if isPathProbePacket {
		hist.SentPathProbePacket(pn, p)
		h.setLossDetectionTimer(t)
		return
	}
	// The PathIDZero appData path drives the connection-level PTO/probe
	// bookkeeping (Initial/Handshake share it); a non-zero path tracks its own
	// bytes-in-flight against its own controller.
	pathData := h.getAppDataPath(pid)
	appData := h.getAppDataPath(protocol.PathIDZero)
	if encLevel == protocol.Encryption1RTT || encLevel == protocol.Encryption0RTT {
		pathData.bytesSent += uint64(size)
	}
	if isAckEliciting {
		pnSpace.lastAckElicitingPacketTime = t
		if encLevel == protocol.Encryption1RTT {
			pathData.bytesInFlight += size
		} else {
			*h.bytesInFlightFor(encLevel) += size
		}
		p.includedInBytesInFlight = true
		if appData.numProbesToSend > 0 {
			appData.numProbesToSend--
		}
	}
	pathData.congestion.OnPacketSent(t, h.totalBytesInFlight(), pn, size, isAckEliciting)

	if encLevel == protocol.Encryption1RTT && pathData.ecnTracker != nil {
		pathData.ecnTracker.SentPacket(pn, ecn)
	}

	if p.Outstanding() {
		pnSpace.numOutstanding++
	}
	hist.SentPacket(pn, p)
	if !isAckEliciting {
		if !h.peerCompletedAddressValidation {
			h.setLossDetectionTimer(t)
		}
		return
	}
	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}
	h.setLossDetectionTimer(t)
}

func (h *sentPacketHandler) qlogMetricsUpdated() {
	var metricsUpdatedEvent qlog.MetricsUpdated
	var updated bool
	if h.rttStats.HasMeasurement() {
		if h.lastMetrics.MinRTT != h.rttStats.MinRTT() {
			metricsUpdatedEvent.MinRTT = h.rttStats.MinRTT()
			h.lastMetrics.MinRTT = metricsUpdatedEvent.MinRTT
			updated = true
		}
		if h.lastMetrics.SmoothedRTT != h.rttStats.SmoothedRTT() {
			metricsUpdatedEvent.SmoothedRTT = h.rttStats.SmoothedRTT()
			h.lastMetrics.SmoothedRTT = metricsUpdatedEvent.SmoothedRTT
			updated = true
		}
		if h.lastMetrics.LatestRTT != h.rttStats.LatestRTT() {
			metricsUpdatedEvent.LatestRTT = h.rttStats.LatestRTT()
			h.lastMetrics.LatestRTT = metricsUpdatedEvent.LatestRTT
			updated = true
		}
		if h.lastMetrics.RTTVariance != h.rttStats.MeanDeviation() {
			metricsUpdatedEvent.RTTVariance = h.rttStats.MeanDeviation()
			h.lastMetrics.RTTVariance = metricsUpdatedEvent.RTTVariance
			updated = true
		}
	}
	if cwnd := h.congestion.GetCongestionWindow(); h.lastMetrics.CongestionWindow != int(cwnd) {
		metricsUpdatedEvent.CongestionWindow = int(cwnd)
		h.lastMetrics.CongestionWindow = metricsUpdatedEvent.CongestionWindow
		updated = true
	}
	bytesInFlight := h.totalBytesInFlight()
	if h.lastMetrics.BytesInFlight != int(bytesInFlight) {
		metricsUpdatedEvent.BytesInFlight = int(bytesInFlight)
		h.lastMetrics.BytesInFlight = metricsUpdatedEvent.BytesInFlight
		updated = true
	}
	packetsInFlight := h.hist.NumOutstanding()
	if h.lastMetrics.PacketsInFlight != packetsInFlight {
		metricsUpdatedEvent.PacketsInFlight = packetsInFlight
		h.lastMetrics.PacketsInFlight = metricsUpdatedEvent.PacketsInFlight
		updated = true
	}
	if updated {
		h.qlogger.RecordEvent(metricsUpdatedEvent)
	}
}

// getAppDataPath returns the per-path application-data state for pid. The map
// always contains the PathIDZero entry; an unknown pid returns nil so callers
// can reject ACKs for paths that have not been opened (Stage 4 spec risk #1).
func (h *sentPacketHandler) getAppDataPath(pid protocol.PathID) *appDataPath {
	return h.appDataPaths[pid]
}

// PathDebugStats reports the live application-data recovery state of path pid.
// See the interface doc: it is test-support state used by the multipath e2e
// test to prove a non-zero path genuinely carried packets in its own number
// space and has its own (distinct) congestion controller + RTT estimator.
func (h *sentPacketHandler) PathDebugStats(pid protocol.PathID) (PathDebugStats, bool) {
	path := h.getAppDataPath(pid)
	if path == nil {
		return PathDebugStats{}, false
	}
	stats := PathDebugStats{
		LargestSent:      path.space.largestSent,
		LargestAcked:     path.space.largestAcked,
		BytesInFlight:    path.bytesInFlight,
		BytesSent:        path.bytesSent,
		BytesReceived:    path.bytesReceived,
		CongestionWindow: path.congestion.GetCongestionWindow(),
		LostPackets:      path.lostPacketCount,
		LostBytes:        path.lostByteCount,
		SmoothedRTT:      path.rttStats.SmoothedRTT(),
		HasRTT:           path.rttStats.HasMeasurement(),
	}
	if pid != protocol.PathIDZero {
		path0 := h.getAppDataPath(protocol.PathIDZero)
		stats.DistinctController = path.congestion != path0.congestion &&
			path.congestion != h.congestion &&
			path.rttStats != path0.rttStats &&
			path.rttStats != h.rttStats
	}
	return stats, true
}

func (h *sentPacketHandler) getPacketNumberSpace(space protocol.PacketNumberSpace) *packetNumberSpace {
	switch space {
	case protocol.PacketNumberSpaceInitial:
		return h.initialPackets
	case protocol.PacketNumberSpaceHandshake:
		return h.handshakePackets
	case protocol.PacketNumberSpaceAppData:
		return h.getAppDataPath(protocol.PathIDZero).space
	default:
		panic("invalid packet number space")
	}
}

// getPacketNumberSpaceForPath is getPacketNumberSpace, but for application data
// it returns the space of path pid (its independent number sequence). For
// Initial/Handshake pid is irrelevant; for PathIDZero it is identical to
// getPacketNumberSpace.
func (h *sentPacketHandler) getPacketNumberSpaceForPath(encLevel protocol.EncryptionLevel, pid protocol.PathID) *packetNumberSpace {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets
	case protocol.EncryptionHandshake:
		return h.handshakePackets
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.getAppDataPath(pid).space
	default:
		panic("invalid packet number space")
	}
}

// ReceivedAck processes an ACK frame for the given encryption level. For
// application data (0-RTT/1-RTT) it delegates to ReceivedAckForPath with
// PathIDZero, so single-path behavior is bit-identical to the per-path form.
func (h *sentPacketHandler) ReceivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* contained 1-RTT packet */, error) {
	if encLevel == protocol.Encryption0RTT || encLevel == protocol.Encryption1RTT {
		return h.ReceivedAckForPath(ack, protocol.PathIDZero, rcvTime)
	}
	return h.receivedAck(ack, encLevel, protocol.PathIDZero, rcvTime)
}

// ReceivedAckForPath processes a (possibly multipath) ACK that acknowledges
// packets sent on the application-data packet number space identified by pid.
//
// An unknown pid (no entry in appDataPaths) is a protocol violation: the peer
// cannot acknowledge a path we never opened. We MUST NOT fall back to
// PathIDZero, because path pid carries an independent packet-number sequence —
// matching it against path 0's history would corrupt loss detection and ACK
// attribution (Stage 4 spec risk #1; QNG-MULTIPATH-PLAN.md:94-96). Until a
// second path is opened on the send side (Stage 5), the map only ever contains
// PathIDZero, so any non-zero pid is rejected here.
func (h *sentPacketHandler) ReceivedAckForPath(ack *wire.AckFrame, pid protocol.PathID, rcvTime monotime.Time) (bool /* contained 1-RTT packet */, error) {
	if h.getAppDataPath(pid) == nil {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: fmt.Sprintf("received ACK for unknown path %d", pid),
		}
	}
	return h.receivedAck(ack, protocol.Encryption1RTT, pid, rcvTime)
}

// receivedAck processes an ACK against the packet-number space identified by
// (encLevel, pid). For Initial/Handshake pid is ignored (those spaces are not
// path-scoped). For 1-RTT pid selects the path: its own space, congestion
// controller, RTT estimator, ECN tracker, and spurious-loss history. For
// PathIDZero every per-path object aliases the connection-level object, so this
// is byte-identical to the former single-path code.
func (h *sentPacketHandler) receivedAck(ack *wire.AckFrame, encLevel protocol.EncryptionLevel, pid protocol.PathID, rcvTime monotime.Time) (bool /* contained 1-RTT packet */, error) {
	// path is the per-path recovery state the ACK applies to. For
	// Initial/Handshake the space is handler-level but RTT/congestion are still
	// the PathIDZero (connection) objects, exactly as before.
	ackPath := h.getAppDataPath(pid)
	pnSpace := h.getPacketNumberSpaceForPath(encLevel, pid)

	largestAcked := ack.LargestAcked()
	if largestAcked > pnSpace.largestSent {
		return false, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received ACK for an unsent packet",
		}
	}

	// Servers complete address validation when a protected packet is received.
	if h.perspective == protocol.PerspectiveClient && !h.peerCompletedAddressValidation &&
		(encLevel == protocol.EncryptionHandshake || encLevel == protocol.Encryption1RTT) {
		h.peerCompletedAddressValidation = true
		h.logger.Debugf("Peer doesn't await address validation any longer.")
		// Make sure that the timer is reset, even if this ACK doesn't acknowledge any (ack-eliciting) packets.
		h.setLossDetectionTimer(rcvTime)
	}

	// ackRTT / ackCongestion are the recovery objects the ACK feeds. For 1-RTT
	// they are the target path's own estimator and controller (for PathIDZero
	// these alias the connection's). Initial/Handshake ACKs always use the
	// connection-level objects.
	ackRTT := h.rttStats
	ackCongestion := h.congestion
	if encLevel == protocol.Encryption1RTT {
		ackRTT = ackPath.rttStats
		ackCongestion = ackPath.congestion
	}

	// priorInFlight is the total bytes in flight across all spaces; each path's
	// controller operates on this total (for PathIDZero, the single controller).
	priorInFlight := h.totalBytesInFlight()
	ackedPackets, hasAckEliciting, err := h.detectAndRemoveAckedPackets(ack, encLevel, pid)
	if err != nil {
		return false, err
	}
	// update the RTT, if:
	// * the largest acked is newly acknowledged, AND
	// * at least one new ack-eliciting packet was acknowledged
	if len(ackedPackets) > 0 {
		if p := ackedPackets[len(ackedPackets)-1]; p.PacketNumber == ack.LargestAcked() && !p.isPathProbePacket && hasAckEliciting {
			// don't use the ack delay for Initial and Handshake packets
			var ackDelay time.Duration
			if encLevel == protocol.Encryption1RTT {
				ackDelay = min(ack.DelayTime, ackRTT.MaxAckDelay())
			}
			// largestAckedTime is the send time of the largest acknowledged
			// packet, tracked per path. For PathIDZero this is the same shared
			// field as before.
			if ackPath.largestAckedTime.IsZero() || !p.SendTime.Before(ackPath.largestAckedTime) {
				ackRTT.UpdateRTT(rcvTime.Sub(p.SendTime), ackDelay)
				if h.logger.Debug() {
					h.logger.Debugf("\tupdated RTT: %s (σ: %s)", ackRTT.SmoothedRTT(), ackRTT.MeanDeviation())
				}
				ackPath.largestAckedTime = p.SendTime
			}
			ackCongestion.MaybeExitSlowStart()
		}
	}

	// Detect spurious losses even if no outstanding packets were newly acknowledged.
	var spuriousLosses []protocol.PacketNumber
	var timeThresholdIncreased bool
	if encLevel == protocol.Encryption1RTT {
		spuriousLosses, timeThresholdIncreased = h.detectSpuriousLosses(
			ack,
			pid,
			rcvTime.Add(-min(ack.DelayTime, ackRTT.MaxAckDelay())),
		)
		// clean up lost packet history
		ackPath.lostPackets.DeleteBefore(rcvTime.Add(-3 * ackRTT.PTO(false)))
	}
	if len(ackedPackets) > 0 {
		// Only inform the ECN tracker about new 1-RTT ACKs if the ACK increases the largest acked.
		if encLevel == protocol.Encryption1RTT && ackPath.ecnTracker != nil && largestAcked > pnSpace.largestAcked {
			congested := ackPath.ecnTracker.HandleNewlyAcked(ackedPackets, int64(ack.ECT0), int64(ack.ECT1), int64(ack.ECNCE))
			if congested {
				ackCongestion.OnCongestionEvent(largestAcked, 0, priorInFlight)
			}
		}

		pnSpace.largestAcked = max(pnSpace.largestAcked, largestAcked)
	}
	// new acked packets can advance largestAcked or update the RTT,
	// and a larger time threshold moves the loss deadline
	if len(ackedPackets) > 0 || timeThresholdIncreased {
		h.detectLostPackets(rcvTime, encLevel, pid)
		if encLevel == protocol.Encryption1RTT {
			h.detectLostPathProbes(rcvTime)
		}
	}
	// report spurious losses after any new congestion events from this ACK
	for _, pn := range spuriousLosses {
		ackCongestion.OnSpuriousLoss(pn)
	}
	if len(ackedPackets) == 0 {
		if len(spuriousLosses) > 0 && h.qlogger != nil {
			h.qlogMetricsUpdated()
		}
		if timeThresholdIncreased {
			h.setLossDetectionTimer(rcvTime)
		}
		return false, nil
	}

	var acked1RTTPacket bool
	for _, p := range ackedPackets {
		if p.includedInBytesInFlight {
			ackCongestion.OnPacketAcked(p.PacketNumber, p.Length, priorInFlight, rcvTime)
		}
		if p.EncryptionLevel == protocol.Encryption1RTT {
			acked1RTTPacket = true
		}
		h.removeFromBytesInFlight(p.packet)
		if !p.isPathProbePacket {
			putPacket(p.packet)
		}
	}

	// After this point, we must not use ackedPackets any longer!
	// We've already returned the buffers.
	ackedPackets = nil    //nolint:ineffassign // This is just to be on the safe side.
	clear(h.ackedPackets) // make sure the memory is released
	h.ackedPackets = h.ackedPackets[:0]

	// Reset the pto_count unless the client is unsure if the server has validated the client's address.
	appData := h.getAppDataPath(protocol.PathIDZero)
	if h.peerCompletedAddressValidation {
		if h.qlogger != nil && appData.ptoCount != 0 {
			h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		}
		appData.ptoCount = 0
	}
	appData.numProbesToSend = 0

	if h.qlogger != nil {
		h.qlogMetricsUpdated()
	}

	h.setLossDetectionTimer(rcvTime)
	return acked1RTTPacket, nil
}

func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, pid protocol.PathID, ackTime monotime.Time) (_ []protocol.PacketNumber, timeThresholdIncreased bool) {
	appData := h.getAppDataPath(pid)
	var maxPacketReordering protocol.PacketNumber
	var maxTimeReordering time.Duration
	var packetThresholdChanged bool
	ackRangeIdx := len(ack.AckRanges) - 1
	var spuriousLosses []protocol.PacketNumber
	for pn, sendTime := range appData.lostPackets.All() {
		ackRange := ack.AckRanges[ackRangeIdx]
		for pn > ackRange.Largest && ackRangeIdx > 0 {
			ackRangeIdx--
			ackRange = ack.AckRanges[ackRangeIdx]
		}
		if pn < ackRange.Smallest {
			continue
		}
		if pn <= ackRange.Largest {
			if !h.packetThresholdDisabled {
				h.packetThresholdDisabled = true
				packetThresholdChanged = true
			}
			packetReordering := appData.hist.Difference(ack.LargestAcked(), pn)
			timeReordering := ackTime.Sub(sendTime)
			maxPacketReordering = max(maxPacketReordering, packetReordering)
			if h.minPNToRelaxReordering != protocol.InvalidPacketNumber && pn >= h.minPNToRelaxReordering {
				maxTimeReordering = max(maxTimeReordering, timeReordering)
			}

			if h.qlogger != nil {
				h.qlogger.RecordEvent(qlog.SpuriousLoss{
					EncryptionLevel:  protocol.Encryption1RTT,
					PacketNumber:     pn,
					PacketReordering: uint64(packetReordering),
					TimeReordering:   timeReordering,
				})
			}
			if h.connStats != nil {
				h.connStats.SpuriousLosses.Add(1)
			}
			spuriousLosses = append(spuriousLosses, pn)
		}
	}
	for _, pn := range spuriousLosses {
		appData.lostPackets.Delete(pn)
	}
	lossDelay := max(
		max(appData.rttStats.LatestRTT(), appData.rttStats.SmoothedRTT())*time.Duration(8+h.timeThresholdEighths)/8,
		protocol.TimerGranularity,
	)
	if maxTimeReordering > lossDelay && h.timeThresholdEighths < maxTimeThresholdEighths {
		h.timeThresholdEighths = min(2*h.timeThresholdEighths, maxTimeThresholdEighths)
		h.minPNToRelaxReordering = protocol.InvalidPacketNumber
		timeThresholdIncreased = true
	}
	if packetThresholdChanged || timeThresholdIncreased {
		h.qlogRecoveryParametersSet(false)
	}
	return spuriousLosses, timeThresholdIncreased
}

// Packets are returned in ascending packet number order.
func (h *sentPacketHandler) detectAndRemoveAckedPackets(
	ack *wire.AckFrame,
	encLevel protocol.EncryptionLevel,
	pid protocol.PathID,
) (_ []packetWithPacketNumber, hasAckEliciting bool, _ error) {
	if len(h.ackedPackets) > 0 {
		return nil, false, errors.New("ackhandler BUG: ackedPackets slice not empty")
	}

	hist := h.historyFor(encLevel, pid)
	if encLevel == protocol.Encryption1RTT {
		for p := range hist.SkippedPackets() {
			if ack.AcksPacket(p) {
				return nil, false, &qerr.TransportError{
					ErrorCode:    qerr.ProtocolViolation,
					ErrorMessage: fmt.Sprintf("received an ACK for skipped packet number: %d (%s)", p, encLevel),
				}
			}
		}
	}

	var ackRangeIndex int
	lowestAcked := ack.LowestAcked()
	largestAcked := ack.LargestAcked()
	for pn, p := range hist.Packets() {
		// ignore packets below the lowest acked
		if pn < lowestAcked {
			continue
		}
		if pn > largestAcked {
			break
		}
		if p.EncryptionLevel.PacketNumberSpace() != encLevel.PacketNumberSpace() {
			continue
		}

		if ack.HasMissingRanges() {
			ackRange := ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]

			for pn > ackRange.Largest && ackRangeIndex < len(ack.AckRanges)-1 {
				ackRangeIndex++
				ackRange = ack.AckRanges[len(ack.AckRanges)-1-ackRangeIndex]
			}

			if pn < ackRange.Smallest { // packet not contained in ACK range
				continue
			}
			if pn > ackRange.Largest {
				return nil, false, fmt.Errorf("BUG: ackhandler would have acked wrong packet %d, while evaluating range %d -> %d", pn, ackRange.Smallest, ackRange.Largest)
			}
		}
		if p.isPathProbePacket {
			probePacket := hist.RemovePathProbe(pn)
			// the probe packet might already have been declared lost
			if probePacket != nil {
				h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: probePacket})
			}
			continue
		}
		if p.IsAckEliciting() {
			hasAckEliciting = true
		}
		h.ackedPackets = append(h.ackedPackets, packetWithPacketNumber{PacketNumber: pn, packet: p})
	}
	if h.logger.Debug() && len(h.ackedPackets) > 0 {
		pns := make([]protocol.PacketNumber, len(h.ackedPackets))
		for i, p := range h.ackedPackets {
			pns[i] = p.PacketNumber
		}
		h.logger.Debugf("\tnewly acked packets (%d): %d", len(pns), pns)
	}

	for _, p := range h.ackedPackets {
		if p.LargestAcked != protocol.InvalidPacketNumber && encLevel == protocol.Encryption1RTT && h.ignorePacketsBelow != nil {
			h.ignorePacketsBelow(p.LargestAcked + 1)
		}

		for _, f := range p.Frames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		if p.HasStreamFrame && p.StreamFrame.Handler != nil {
			p.StreamFrame.Handler.OnAcked(p.StreamFrame.Frame)
		}
		for _, f := range p.StreamFrames {
			if f.Handler != nil {
				f.Handler.OnAcked(f.Frame)
			}
		}
		if err := hist.Remove(p.PacketNumber); err != nil {
			return nil, false, err
		}
	}
	// TODO: add support for the transport:packets_acked qlog event
	return h.ackedPackets, hasAckEliciting, nil
}

func (h *sentPacketHandler) getLossTimeAndSpace() (monotime.Time, protocol.EncryptionLevel, protocol.PathID) {
	var encLevel protocol.EncryptionLevel
	var pid protocol.PathID
	var lossTime monotime.Time

	if h.initialPackets != nil {
		lossTime = h.initialPackets.lossTime
		encLevel = protocol.EncryptionInitial
	}
	if h.handshakePackets != nil && (lossTime.IsZero() || (!h.handshakePackets.lossTime.IsZero() && h.handshakePackets.lossTime.Before(lossTime))) {
		lossTime = h.handshakePackets.lossTime
		encLevel = protocol.EncryptionHandshake
	}
	// Fan out over the application-data paths, recording which path owns the
	// earliest loss time. With one path (PathIDZero) this is the same comparison
	// against the single appData lossTime as before, and pid stays PathIDZero.
	for _, r := range h.pathList {
		if lossTime.IsZero() || (!r.p.space.lossTime.IsZero() && r.p.space.lossTime.Before(lossTime)) {
			lossTime = r.p.space.lossTime
			encLevel = protocol.Encryption1RTT
			pid = r.id
		}
	}
	return lossTime, encLevel, pid
}

func (h *sentPacketHandler) getScaledPTO(includeMaxAckDelay bool) time.Duration {
	// The PTO count lives on the PathIDZero appData path; during the handshake
	// the Initial/Handshake spaces share it (paths.rs:154-157), so for a single
	// path this is identical to the former handler-level ptoCount.
	pto := h.rttStats.PTO(includeMaxAckDelay) << h.getAppDataPath(protocol.PathIDZero).ptoCount
	if pto > maxPTODuration || pto <= 0 {
		return maxPTODuration
	}
	return pto
}

// same logic as getLossTimeAndSpace, but for lastAckElicitingPacketTime instead of lossTime.
// For Encryption1RTT the returned pid is the application-data path whose
// deadline expires first; for all other levels it is PathIDZero.
func (h *sentPacketHandler) getPTOTimeAndSpace(now monotime.Time) (pto monotime.Time, encLevel protocol.EncryptionLevel, pid protocol.PathID) {
	// We only send application data probe packets once the handshake is confirmed,
	// because before that, we don't have the keys to decrypt ACKs sent in 1-RTT packets.
	if !h.handshakeConfirmed && !h.hasOutstandingCryptoPackets() {
		if h.peerCompletedAddressValidation {
			return
		}
		t := now.Add(h.getScaledPTO(false))
		if h.initialPackets != nil {
			return t, protocol.EncryptionInitial, protocol.PathIDZero
		}
		return t, protocol.EncryptionHandshake, protocol.PathIDZero
	}

	if h.initialPackets != nil && h.initialPackets.numOutstanding > 0 &&
		!h.initialPackets.lastAckElicitingPacketTime.IsZero() {
		encLevel = protocol.EncryptionInitial
		if t := h.initialPackets.lastAckElicitingPacketTime; !t.IsZero() {
			pto = t.Add(h.getScaledPTO(false))
		}
	}
	if h.handshakePackets != nil && h.handshakePackets.numOutstanding > 0 &&
		!h.handshakePackets.lastAckElicitingPacketTime.IsZero() {
		t := h.handshakePackets.lastAckElicitingPacketTime.Add(h.getScaledPTO(false))
		if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
			pto = t
			encLevel = protocol.EncryptionHandshake
		}
	}
	// Fan out over the application-data paths. With one path (PathIDZero) this
	// is the same single appData PTO computation as before.
	if h.handshakeConfirmed {
		for _, r := range h.pathList {
			p := r.p
			if p.space.numOutstanding == 0 || p.space.lastAckElicitingPacketTime.IsZero() {
				continue
			}
			t := p.space.lastAckElicitingPacketTime.Add(h.getScaledPTO(true))
			if pto.IsZero() || (!t.IsZero() && t.Before(pto)) {
				pto = t
				encLevel = protocol.Encryption1RTT
				pid = r.id
			}
		}
	}
	return pto, encLevel, pid
}

func (h *sentPacketHandler) hasOutstandingCryptoPackets() bool {
	if h.initialPackets != nil && h.initialPackets.numOutstanding > 0 {
		return true
	}
	if h.handshakePackets != nil && h.handshakePackets.numOutstanding > 0 {
		return true
	}
	return false
}

func (h *sentPacketHandler) setLossDetectionTimer(now monotime.Time) {
	oldAlarm := h.alarm // only needed in case tracing is enabled
	newAlarm := h.lossDetectionTime(now)
	h.alarm = newAlarm

	hasAlarm := !newAlarm.Time.IsZero()
	if !hasAlarm && !oldAlarm.Time.IsZero() {
		h.logger.Debugf("Canceling loss detection timer.")
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}

	if h.qlogger != nil && hasAlarm && newAlarm != oldAlarm {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeSet,
			TimerType: newAlarm.TimerType,
			EncLevel:  newAlarm.EncryptionLevel,
			Time:      newAlarm.Time.ToTime(),
		})
	}
}

func (h *sentPacketHandler) hasOutstandingNonZeroPathPackets() bool {
	for _, r := range h.pathList {
		if r.id == protocol.PathIDZero {
			continue
		}
		if r.p.hist.HasOutstandingPackets() || r.p.hist.HasOutstandingPathProbes() {
			return true
		}
	}
	return false
}

func (h *sentPacketHandler) lossDetectionTime(now monotime.Time) alarmTimer {
	// cancel the alarm if no packets are outstanding
	if h.peerCompletedAddressValidation && !h.hist.HasOutstandingPackets() && !h.hist.HasOutstandingPathProbes() && !h.hasOutstandingNonZeroPathPackets() {
		return alarmTimer{}
	}

	// cancel the alarm if amplification limited
	if h.isAmplificationLimited() {
		return alarmTimer{}
	}

	var pathProbeLossTime monotime.Time
	if h.hist.HasOutstandingPathProbes() {
		if _, p := h.hist.FirstOutstandingPathProbe(); p != nil {
			pathProbeLossTime = p.SendTime.Add(pathProbePacketLossTimeout)
		}
	}

	// early retransmit timer or time loss detection
	lossTime, encLevel, _ := h.getLossTimeAndSpace()
	if !lossTime.IsZero() && (pathProbeLossTime.IsZero() || lossTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            lossTime,
			TimerType:       qlog.TimerTypeACK,
			EncryptionLevel: encLevel,
		}
	}
	ptoTime, encLevel, _ := h.getPTOTimeAndSpace(now)
	if !ptoTime.IsZero() && (pathProbeLossTime.IsZero() || ptoTime.Before(pathProbeLossTime)) {
		return alarmTimer{
			Time:            ptoTime,
			TimerType:       qlog.TimerTypePTO,
			EncryptionLevel: encLevel,
		}
	}
	if !pathProbeLossTime.IsZero() {
		return alarmTimer{
			Time:            pathProbeLossTime,
			TimerType:       qlog.TimerTypePathProbe,
			EncryptionLevel: protocol.Encryption1RTT,
		}
	}
	return alarmTimer{}
}

func (h *sentPacketHandler) detectLostPathProbes(now monotime.Time) {
	if !h.hist.HasOutstandingPathProbes() {
		return
	}
	lossTime := now.Add(-pathProbePacketLossTimeout)
	// RemovePathProbe cannot be called while iterating.
	var lostPathProbes []packetWithPacketNumber
	for pn, p := range h.hist.PathProbes() {
		if !p.SendTime.After(lossTime) {
			lostPathProbes = append(lostPathProbes, packetWithPacketNumber{PacketNumber: pn, packet: p})
		}
	}
	for _, p := range lostPathProbes {
		for _, f := range p.Frames {
			if f.Handler != nil {
				f.Handler.OnLost(f.Frame)
			}
		}
		h.hist.RemovePathProbe(p.PacketNumber)
	}
}

func countPacketNumbers(pns []protocol.PacketNumber, lower, upper protocol.PacketNumber) protocol.PacketNumber {
	if len(pns) == 0 || pns[len(pns)-1] <= lower {
		return 0
	}
	var count protocol.PacketNumber
	for _, pn := range pns {
		if pn > lower && pn <= upper {
			count++
		}
	}
	return count
}

func (h *sentPacketHandler) detectLostPackets(now monotime.Time, encLevel protocol.EncryptionLevel, pid protocol.PathID) {
	pnSpace := h.getPacketNumberSpaceForPath(encLevel, pid)
	hist := h.historyFor(encLevel, pid)
	pnSpace.lossTime = 0
	space := encLevel.PacketNumberSpace()
	usePacketThreshold := space != protocol.PacketNumberSpaceAppData || !h.packetThresholdDisabled
	timeThresholdEighths := uint8(defaultTimeThresholdEighths)
	if space == protocol.PacketNumberSpaceAppData {
		timeThresholdEighths = h.timeThresholdEighths
	}

	// lossPath supplies the recovery objects (RTT, congestion, lost-packet
	// history, ECN tracker) for application-data loss detection. For
	// Initial/Handshake these all come from the connection (PathIDZero). For
	// PathIDZero they alias the connection objects, so this is byte-identical.
	lossPath := h.getAppDataPath(pid)
	lossRTT := h.rttStats
	lossCongestion := h.congestion
	if encLevel == protocol.Encryption1RTT {
		lossRTT = lossPath.rttStats
		lossCongestion = lossPath.congestion
	}

	lossDelay := max(
		max(lossRTT.LatestRTT(), lossRTT.SmoothedRTT())*time.Duration(8+timeThresholdEighths)/8,
		protocol.TimerGranularity,
	)

	// Packets sent before this time are deemed lost.
	lostSendTime := now.Add(-lossDelay)

	// priorInFlight is the total across all spaces; each path's controller
	// operates on the total (for PathIDZero, the single controller).
	priorInFlight := h.totalBytesInFlight()
	for pn, p := range hist.Packets() {
		if pn > pnSpace.largestAcked {
			break
		}
		if p.EncryptionLevel.PacketNumberSpace() != space {
			continue
		}

		var distance protocol.PacketNumber
		switch space {
		case protocol.PacketNumberSpaceInitial:
			distance = countPacketNumbers(h.handshakePNs.Initial, pn, pnSpace.largestAcked)
		case protocol.PacketNumberSpaceHandshake:
			distance = countPacketNumbers(h.handshakePNs.Handshake, pn, pnSpace.largestAcked)
		case protocol.PacketNumberSpaceAppData:
			distance = hist.Difference(pnSpace.largestAcked, pn)
			if pid == protocol.PathIDZero && h.handshakePNs != nil {
				distance -= countPacketNumbers(h.handshakePNs.Initial, pn, pnSpace.largestAcked)
				distance -= countPacketNumbers(h.handshakePNs.Handshake, pn, pnSpace.largestAcked)
			}
		}
		var packetLost bool
		if !p.SendTime.After(lostSendTime) {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (time threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossTimeThreshold,
					})
				}
			}
		} else if usePacketThreshold && distance >= packetThreshold {
			packetLost = true
			if !p.isPathProbePacket && p.IsAckEliciting() {
				if h.logger.Debug() {
					h.logger.Debugf("\tlost packet %d (reordering threshold)", pn)
				}
				if h.qlogger != nil {
					h.qlogger.RecordEvent(qlog.PacketLost{
						Header: qlog.PacketHeader{
							PacketType:   qlog.EncryptionLevelToPacketType(p.EncryptionLevel),
							PacketNumber: pn,
						},
						Trigger: qlog.PacketLossReorderingThreshold,
					})
				}
			}
		} else if pnSpace.lossTime.IsZero() {
			// Note: This conditional is only entered once per call
			lossTime := p.SendTime.Add(lossDelay)
			if h.logger.Debug() {
				h.logger.Debugf("\tsetting loss timer for packet %d (%s) to %s (in %s)", pn, encLevel, lossDelay, lossTime)
			}
			pnSpace.lossTime = lossTime
		}
		if packetLost {
			if p.Outstanding() && space == protocol.PacketNumberSpaceAppData {
				lossPath.lostPackets.Add(pn, p.SendTime)
			}
			hist.DeclareLost(pn)
			if !p.isPathProbePacket && p.IsAckEliciting() {
				// the bytes in flight need to be reduced no matter if the frames in this packet will be retransmitted
				h.removeFromBytesInFlight(p)
				h.queueFramesForRetransmission(p)
				if !p.IsPathMTUProbePacket {
					if encLevel == protocol.Encryption1RTT {
						lossPath.lostPacketCount++
						lossPath.lostByteCount += uint64(p.Length)
					}
					lossCongestion.OnCongestionEvent(pn, p.Length, priorInFlight)
				}
				if encLevel == protocol.Encryption1RTT && lossPath.ecnTracker != nil {
					lossPath.ecnTracker.LostPacket(pn)
				}
			}
		}
	}
	if h.handshakeConfirmed && h.handshakePNs != nil {
		firstPN := h.hist.FirstPacketNumber()
		highestPN := h.handshakePNs.Highest()
		if firstPN == protocol.InvalidPacketNumber || highestPN == protocol.InvalidPacketNumber || firstPN > highestPN {
			h.handshakePNs = nil
		}
	}
}

// countPTO records one fired PTO alarm. Every branch of OnLossDetectionTimeout
// that treats the alarm as a probe timeout calls it, so ConnectionStats.PTOs
// counts the address-validation and nonzero-path probes too, not just the
// ordinary 1-RTT one.
func (h *sentPacketHandler) countPTO() {
	if h.connStats != nil {
		h.connStats.PTOs.Add(1)
	}
}

func (h *sentPacketHandler) OnLossDetectionTimeout(now monotime.Time) error {
	defer h.setLossDetectionTimer(now)

	if h.handshakeConfirmed {
		h.detectLostPathProbes(now)
	}

	earliestLossTime, encLevel, lossPathID := h.getLossTimeAndSpace()
	if !earliestLossTime.IsZero() {
		if h.logger.Debug() {
			h.logger.Debugf("Loss detection alarm fired in loss timer mode. Loss time: %s", earliestLossTime)
		}
		if h.qlogger != nil {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type:      qlog.LossTimerUpdateTypeExpired,
				TimerType: qlog.TimerTypeACK,
				EncLevel:  encLevel,
			})
		}
		// Early retransmit or time loss detection
		h.detectLostPackets(now, encLevel, lossPathID)
		return nil
	}

	// PTO
	// When all outstanding are acknowledged, the alarm is canceled in setLossDetectionTimer.
	// However, there's no way to reset the timer in the connection.
	// When OnLossDetectionTimeout is called, we therefore need to make sure that there are
	// actually packets outstanding.
	// The PTO send-state (count/mode/probes) lives on the PathIDZero appData
	// path; during the handshake the Initial/Handshake spaces share it
	// (paths.rs:154-157), so this is identical to the former handler-level
	// state for a single path.
	appData := h.getAppDataPath(protocol.PathIDZero)
	if h.totalBytesInFlight() == 0 && !h.peerCompletedAddressValidation {
		appData.ptoCount++
		h.countPTO()
		appData.numProbesToSend++
		if h.initialPackets != nil {
			appData.ptoMode = SendPTOInitial
		} else if h.handshakePackets != nil {
			appData.ptoMode = SendPTOHandshake
		} else {
			return errors.New("sentPacketHandler BUG: PTO fired, but bytes_in_flight is 0 and Initial and Handshake already dropped")
		}
		return nil
	}

	ptoTime, encLevel, ptoPathID := h.getPTOTimeAndSpace(now)
	if ptoTime.IsZero() {
		return nil
	}
	if encLevel == protocol.Encryption1RTT && ptoPathID != protocol.PathIDZero {
		// PTO probes are only ever sent on path 0, so a probe can never
		// refresh this path's lastAckElicitingPacketTime: once its PTO
		// deadline has expired, re-arming the timer would fire it again
		// immediately, forever. The path has gone a full PTO backoff without
		// an acknowledgment; declare its outstanding packets lost so their
		// frames retransmit on path 0 and the path stops arming the timer.
		h.countPTO()
		h.declareAppDataPathLost(ptoPathID)
		h.setLossDetectionTimer(now)
		return nil
	}
	ps := h.getPacketNumberSpace(encLevel.PacketNumberSpace())
	if ps.numOutstanding == 0 && (encLevel != protocol.Encryption1RTT || !h.hist.HasOutstandingPathProbes()) && !h.peerCompletedAddressValidation {
		return nil
	}
	appData.ptoCount++
	h.countPTO()
	if h.logger.Debug() {
		h.logger.Debugf("Loss detection alarm for %s fired in PTO mode. PTO count: %d", encLevel, appData.ptoCount)
	}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.LossTimerUpdated{
			Type:      qlog.LossTimerUpdateTypeExpired,
			TimerType: qlog.TimerTypePTO,
			EncLevel:  encLevel,
		})
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: appData.ptoCount})
	}
	appData.numProbesToSend += 2
	//nolint:exhaustive // We never arm a PTO timer for 0-RTT packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		appData.ptoMode = SendPTOInitial
	case protocol.EncryptionHandshake:
		appData.ptoMode = SendPTOHandshake
	case protocol.Encryption1RTT:
		// skip a packet number in order to elicit an immediate ACK
		pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		h.hist.SkippedPacket(pn)
		appData.ptoMode = SendPTOAppData
	default:
		return fmt.Errorf("PTO timer in unexpected encryption level: %s", encLevel)
	}
	return nil
}

func (h *sentPacketHandler) GetLossDetectionTimeout() monotime.Time {
	return h.alarm.Time
}

// PTOCount reports the consecutive PTOs on the application-data path since the
// last acknowledgment.
func (h *sentPacketHandler) PTOCount() uint32 {
	return h.getAppDataPath(protocol.PathIDZero).ptoCount
}

func (h *sentPacketHandler) ECNMode(isShortHeaderPacket bool) protocol.ECN {
	if !h.enableECN {
		return protocol.ECNUnsupported
	}
	if !isShortHeaderPacket {
		return protocol.ECNNon
	}
	return h.getAppDataPath(protocol.PathIDZero).ecnTracker.Mode()
}

func (h *sentPacketHandler) PeekPacketNumber(space protocol.PacketNumberSpace) (protocol.PacketNumber, protocol.PacketNumberLen) {
	pnSpace := h.getPacketNumberSpace(space)
	pn := h.pns.Peek(space == protocol.PacketNumberSpaceAppData)
	// See section 17.1 of RFC 9000.
	return pn, protocol.PacketNumberLengthForHeader(pn, pnSpace.largestAcked)
}

func (h *sentPacketHandler) PopPacketNumber(space protocol.PacketNumberSpace) protocol.PacketNumber {
	skipped, pn := h.pns.Pop(space == protocol.PacketNumberSpaceAppData)
	if skipped {
		skippedPN := pn - 1
		h.hist.SkippedPacket(skippedPN)
		if h.logger.Debug() {
			h.logger.Debugf("Skipping packet number %d", skippedPN)
		}
	}
	return pn
}

// PeekPacketNumberForPath peeks the next application-data (1-RTT) packet number
// from the packet-number space of path pid, which carries its own independent
// sequence (draft-multipath gives each PathID its own number space,
// QNG-MULTIPATH-PLAN.md:94-96). For PathIDZero this is byte-identical to
// PeekPacketNumber(Encryption1RTT) — it reads the same space. An unknown pid is
// a BUG: the caller must AddPath before packing for it.
func (h *sentPacketHandler) PeekPacketNumberForPath(pid protocol.PathID) (protocol.PacketNumber, protocol.PacketNumberLen) {
	path := h.getAppDataPath(pid)
	if path == nil {
		panic(fmt.Sprintf("PeekPacketNumberForPath: unknown path %d", pid))
	}
	pn := path.pns.Peek(true)
	return pn, protocol.PacketNumberLengthForHeader(pn, path.space.largestAcked)
}

// PopPacketNumberForPath pops the next application-data packet number from path
// pid's own packet-number space, recording any skipped packet in that path's
// history. For PathIDZero this is byte-identical to
// PopPacketNumber(PacketNumberSpaceAppData).
func (h *sentPacketHandler) PopPacketNumberForPath(pid protocol.PathID) protocol.PacketNumber {
	path := h.getAppDataPath(pid)
	if path == nil {
		panic(fmt.Sprintf("PopPacketNumberForPath: unknown path %d", pid))
	}
	skipped, pn := path.pns.Pop(true)
	if skipped {
		skippedPN := pn - 1
		path.hist.SkippedPacket(skippedPN)
		if h.logger.Debug() {
			h.logger.Debugf("Skipping packet number %d (path %d)", skippedPN, pid)
		}
	}
	return pn
}

func (h *sentPacketHandler) SendMode(now monotime.Time) SendMode {
	return h.SendModeForPath(now, protocol.PathIDZero)
}

// SendModeForPath is SendMode for sends targeting application-data path pid: the
// congestion-window and pacing checks consult pid's own controller (for
// PathIDZero, the connection controller, so this is byte-identical to the
// former SendMode). Amplification, tracked-packet, and PTO-probe gates stay
// connection-level: amplification and the tracked-packet cap span all spaces,
// and PTO probing is driven through the PathIDZero appData path. An unknown pid
// is a BUG (open the path first).
func (h *sentPacketHandler) SendModeForPath(now monotime.Time, pid protocol.PathID) SendMode {
	path := h.getAppDataPath(pid)
	if path == nil {
		panic(fmt.Sprintf("SendModeForPath: unknown path %d", pid))
	}

	numTrackedPackets := h.hist.Len()
	for _, r := range h.pathList {
		if r.id != protocol.PathIDZero {
			numTrackedPackets += r.p.hist.Len()
		}
	}

	if h.isAmplificationLimited() {
		h.logger.Debugf("Amplification window limited. Received %d bytes, already sent out %d bytes", h.bytesReceived, h.bytesSent)
		return SendNone
	}
	// Don't send any packets if we're keeping track of the maximum number of packets.
	// Note that since MaxOutstandingSentPackets is smaller than MaxTrackedSentPackets,
	// we will stop sending out new data when reaching MaxOutstandingSentPackets,
	// but still allow sending of retransmissions and ACKs.
	if numTrackedPackets >= protocol.MaxTrackedSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Limited by the number of tracked packets: tracking %d packets, maximum %d", numTrackedPackets, protocol.MaxTrackedSentPackets)
		}
		return SendNone
	}
	// PTO probing is connection-level: the probe send-state lives on the
	// PathIDZero appData path (Initial/Handshake share it).
	appData := h.getAppDataPath(protocol.PathIDZero)
	if appData.numProbesToSend > 0 {
		return appData.ptoMode
	}
	// Only send ACKs if we're congestion limited. The target path's controller
	// operates on the total bytes in flight.
	bytesInFlight := h.totalBytesInFlight()
	if !path.congestion.CanSend(bytesInFlight) {
		if h.logger.Debug() {
			h.logger.Debugf("Congestion limited: bytes in flight %d, window %d", bytesInFlight, path.congestion.GetCongestionWindow())
		}
		return SendAck
	}
	if numTrackedPackets >= protocol.MaxOutstandingSentPackets {
		if h.logger.Debug() {
			h.logger.Debugf("Max outstanding limited: tracking %d packets, maximum: %d", numTrackedPackets, protocol.MaxOutstandingSentPackets)
		}
		return SendAck
	}
	if !path.congestion.HasPacingBudget(now) {
		return SendPacingLimited
	}
	return SendAny
}

func (h *sentPacketHandler) TimeUntilSend() monotime.Time {
	return h.congestion.TimeUntilSend(h.totalBytesInFlight())
}

func (h *sentPacketHandler) SetMaxDatagramSize(s protocol.ByteCount) {
	h.congestion.SetMaxDatagramSize(s)
}

func (h *sentPacketHandler) isAmplificationLimited() bool {
	if h.peerAddressValidated {
		return false
	}
	return h.bytesSent >= amplificationFactor*h.bytesReceived
}

func (h *sentPacketHandler) QueueProbePacket(space protocol.PacketNumberSpace) bool {
	pn, p := h.hist.FirstOutstanding(space)
	if p == nil {
		return false
	}
	// TODO: don't declare the packet lost here.
	// Keep track of acknowledged frames instead.
	// Call DeclareLost before queueFramesForRetransmission, which clears the packet's frames.
	h.hist.DeclareLost(pn)
	h.removeFromBytesInFlight(p)
	h.queueFramesForRetransmission(p)
	return true
}

func (h *sentPacketHandler) queueFramesForRetransmission(p *packet) {
	if len(p.Frames) == 0 && !p.HasStreamFrame && len(p.StreamFrames) == 0 {
		panic("no frames")
	}
	for _, f := range p.Frames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	if p.HasStreamFrame && p.StreamFrame.Handler != nil {
		p.StreamFrame.Handler.OnLost(p.StreamFrame.Frame)
	}
	for _, f := range p.StreamFrames {
		if f.Handler != nil {
			f.Handler.OnLost(f.Frame)
		}
	}
	p.StreamFrame = StreamFrame{}
	p.HasStreamFrame = false
	p.StreamFrames = nil
	p.Frames = nil
}

func (h *sentPacketHandler) ResetForRetry(now monotime.Time) {
	// A Retry can only happen during the handshake, when PathIDZero is the only
	// application-data path.
	appData := h.getAppDataPath(protocol.PathIDZero)
	// Zero both the handshake bytes in flight and the application-data (0-RTT)
	// bytes in flight: a Retry drops all packets sent so far.
	h.bytesInFlight = 0
	appData.bytesInFlight = 0
	var firstPacketSendTime monotime.Time
	// Only Initial and 0-RTT packets can have been sent before a Retry.
	for _, p := range h.hist.Packets() {
		if p.EncryptionLevel == protocol.EncryptionInitial && firstPacketSendTime.IsZero() {
			firstPacketSendTime = p.SendTime
		}
		if p.IsAckEliciting() {
			h.queueFramesForRetransmission(p)
		}
	}

	// Only use the Retry to estimate the RTT if we didn't send any retransmission for the Initial.
	// Otherwise, we don't know which Initial the Retry was sent in response to.
	if appData.ptoCount == 0 {
		// Don't set the RTT to a value lower than 5ms here.
		h.rttStats.UpdateRTT(max(minRTTAfterRetry, now.Sub(firstPacketSendTime)), 0)
		if h.logger.Debug() {
			h.logger.Debugf("\tupdated RTT: %s (σ: %s)", h.rttStats.SmoothedRTT(), h.rttStats.MeanDeviation())
		}
		if h.qlogger != nil {
			h.qlogMetricsUpdated()
		}
	}
	h.hist = *newSentPacketHistory()
	appData.hist = &h.hist
	h.handshakePNs.Initial = h.handshakePNs.Initial[:0]
	h.handshakePNs.Handshake = h.handshakePNs.Handshake[:0]
	h.initialPackets = newPacketNumberSpace()
	appData.space = newPacketNumberSpace()
	oldAlarm := h.alarm
	h.alarm = alarmTimer{}
	if h.qlogger != nil {
		h.qlogger.RecordEvent(qlog.PTOCountUpdated{PTOCount: 0})
		if !oldAlarm.Time.IsZero() {
			h.qlogger.RecordEvent(qlog.LossTimerUpdated{
				Type: qlog.LossTimerUpdateTypeCancelled,
			})
		}
	}
	appData.ptoCount = 0
}

// declareAppDataPathLost declares every outstanding packet on the given
// application-data path lost, requeueing the frames of ack-eliciting packets
// for retransmission (they will be resent on path 0), and drops the path's
// outstanding path probes.
func (h *sentPacketHandler) declareAppDataPathLost(pid protocol.PathID) {
	path, ok := h.appDataPaths[pid]
	if !ok {
		return
	}
	for pn, p := range path.hist.Packets() {
		path.hist.DeclareLost(pn)
		if !p.isPathProbePacket {
			h.removeFromBytesInFlight(p)
			if p.IsAckEliciting() {
				h.queueFramesForRetransmission(p)
			}
		}
	}
	for pn := range path.hist.PathProbes() {
		path.hist.RemovePathProbe(pn)
	}
}

func (h *sentPacketHandler) MigratedPath(now monotime.Time, initialMaxDatagramSize protocol.ByteCount) {
	// MigratedPath is RFC 9000 single-path connection migration, not
	// draft-multipath; PathIDZero is still the only application-data path.
	appData := h.getAppDataPath(protocol.PathIDZero)
	h.rttStats.ResetForPathMigration()
	h.packetThresholdDisabled = false
	h.timeThresholdEighths = defaultTimeThresholdEighths
	h.minPNToRelaxReordering = protocol.InvalidPacketNumber
	appData.lostPackets.Reset()
	for pn, p := range h.hist.Packets() {
		if p.EncryptionLevel.PacketNumberSpace() != protocol.PacketNumberSpaceAppData {
			continue
		}
		h.hist.DeclareLost(pn)
		if !p.isPathProbePacket {
			h.removeFromBytesInFlight(p)
			if p.IsAckEliciting() {
				h.queueFramesForRetransmission(p)
			}
		}
	}
	for pn := range h.hist.PathProbes() {
		h.hist.RemovePathProbe(pn)
	}
	h.congestion = congestion.NewCubicSender(
		congestion.DefaultClock{},
		h.rttStats,
		h.connStats,
		initialMaxDatagramSize,
		true, // use Reno
		h.qlogger,
	)
	// Keep the PathIDZero appData controller in sync with the rebuilt handler
	// controller; for a single path they are the same instance.
	appData.congestion = h.congestion
	h.qlogRecoveryParametersSet(true)
	h.setLossDetectionTimer(now)
}
