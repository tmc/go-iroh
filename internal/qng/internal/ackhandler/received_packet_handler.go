package ackhandler

import (
	"fmt"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

type ReceivedPacketHandler struct {
	initialPackets   *receivedPacketTracker
	handshakePackets *receivedPacketTracker
	// appDataPaths holds the per-path application-data (0-RTT/1-RTT) packet
	// trackers. It always contains exactly the PathIDZero entry until
	// additional paths are opened (Stage 5), making the path map a behavioral
	// no-op with multipath off.
	appDataPaths map[protocol.PathID]*appDataReceivedPacketTracker

	// lowest1RTTPacket is connection-global: 0-RTT is only accepted before the
	// first 1-RTT packet, and multipath paths are added after 1-RTT is live.
	lowest1RTTPacket protocol.PacketNumber
}

func NewReceivedPacketHandler(logger utils.Logger) *ReceivedPacketHandler {
	return &ReceivedPacketHandler{
		initialPackets:   newReceivedPacketTracker(),
		handshakePackets: newReceivedPacketTracker(),
		appDataPaths: map[protocol.PathID]*appDataReceivedPacketTracker{
			protocol.PathIDZero: newAppDataReceivedPacketTracker(logger),
		},
		lowest1RTTPacket: protocol.InvalidPacketNumber,
	}
}

// getAppDataPath returns the per-path application-data tracker for pid. The map
// always contains the PathIDZero entry; an unknown pid returns nil so callers
// can reject path-qualified work for paths that have not been opened.
func (h *ReceivedPacketHandler) getAppDataPath(pid protocol.PathID) *appDataReceivedPacketTracker {
	return h.appDataPaths[pid]
}

// AddPath provisions a received-packet tracker for the genuinely-new
// application-data path pid (multipath). Each path acknowledges the packets it
// receives in its own PATH_ACK number space, so it needs its own tracker. It
// mirrors sentPacketHandler.AddPath: pid == PathIDZero or an already-present pid
// is a BUG, and it is only ever called once multipath is negotiated.
func (h *ReceivedPacketHandler) AddPath(pid protocol.PathID, logger utils.Logger) error {
	if pid == protocol.PathIDZero {
		return fmt.Errorf("cannot add received path with reserved id %d", protocol.PathIDZero)
	}
	if _, ok := h.appDataPaths[pid]; ok {
		return fmt.Errorf("received path %d already exists", pid)
	}
	h.appDataPaths[pid] = newAppDataReceivedPacketTracker(logger)
	return nil
}

func (h *ReceivedPacketHandler) RemovePath(pid protocol.PathID) {
	if pid == protocol.PathIDZero {
		return
	}
	delete(h.appDataPaths, pid)
}

// SetAckFrequencyParams applies ACK_FREQUENCY frame parameters to all application data path trackers.
func (h *ReceivedPacketHandler) SetAckFrequencyParams(ackElicitingThreshold uint64, maxAckDelay time.Duration, reorderingThreshold protocol.PacketNumber, now monotime.Time) {
	for _, path := range h.appDataPaths {
		path.SetAckFrequencyParams(ackElicitingThreshold, maxAckDelay, reorderingThreshold, now)
	}
}

// SetImmediateAckRequired sets immediate ack required across all application data path trackers.
func (h *ReceivedPacketHandler) SetImmediateAckRequired() {
	for _, path := range h.appDataPaths {
		path.SetImmediateAckRequired()
	}
}

// ReceivedPacketForPath records a 1-RTT packet received on application-data path
// pid (multipath), so its acknowledgement is emitted as a PATH_ACK{pid} from
// pid's own tracker rather than the connection-level (PathIDZero) ACK. An
// unknown pid is a BUG (open the path first). For PathIDZero it is identical to
// ReceivedPacket with Encryption1RTT, including the 0-RTT/1-RTT boundary check
// (which is connection-global, Stage 4 spec risk #7).
func (h *ReceivedPacketHandler) ReceivedPacketForPath(
	pn protocol.PacketNumber,
	ecn protocol.ECN,
	pid protocol.PathID,
	rcvTime monotime.Time,
	ackEliciting bool,
) error {
	if h.lowest1RTTPacket == protocol.InvalidPacketNumber || pn < h.lowest1RTTPacket {
		h.lowest1RTTPacket = pn
	}
	path := h.getAppDataPath(pid)
	if path == nil {
		panic(fmt.Sprintf("ReceivedPacketForPath: unknown path %d", pid))
	}
	return path.ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
}

// GetAckFrameForPath returns the ACK frame for path pid's received packets, to
// be carried in a PATH_ACK{pid} frame. For PathIDZero it is identical to
// GetAckFrame(Encryption1RTT). An unknown pid returns nil.
func (h *ReceivedPacketHandler) GetAckFrameForPath(pid protocol.PathID, now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	path := h.getAppDataPath(pid)
	if path == nil {
		return nil
	}
	return path.GetAckFrame(now, onlyIfQueued)
}

// GetAlarmTimeoutForPath returns the ACK alarm timeout for path pid's tracker.
func (h *ReceivedPacketHandler) GetAlarmTimeoutForPath(pid protocol.PathID) monotime.Time {
	path := h.getAppDataPath(pid)
	if path == nil {
		return 0
	}
	return path.GetAlarmTimeout()
}

// IsPotentiallyDuplicateForPath reports whether the 1-RTT packet number pn was
// already received on path pid. Each non-zero path has its own received-packet
// space, so this is checked against pid's tracker, NOT path 0's — path 1's pn=0
// is not a duplicate of path 0's pn=0. An unknown pid returns false.
func (h *ReceivedPacketHandler) IsPotentiallyDuplicateForPath(pn protocol.PacketNumber, pid protocol.PathID) bool {
	path := h.getAppDataPath(pid)
	if path == nil {
		return false
	}
	return path.IsPotentiallyDuplicate(pn)
}

func (h *ReceivedPacketHandler) ReceivedPacket(
	pn protocol.PacketNumber,
	ecn protocol.ECN,
	encLevel protocol.EncryptionLevel,
	rcvTime monotime.Time,
	ackEliciting bool,
) error {
	switch encLevel {
	case protocol.EncryptionInitial:
		return h.initialPackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.EncryptionHandshake:
		// The Handshake packet number space might already have been dropped as a result
		// of processing the CRYPTO frame that was contained in this packet.
		if h.handshakePackets == nil {
			return nil
		}
		return h.handshakePackets.ReceivedPacket(pn, ecn, ackEliciting)
	case protocol.Encryption0RTT:
		if h.lowest1RTTPacket != protocol.InvalidPacketNumber && pn > h.lowest1RTTPacket {
			return fmt.Errorf("received packet number %d on a 0-RTT packet after receiving %d on a 1-RTT packet", pn, h.lowest1RTTPacket)
		}
		return h.getAppDataPath(protocol.PathIDZero).ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	case protocol.Encryption1RTT:
		if h.lowest1RTTPacket == protocol.InvalidPacketNumber || pn < h.lowest1RTTPacket {
			h.lowest1RTTPacket = pn
		}
		return h.getAppDataPath(protocol.PathIDZero).ReceivedPacket(pn, ecn, rcvTime, ackEliciting)
	default:
		panic(fmt.Sprintf("received packet with unknown encryption level: %s", encLevel))
	}
}

func (h *ReceivedPacketHandler) IgnorePacketsBelow(pn protocol.PacketNumber) {
	h.getAppDataPath(protocol.PathIDZero).IgnoreBelow(pn)
}

func (h *ReceivedPacketHandler) DropPackets(encLevel protocol.EncryptionLevel) {
	//nolint:exhaustive // 1-RTT packet number space is never dropped.
	switch encLevel {
	case protocol.EncryptionInitial:
		h.initialPackets = nil
	case protocol.EncryptionHandshake:
		h.handshakePackets = nil
	case protocol.Encryption0RTT:
		// Nothing to do here.
		// If we are rejecting 0-RTT, no 0-RTT packets will have been decrypted.
	default:
		panic(fmt.Sprintf("Cannot drop keys for encryption level %s", encLevel))
	}
}

func (h *ReceivedPacketHandler) GetAlarmTimeout() monotime.Time {
	return h.getAppDataPath(protocol.PathIDZero).GetAlarmTimeout()
}

func (h *ReceivedPacketHandler) GetAckFrame(encLevel protocol.EncryptionLevel, now monotime.Time, onlyIfQueued bool) *wire.AckFrame {
	//nolint:exhaustive // 0-RTT packets can't contain ACK frames.
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialPackets != nil {
			return h.initialPackets.GetAckFrame()
		}
		return nil
	case protocol.EncryptionHandshake:
		if h.handshakePackets != nil {
			return h.handshakePackets.GetAckFrame()
		}
		return nil
	case protocol.Encryption1RTT:
		return h.getAppDataPath(protocol.PathIDZero).GetAckFrame(now, onlyIfQueued)
	default:
		// 0-RTT packets can't contain ACK frames
		return nil
	}
}

func (h *ReceivedPacketHandler) IsPotentiallyDuplicate(pn protocol.PacketNumber, encLevel protocol.EncryptionLevel) bool {
	switch encLevel {
	case protocol.EncryptionInitial:
		if h.initialPackets != nil {
			return h.initialPackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.EncryptionHandshake:
		if h.handshakePackets != nil {
			return h.handshakePackets.IsPotentiallyDuplicate(pn)
		}
	case protocol.Encryption0RTT, protocol.Encryption1RTT:
		return h.getAppDataPath(protocol.PathIDZero).IsPotentiallyDuplicate(pn)
	}
	panic("unexpected encryption level")
}
