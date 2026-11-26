package ackhandler

import (
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(t monotime.Time, pn, largestAcked protocol.PacketNumber, streamFrames []StreamFrame, frames []Frame, encLevel protocol.EncryptionLevel, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket, isPathProbePacket bool)
	// SentPacketOneStream records the common 1-RTT packet containing one
	// STREAM frame without allocating a one-element slice.
	SentPacketOneStream(t monotime.Time, pn, largestAcked protocol.PacketNumber, streamFrame StreamFrame, frames []Frame, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket bool)
	// SentPacketForPath records a 1-RTT packet sent on the application-data
	// path pid (multipath). The bytes-in-flight, packet-number bookkeeping, and
	// congestion accounting land on pid's own appDataPath. For PathIDZero it is
	// identical to SentPacket with Encryption1RTT.
	SentPacketForPath(t monotime.Time, pn, largestAcked protocol.PacketNumber, pid protocol.PathID, streamFrames []StreamFrame, frames []Frame, ecn protocol.ECN, size protocol.ByteCount, isPathMTUProbePacket bool)
	// ReceivedAck processes an ACK frame.
	// It does not store a copy of the frame.
	ReceivedAck(f *wire.AckFrame, encLevel protocol.EncryptionLevel, rcvTime monotime.Time) (bool /* 1-RTT packet acked */, error)
	// ReceivedAckForPath processes a multipath ACK (PATH_ACK) for the
	// application-data packet number space identified by pid. An unknown pid
	// is a protocol violation; it never falls back to PathIDZero.
	ReceivedAckForPath(f *wire.AckFrame, pid protocol.PathID, rcvTime monotime.Time) (bool /* 1-RTT packet acked */, error)
	// AddPath provisions a genuinely-new application-data path (pid !=
	// PathIDZero) with its own RTT estimator and its own congestion controller
	// (never the connection-level objects PathIDZero aliases). It does not
	// schedule any send over the path. pid == PathIDZero or an already-present
	// pid is an error. It is only called once multipath is negotiated.
	AddPath(pid protocol.PathID) error
	// RemovePath removes a path provisioned by AddPath. It is used only to roll
	// back a path open that failed before becoming visible to the connection.
	RemovePath(pid protocol.PathID)
	ReceivedPacket(protocol.EncryptionLevel, monotime.Time)
	ReceivedPacketForPath(pid protocol.PathID, size protocol.ByteCount, rcvTime monotime.Time)
	ReceivedBytes(_ protocol.ByteCount, rcvTime monotime.Time)
	DropPackets(_ protocol.EncryptionLevel, rcvTime monotime.Time)
	ResetForRetry(rcvTime monotime.Time)

	// The SendMode determines if and what kind of packets can be sent.
	SendMode(now monotime.Time) SendMode
	// SendModeForPath is SendMode for a send targeting application-data path
	// pid: the congestion/pacing checks use pid's own controller. For
	// PathIDZero it is identical to SendMode.
	SendModeForPath(now monotime.Time, pid protocol.PathID) SendMode
	// TimeUntilSend is the time when the next packet should be sent.
	// It is used for pacing packets.
	TimeUntilSend() monotime.Time
	SetMaxDatagramSize(count protocol.ByteCount)

	// only to be called once the handshake is complete
	QueueProbePacket(protocol.PacketNumberSpace) bool /* was a packet queued */

	ECNMode(isShortHeaderPacket bool) protocol.ECN // isShortHeaderPacket should only be true for non-coalesced 1-RTT packets
	PeekPacketNumber(protocol.PacketNumberSpace) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.PacketNumberSpace) protocol.PacketNumber
	// PeekPacketNumberForPath / PopPacketNumberForPath operate on the
	// application-data packet-number space of path pid. For PathIDZero they are
	// identical to Peek/PopPacketNumber(PacketNumberSpaceAppData).
	PeekPacketNumberForPath(pid protocol.PathID) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumberForPath(pid protocol.PathID) protocol.PacketNumber

	GetLossDetectionTimeout() monotime.Time
	OnLossDetectionTimeout(now monotime.Time) error
	// PTOCount is the number of consecutive PTOs on the application-data path
	// since the last acknowledgment.
	PTOCount() uint32

	MigratedPath(now monotime.Time, initialMaxPacketSize protocol.ByteCount)

	// PathDebugStats reports the live application-data recovery state of path
	// pid. It exists so the multipath end-to-end test can prove, on a real
	// connection, that a non-zero path genuinely carried packets (LargestSent)
	// in its own number space and that the path has its own congestion
	// controller + RTT estimator distinct from path 0 and the connection
	// (Stage 4 spec risk #4). It must be called from the run goroutine.
	PathDebugStats(pid protocol.PathID) (PathDebugStats, bool)
}

// PathDebugStats is the live per-path recovery snapshot returned by
// SentPacketHandler.PathDebugStats. It is test-support state, not part of the
// wire protocol.
type PathDebugStats struct {
	// LargestSent is the largest packet number sent in pid's own
	// application-data number space (InvalidPacketNumber if none yet). A value
	// >= 0 proves a packet was packed and sent for pid specifically.
	LargestSent protocol.PacketNumber
	// LargestAcked is the largest packet number acknowledged in pid's space.
	LargestAcked protocol.PacketNumber
	// BytesInFlight is pid's current application-data bytes in flight.
	BytesInFlight protocol.ByteCount
	// BytesSent is the cumulative application-data bytes sent on pid.
	BytesSent uint64
	// BytesReceived is the cumulative application-data bytes received on pid.
	BytesReceived uint64
	// CongestionWindow is pid's current congestion window.
	CongestionWindow protocol.ByteCount
	// LostPackets is the number of application-data packets declared lost on
	// pid. It excludes path validation and path MTU probe packets.
	LostPackets uint64
	// LostBytes is the number of application-data bytes declared lost on pid.
	// It excludes path validation and path MTU probe packets.
	LostBytes uint64
	// SmoothedRTT is pid's application-data RTT estimate.
	SmoothedRTT time.Duration
	// HasRTT reports whether SmoothedRTT is based on a real RTT measurement.
	HasRTT bool
	// DistinctController is true when pid's congestion controller and RTT
	// estimator are both distinct from path 0's and from the connection-level
	// objects (the Stage 4 risk-#4 gate). It is always false for PathIDZero,
	// which aliases the connection objects by design.
	DistinctController bool
}
