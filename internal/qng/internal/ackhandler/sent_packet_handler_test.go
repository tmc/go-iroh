package ackhandler

import (
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
	"github.com/tmc/go-iroh/internal/qng/qlog"
)

// These tests pin the behavior of the flat-field sentPacketHandler so that the
// Stage 4a refactor (introducing a single-entry appDataPaths map keyed by
// protocol.PathIDZero) can be shown to be a behavioral no-op. They construct the
// real handler via NewSentPacketHandler with the real cubic congestion
// controller and a real RTTStats, then assert observable recovery state through
// the concrete *sentPacketHandler.
//
// Stage 4a moved the packet-number bookkeeping into the single PathIDZero map
// entry; Stage 4b additionally moved the appData bytes-in-flight, PTO count,
// congestion controller, RTT estimator and ECN tracker there. The field reads
// below therefore go through getAppDataPath(protocol.PathIDZero) for the
// app-data recovery state (bytesInFlight, ptoCount); the asserted values are
// identical to the pre-refactor flat-field handler.

const oracleInitialMaxDatagramSize = protocol.ByteCount(1252)

// newOracleSentHandler builds a sentPacketHandler with the handshake already
// confirmed and the peer's address validated, so the appData (1-RTT) space
// behaves as it does in steady state. A fixed RTT is seeded so loss-detection
// and PTO timers are deterministic.
func newOracleSentHandler(t *testing.T) (*sentPacketHandler, *utils.RTTStats) {
	t.Helper()
	rttStats := utils.NewRTTStats()
	// Seed a deterministic RTT so getScaledPTO / time-threshold loss detection
	// produce stable, non-zero timer values.
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	h := NewSentPacketHandler(
		0,
		oracleInitialMaxDatagramSize,
		rttStats,
		connStats,
		true, // clientAddressValidated
		false,
		func(protocol.PacketNumber) {},
		protocol.PerspectiveClient,
		nil, // no qlogger
		utils.DefaultLogger,
	).(*sentPacketHandler)
	// Put the handler into the post-handshake steady state for the appData space.
	h.handshakeConfirmed = true
	h.peerCompletedAddressValidation = true
	h.peerAddressValidated = true
	h.initialPackets = nil
	h.handshakePackets = nil
	return h, rttStats
}

// ackElicitingFrame returns a Frame that makes a packet ack-eliciting without
// any acked/lost callbacks.
func ackElicitingFrame() Frame {
	return Frame{Frame: &wire.PingFrame{}}
}

// sendAppDataPacket allocates the next 1-RTT packet number through the handler
// (so the packet-number generator and the sent-packet history stay in lockstep,
// exactly as the connection drives them) and sends a single ack-eliciting 1-RTT
// packet. It returns the allocated packet number.
func sendAppDataPacket(h *sentPacketHandler, sendTime monotime.Time, size protocol.ByteCount) protocol.PacketNumber {
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	h.SentPacket(
		sendTime,
		pn,
		protocol.InvalidPacketNumber,
		nil,
		[]Frame{ackElicitingFrame()},
		protocol.Encryption1RTT,
		protocol.ECNNon,
		size,
		false,
		false,
	)
	return pn
}

// ackFrameForPN returns an ACK frame acknowledging a single packet number.
func ackFrameForPN(pn protocol.PacketNumber) *wire.AckFrame {
	return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}}}
}

// ackRangesForPNs builds the AckRanges acknowledging exactly the supplied
// packet numbers and nothing else. The appData generator skips packet numbers
// at random, so a window of sent PNs is not necessarily contiguous; a single
// {Smallest,Largest} range would acknowledge a skipped (never-sent) PN, which
// ReceivedAck rejects as an optimistic-ACK attack. This coalesces the sent PNs
// into the gap-respecting ranges the wire expects (descending, non-overlapping).
func ackRangesForPNs(pns []protocol.PacketNumber) []wire.AckRange {
	if len(pns) == 0 {
		return nil
	}
	sorted := append([]protocol.PacketNumber(nil), pns...)
	slices.Sort(sorted)
	var ranges []wire.AckRange
	lo, hi := sorted[0], sorted[0]
	flush := func() {
		ranges = append(ranges, wire.AckRange{Smallest: lo, Largest: hi})
	}
	for _, pn := range sorted[1:] {
		if pn == hi+1 {
			hi = pn
			continue
		}
		flush()
		lo, hi = pn, pn
	}
	flush()
	// AckFrame ranges run from the largest packet number to the smallest.
	slices.Reverse(ranges)
	return ranges
}

// TestAckRangesForPNs pins ackRangesForPNs: it must emit gap-respecting,
// descending ranges so a skipped (never-sent) packet number is never
// acknowledged. This is the helper that keeps TestSentPacketHandlerAckBookkeeping
// from flaking when the appData generator skips a PN inside the acked window.
func TestAckRangesForPNs(t *testing.T) {
	tests := []struct {
		name string
		pns  []protocol.PacketNumber
		want []wire.AckRange
	}{
		{name: "empty", pns: nil, want: nil},
		{name: "single", pns: []protocol.PacketNumber{2}, want: []wire.AckRange{{Smallest: 2, Largest: 2}}},
		{name: "contiguous", pns: []protocol.PacketNumber{0, 1, 2, 3}, want: []wire.AckRange{{Smallest: 0, Largest: 3}}},
		{
			name: "one gap (a skipped PN inside the window)",
			pns:  []protocol.PacketNumber{0, 1, 2, 3, 5}, // 4 skipped
			want: []wire.AckRange{{Smallest: 5, Largest: 5}, {Smallest: 0, Largest: 3}},
		},
		{
			name: "two gaps unsorted input",
			pns:  []protocol.PacketNumber{5, 0, 2, 3},
			want: []wire.AckRange{{Smallest: 5, Largest: 5}, {Smallest: 2, Largest: 3}, {Smallest: 0, Largest: 0}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ackRangesForPNs(tt.pns)
			if !slices.Equal(got, tt.want) {
				t.Errorf("ackRangesForPNs(%v) = %v, want %v", tt.pns, got, tt.want)
			}
		})
	}
}

// outstandingPNs returns the still-outstanding packet numbers in the appData
// history, in ascending order.
func outstandingPNs(h *sentPacketHandler) []protocol.PacketNumber {
	var pns []protocol.PacketNumber
	for pn, p := range h.getAppDataPath(protocol.PathIDZero).hist.Packets() {
		if p.Outstanding() {
			pns = append(pns, pn)
		}
	}
	return pns
}

func TestSentPacketHandlerAckBookkeeping(t *testing.T) {
	const packetSize = protocol.ByteCount(1000)

	// The appData packet-number generator skips numbers at random, so the test
	// captures the actually-allocated PNs and indexes into them rather than
	// hardcoding values. ackIdx/wantOutstandingIdx are indices into the slice
	// of sent PNs.
	tests := []struct {
		name string
		// number of 1-RTT packets to send
		numSent int
		// indices (into the sent-PN slice) acked by a contiguous range
		// [sent[ackLoIdx] .. sent[ackHiIdx]]
		ackLoIdx, ackHiIdx int
		wantBytesInFlight  protocol.ByteCount
		wantAcked1RTT      bool
		// indices of PNs expected to remain outstanding after the ack
		wantOutstandingIdx []int
	}{
		{
			name:               "ack all packets",
			numSent:            5,
			ackLoIdx:           0,
			ackHiIdx:           4,
			wantBytesInFlight:  0,
			wantAcked1RTT:      true,
			wantOutstandingIdx: nil,
		},
		{
			name:               "ack a prefix",
			numSent:            5,
			ackLoIdx:           0,
			ackHiIdx:           2,
			wantBytesInFlight:  2 * packetSize, // sent[3], sent[4] still outstanding
			wantAcked1RTT:      true,
			wantOutstandingIdx: []int{3, 4},
		},
		{
			name:               "ack single middle packet",
			numSent:            3,
			ackLoIdx:           1,
			ackHiIdx:           1,
			wantBytesInFlight:  2 * packetSize, // sent[0], sent[2] still outstanding
			wantAcked1RTT:      true,
			wantOutstandingIdx: []int{0, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newOracleSentHandler(t)
			now := monotime.Now()
			sent := make([]protocol.PacketNumber, tt.numSent)
			for i := range sent {
				sent[i] = sendAppDataPacket(h, now, packetSize)
			}
			if got := h.getAppDataPath(protocol.PathIDZero).bytesInFlight; got != protocol.ByteCount(tt.numSent)*packetSize {
				t.Fatalf("bytesInFlight before ack = %d, want %d", got, protocol.ByteCount(tt.numSent)*packetSize)
			}

			wantLargestAcked := sent[tt.ackHiIdx]
			// Acknowledge exactly the PNs actually sent in [ackLoIdx, ackHiIdx];
			// the generator may have skipped a PN inside that window, and a
			// single contiguous range would ACK a never-sent PN.
			ack := &wire.AckFrame{AckRanges: ackRangesForPNs(sent[tt.ackLoIdx : tt.ackHiIdx+1])}
			acked1RTT, err := h.ReceivedAck(ack, protocol.Encryption1RTT, now)
			if err != nil {
				t.Fatalf("ReceivedAck: %v", err)
			}
			if acked1RTT != tt.wantAcked1RTT {
				t.Errorf("acked1RTT = %v, want %v", acked1RTT, tt.wantAcked1RTT)
			}
			if got := h.getAppDataPath(protocol.PathIDZero).bytesInFlight; got != tt.wantBytesInFlight {
				t.Errorf("bytesInFlight = %d, want %d", got, tt.wantBytesInFlight)
			}
			if got := h.getAppDataPath(protocol.PathIDZero).space.largestAcked; got != wantLargestAcked {
				t.Errorf("largestAcked = %d, want %d", got, wantLargestAcked)
			}

			var want []protocol.PacketNumber
			for _, idx := range tt.wantOutstandingIdx {
				want = append(want, sent[idx])
			}
			if got := outstandingPNs(h); !equalPNs(got, want) {
				t.Errorf("outstanding = %v, want %v", got, want)
			}
		})
	}
}

// TestSentPacketHandlerPTOCountReset pins that ptoCount is reset on an ACK that
// acknowledges packets once the peer has completed address validation.
func TestSentPacketHandlerPTOCountReset(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()
	sendAppDataPacket(h, now, 1000)

	// Force a PTO to bump ptoCount.
	if err := h.OnLossDetectionTimeout(now.Add(time.Second)); err != nil {
		t.Fatalf("OnLossDetectionTimeout: %v", err)
	}
	if h.getAppDataPath(protocol.PathIDZero).ptoCount == 0 {
		t.Fatalf("expected ptoCount > 0 after PTO, got 0")
	}

	// A packet sent in PTO mode, then acked, must reset ptoCount.
	pn := sendAppDataPacket(h, now.Add(time.Second), 1000)
	if _, err := h.ReceivedAck(ackFrameForPN(pn), protocol.Encryption1RTT, now.Add(2*time.Second)); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}
	if got := h.getAppDataPath(protocol.PathIDZero).ptoCount; got != 0 {
		t.Errorf("ptoCount after ack = %d, want 0", got)
	}
}

func TestSentPacketHandlerLostPathProbeWithoutHandler(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()
	pn := h.PopPacketNumber(protocol.PacketNumberSpaceAppData)
	h.SentPacket(
		now,
		pn,
		protocol.InvalidPacketNumber,
		nil,
		[]Frame{{Frame: &wire.PathChallengeFrame{Data: [8]byte{1}}}},
		protocol.Encryption1RTT,
		protocol.ECNNon,
		oracleInitialMaxDatagramSize,
		false,
		true,
	)

	hist := h.getAppDataPath(protocol.PathIDZero).hist
	if !hist.HasOutstandingPathProbes() {
		t.Fatal("path probe not tracked")
	}
	h.detectLostPathProbes(now.Add(pathProbePacketLossTimeout + time.Millisecond))
	if hist.HasOutstandingPathProbes() {
		t.Fatal("lost path probe still tracked")
	}
}

// TestSentPacketHandlerLossTimerArmed pins that sending an ack-eliciting 1-RTT
// packet arms a PTO loss-detection timer in the 1-RTT space and that delivering
// an ACK that leaves nothing outstanding cancels it.
func TestSentPacketHandlerLossTimerArmed(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	if !h.GetLossDetectionTimeout().IsZero() {
		t.Fatalf("loss timer should be unset before any packet is sent")
	}

	pn := sendAppDataPacket(h, now, 1000)
	armed := h.GetLossDetectionTimeout()
	if armed.IsZero() {
		t.Fatalf("loss timer should be armed after sending an ack-eliciting packet")
	}
	// With a single outstanding packet, the armed alarm is a PTO timer.
	if h.alarm.TimerType != qlog.TimerTypePTO {
		t.Errorf("alarm type = %v, want %v", h.alarm.TimerType, qlog.TimerTypePTO)
	}
	if h.alarm.EncryptionLevel != protocol.Encryption1RTT {
		t.Errorf("alarm enc level = %v, want %v", h.alarm.EncryptionLevel, protocol.Encryption1RTT)
	}

	// Ack the only outstanding packet: timer must be canceled.
	if _, err := h.ReceivedAck(ackFrameForPN(pn), protocol.Encryption1RTT, now); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}
	if !h.GetLossDetectionTimeout().IsZero() {
		t.Errorf("loss timer should be canceled once nothing is outstanding, got %v", h.GetLossDetectionTimeout())
	}
}

// TestSentPacketHandlerReorderingLoss pins reordering-threshold loss detection:
// after acking a much higher packet number, lower outstanding ack-eliciting
// packets beyond the reordering threshold are declared lost (removed from
// bytes-in-flight and history).
func TestSentPacketHandlerReorderingLoss(t *testing.T) {
	const packetSize = protocol.ByteCount(1000)
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	// Send 5 packets, capturing the actually-allocated packet numbers (the
	// appData generator skips numbers at random).
	sent := make([]protocol.PacketNumber, 5)
	for i := range sent {
		sent[i] = sendAppDataPacket(h, now, packetSize)
	}
	largest := sent[len(sent)-1]

	// Derive, from the implementation's own packet-distance measure, which of the
	// earlier packets are >= packetThreshold behind the largest acked. Those must
	// be declared lost by reordering; the rest must remain outstanding. This makes
	// the assertion robust to random packet-number skips while still pinning the
	// reordering-threshold behavior.
	appData := h.getAppDataPath(protocol.PathIDZero).space
	var wantOutstanding []protocol.PacketNumber
	for _, pn := range sent[:len(sent)-1] {
		if h.hist.Difference(largest, pn) < packetThreshold {
			wantOutstanding = append(wantOutstanding, pn)
		}
	}

	// Ack only the largest packet.
	if _, err := h.ReceivedAck(ackFrameForPN(largest), protocol.Encryption1RTT, now); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}

	if got := outstandingPNs(h); !equalPNs(got, wantOutstanding) {
		t.Errorf("outstanding after reordering loss = %v, want %v", got, wantOutstanding)
	}
	if got, want := h.getAppDataPath(protocol.PathIDZero).bytesInFlight, protocol.ByteCount(len(wantOutstanding))*packetSize; got != want {
		t.Errorf("bytesInFlight = %d, want %d", got, want)
	}
	wantLost := uint64(len(sent) - 1 - len(wantOutstanding))
	pathStats, ok := h.PathDebugStats(protocol.PathIDZero)
	if !ok {
		t.Fatal("PathDebugStats(PathIDZero) not found")
	}
	if pathStats.LostPackets != wantLost {
		t.Errorf("LostPackets = %d, want %d", pathStats.LostPackets, wantLost)
	}
	if pathStats.LostBytes != wantLost*uint64(packetSize) {
		t.Errorf("LostBytes = %d, want %d", pathStats.LostBytes, wantLost*uint64(packetSize))
	}
	if appData.largestAcked != largest {
		t.Errorf("largestAcked = %d, want %d", appData.largestAcked, largest)
	}
	// A loss-detection timer should be armed for the still-pending packets.
	if len(wantOutstanding) > 0 && appData.lossTime.IsZero() {
		t.Errorf("expected an appData lossTime to be set for the pending packets")
	}
}

// TestSentPacketHandlerAckUnsentPacket pins the ProtocolViolation guard for an
// ACK acknowledging a packet number we never sent.
func TestSentPacketHandlerAckUnsentPacket(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()
	pn := sendAppDataPacket(h, now, 1000)

	// Ack a packet number well above the largest we sent.
	_, err := h.ReceivedAck(ackFrameForPN(pn+100), protocol.Encryption1RTT, now)
	if err == nil {
		t.Fatalf("expected error for ACK of unsent packet")
	}
	transportErr, ok := err.(*qerr.TransportError)
	if !ok {
		t.Fatalf("error type = %T, want *qerr.TransportError", err)
	}
	if transportErr.ErrorCode != qerr.ProtocolViolation {
		t.Errorf("error code = %v, want ProtocolViolation", transportErr.ErrorCode)
	}
}

// TestSentPacketHandlerLossTimeAndSpaceSinglePath pins getLossTimeAndSpace /
// getPTOTimeAndSpace for the single (appData) path, which is the exact output
// the post-refactor fan-out over the single-entry path map must reproduce.
func TestSentPacketHandlerLossTimeAndSpaceSinglePath(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	// No outstanding packets: both helpers return zero/empty.
	if lt, _, _ := h.getLossTimeAndSpace(); !lt.IsZero() {
		t.Errorf("getLossTimeAndSpace with nothing sent = %v, want zero", lt)
	}
	if pt, _, _ := h.getPTOTimeAndSpace(now); !pt.IsZero() {
		t.Errorf("getPTOTimeAndSpace with nothing sent = %v, want zero", pt)
	}

	// Send a packet: PTO time/space should reference the 1-RTT space.
	sendAppDataPacket(h, now, 1000)
	ptoTime, ptoEncLevel, _ := h.getPTOTimeAndSpace(now)
	if ptoTime.IsZero() {
		t.Fatalf("expected non-zero PTO time after sending an ack-eliciting packet")
	}
	if ptoEncLevel != protocol.Encryption1RTT {
		t.Errorf("PTO enc level = %v, want %v", ptoEncLevel, protocol.Encryption1RTT)
	}
	// The PTO time is anchored to the last ack-eliciting send time plus the
	// scaled PTO. This pins the exact arithmetic so the per-path version must
	// match.
	wantPTO := now.Add(h.getScaledPTO(true))
	if !ptoTime.Equal(wantPTO) {
		t.Errorf("PTO time = %v, want %v", ptoTime, wantPTO)
	}

	// detectLostPackets sets appData lossTime when there is a still-pending
	// packet below the largest acked; getLossTimeAndSpace must surface it as
	// the 1-RTT space. Send two more and ack only the last so the earlier
	// packets stay within the reordering threshold (arming a time-based loss
	// timer rather than being declared lost outright).
	sendAppDataPacket(h, now, 1000)
	last := sendAppDataPacket(h, now, 1000)
	if _, err := h.ReceivedAck(ackFrameForPN(last), protocol.Encryption1RTT, now); err != nil {
		t.Fatalf("ReceivedAck: %v", err)
	}
	lossTime, lossEncLevel, lossPathID := h.getLossTimeAndSpace()
	if lossTime.IsZero() {
		t.Fatalf("expected a non-zero loss time after partial ack")
	}
	if lossEncLevel != protocol.Encryption1RTT {
		t.Errorf("loss enc level = %v, want %v", lossEncLevel, protocol.Encryption1RTT)
	}
	// Single path: the earliest loss time must be attributed to PathIDZero.
	if lossPathID != protocol.PathIDZero {
		t.Errorf("loss path id = %d, want PathIDZero", lossPathID)
	}
	appDataLossTime := h.getAppDataPath(protocol.PathIDZero).space.lossTime
	if !lossTime.Equal(appDataLossTime) {
		t.Errorf("getLossTimeAndSpace = %v, want appData lossTime %v", lossTime, appDataLossTime)
	}
}

// TestReceivedAckForPathDelegatesToPathIDZero pins that ReceivedAckForPath with
// PathIDZero is bit-identical to ReceivedAck at 1-RTT (Stage 4c). The two paths
// must drive the same recovery state, since ReceivedAck(1-RTT) delegates to
// ReceivedAckForPath(PathIDZero) — single-path stays unchanged.
func TestReceivedAckForPathDelegatesToPathIDZero(t *testing.T) {
	const packetSize = protocol.ByteCount(1000)

	// run drives N sends then a single-PN ack via fn, returning the observable
	// recovery state after the ack.
	run := func(fn func(h *sentPacketHandler, pn protocol.PacketNumber, now monotime.Time) (bool, error)) (acked bool, bytesInFlight protocol.ByteCount, largestAcked protocol.PacketNumber, outstanding []protocol.PacketNumber) {
		h, _ := newOracleSentHandler(t)
		now := monotime.Now()
		sent := make([]protocol.PacketNumber, 3)
		for i := range sent {
			sent[i] = sendAppDataPacket(h, now, packetSize)
		}
		var err error
		acked, err = fn(h, sent[1], now)
		if err != nil {
			t.Fatalf("ack: %v", err)
		}
		return acked, h.getAppDataPath(protocol.PathIDZero).bytesInFlight,
			h.getAppDataPath(protocol.PathIDZero).space.largestAcked, outstandingPNs(h)
	}

	viaReceivedAck := func(h *sentPacketHandler, pn protocol.PacketNumber, now monotime.Time) (bool, error) {
		return h.ReceivedAck(ackFrameForPN(pn), protocol.Encryption1RTT, now)
	}
	viaForPath := func(h *sentPacketHandler, pn protocol.PacketNumber, now monotime.Time) (bool, error) {
		return h.ReceivedAckForPath(ackFrameForPN(pn), protocol.PathIDZero, now)
	}

	a1, bif1, la1, out1 := run(viaReceivedAck)
	a2, bif2, la2, out2 := run(viaForPath)

	if a1 != a2 {
		t.Errorf("acked1RTT differs: ReceivedAck=%v ReceivedAckForPath=%v", a1, a2)
	}
	if bif1 != bif2 {
		t.Errorf("bytesInFlight differs: ReceivedAck=%d ReceivedAckForPath=%d", bif1, bif2)
	}
	if la1 != la2 {
		t.Errorf("largestAcked differs: ReceivedAck=%d ReceivedAckForPath=%d", la1, la2)
	}
	if !equalPNs(out1, out2) {
		t.Errorf("outstanding differs: ReceivedAck=%v ReceivedAckForPath=%v", out1, out2)
	}
}

// TestReceivedAckForPathUnknownPathID is the headline Stage 4c safety test
// (spec risk #1, QNG-MULTIPATH-PLAN.md:94-96): an ACK for a path with no entry
// in the appData path map MUST return a ProtocolViolation and MUST NOT fall
// back to PathIDZero. Until Stage 5 opens a second path, the map only holds
// PathIDZero, so any non-zero pid is rejected — the peer cannot acknowledge a
// path we never opened.
func TestReceivedAckForPathUnknownPathID(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()
	pn := sendAppDataPacket(h, now, 1000)

	// Sanity: PathIDZero is the only entry.
	if _, ok := h.appDataPaths[protocol.PathID(1)]; ok {
		t.Fatalf("path 1 must not exist before Stage 5")
	}

	_, err := h.ReceivedAckForPath(ackFrameForPN(pn), protocol.PathID(1), now)
	if err == nil {
		t.Fatalf("expected ProtocolViolation for ACK on unknown path, got nil")
	}
	transportErr, ok := err.(*qerr.TransportError)
	if !ok {
		t.Fatalf("error type = %T, want *qerr.TransportError", err)
	}
	if transportErr.ErrorCode != qerr.ProtocolViolation {
		t.Errorf("error code = %v, want ProtocolViolation", transportErr.ErrorCode)
	}

	// The unknown-path ACK must not perturb PathIDZero's state: the packet we
	// sent stays outstanding (the ACK was rejected, never attributed to path 0).
	if got := outstandingPNs(h); !equalPNs(got, []protocol.PacketNumber{pn}) {
		t.Errorf("outstanding after rejected ACK = %v, want %v (path 0 untouched)", got, []protocol.PacketNumber{pn})
	}
	if got := h.getAppDataPath(protocol.PathIDZero).bytesInFlight; got != 1000 {
		t.Errorf("bytesInFlight after rejected ACK = %d, want 1000 (path 0 untouched)", got)
	}
}

// TestSentPacketHandlerAddPathDistinctController is the Stage 5a (4b-flagged)
// gate: a genuinely-new path (PathID != 0) MUST get its OWN congestion
// controller and its OWN RTT estimator. It must NOT alias the connection-level
// rttStats/congestion that PathIDZero shares (Stage 4 spec risk #4: the
// connection rttStats drives idle/keepalive/connID-retirement timers and must
// never track a non-zero path's RTT). This mirrors PathData::new
// (paths.rs:304-310), which builds a fresh RttEstimator and a fresh congestion
// controller per path.
func TestSentPacketHandlerAddPathDistinctController(t *testing.T) {
	h, connRTTStats := newOracleSentHandler(t)

	path0 := h.getAppDataPath(protocol.PathIDZero)
	// PathIDZero aliases the connection objects — this is the invariant that
	// must stay (single-path byte-identical).
	if path0.rttStats != connRTTStats {
		t.Fatalf("PathIDZero rttStats must alias the connection rttStats")
	}
	if path0.rttStats != h.rttStats {
		t.Fatalf("PathIDZero rttStats must alias h.rttStats")
	}
	if path0.congestion != h.congestion {
		t.Fatalf("PathIDZero congestion must alias h.congestion")
	}

	if err := h.AddPath(protocol.PathID(1)); err != nil {
		t.Fatalf("AddPath(1): %v", err)
	}
	path1 := h.getAppDataPath(protocol.PathID(1))
	if path1 == nil {
		t.Fatalf("path 1 not present after AddPath(1)")
	}

	// Distinct-pointer assertions: path 1's rttStats and congestion must be
	// independent of both path 0 and the connection.
	if path1.rttStats == path0.rttStats {
		t.Errorf("path 1 rttStats aliases path 0 rttStats")
	}
	if path1.rttStats == h.rttStats {
		t.Errorf("path 1 rttStats aliases the connection rttStats (risk #4)")
	}
	if path1.congestion == path0.congestion {
		t.Errorf("path 1 congestion aliases path 0 congestion")
	}
	if path1.congestion == h.congestion {
		t.Errorf("path 1 congestion aliases the connection congestion controller")
	}

	// Behavioral isolation: capture path 0 / connection state, then drive an
	// RTT sample and an OnPacketSent into path 1 only. Path 0's smoothed RTT and
	// congestion window must be unchanged.
	path0SmoothedRTT := path0.rttStats.SmoothedRTT()
	connSmoothedRTT := h.rttStats.SmoothedRTT()
	path0Cwnd := path0.congestion.GetCongestionWindow()

	path1.rttStats.UpdateRTT(500*time.Millisecond, 0)
	path1.congestion.OnPacketSent(monotime.Now(), 1, 1200, true)

	if got := path0.rttStats.SmoothedRTT(); got != path0SmoothedRTT {
		t.Errorf("path 0 SmoothedRTT changed after path 1 RTT sample: %v != %v", got, path0SmoothedRTT)
	}
	if got := h.rttStats.SmoothedRTT(); got != connSmoothedRTT {
		t.Errorf("connection SmoothedRTT changed after path 1 RTT sample: %v != %v (risk #4)", got, connSmoothedRTT)
	}
	if got := path0.congestion.GetCongestionWindow(); got != path0Cwnd {
		t.Errorf("path 0 congestion window changed after path 1 OnPacketSent: %d != %d", got, path0Cwnd)
	}

	// The fresh path-1 RTT sample is distinct from path 0 / connection (proving
	// the sample landed on the independent estimator).
	if path1.rttStats.SmoothedRTT() == path0.rttStats.SmoothedRTT() {
		t.Errorf("path 1 SmoothedRTT == path 0 SmoothedRTT after independent sample")
	}
}

// TestSentPacketHandlerAddPathErrors pins the AddPath guards: the reserved
// PathIDZero is rejected (it is the connection-aliased path, built at
// construction), and adding the same path twice is rejected.
func TestSentPacketHandlerAddPathErrors(t *testing.T) {
	h, _ := newOracleSentHandler(t)

	if err := h.AddPath(protocol.PathIDZero); err == nil {
		t.Errorf("AddPath(PathIDZero) should error")
	}

	if err := h.AddPath(protocol.PathID(1)); err != nil {
		t.Fatalf("first AddPath(1): %v", err)
	}
	if err := h.AddPath(protocol.PathID(1)); err == nil {
		t.Errorf("double AddPath(1) should error")
	}
}

func equalPNs(a, b []protocol.PacketNumber) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestPTOOnNonZeroPathDrainsPath is the regression gate for the PTO spin loop:
// PTO probes are only ever sent on path 0, so a probe can never refresh a
// non-zero path's lastAckElicitingPacketTime. When such a path's PTO deadline
// expires, the handler must drain the path (declare its outstanding packets
// lost) rather than arm path-0 probes — otherwise the expired deadline
// re-fires the alarm immediately, forever (observed live as the PTO count
// climbing ~1000/s until the tracked-packet limit killed the connection).
func TestPTOOnNonZeroPathDrainsPath(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	if err := h.AddPath(protocol.PathID(1)); err != nil {
		t.Fatalf("AddPath(1): %v", err)
	}
	// One ack-eliciting packet on path 1, never acknowledged.
	pn := h.PopPacketNumberForPath(protocol.PathID(1))
	h.SentPacketForPath(now, pn, protocol.InvalidPacketNumber, protocol.PathID(1), nil,
		[]Frame{ackElicitingFrame()}, protocol.ECNNon, 1200, false)

	path1 := h.getAppDataPath(protocol.PathID(1))
	if !path1.hist.HasOutstandingPackets() {
		t.Fatalf("path 1 has no outstanding packets after SentPacketForPath")
	}

	ptoTime, encLevel, pid := h.getPTOTimeAndSpace(now)
	if ptoTime.IsZero() || encLevel != protocol.Encryption1RTT || pid != protocol.PathID(1) {
		t.Fatalf("getPTOTimeAndSpace = (%v, %v, %v), want non-zero 1-RTT deadline on path 1",
			ptoTime, encLevel, pid)
	}

	// Fire the PTO past the deadline: the path must drain, not probe.
	late := ptoTime.Add(time.Second)
	if err := h.OnLossDetectionTimeout(late); err != nil {
		t.Fatalf("OnLossDetectionTimeout: %v", err)
	}
	if path1.hist.HasOutstandingPackets() {
		t.Errorf("path 1 still has outstanding packets after its PTO fired; an expired deadline would re-fire forever")
	}
	if path1.bytesInFlight != 0 {
		t.Errorf("path 1 bytesInFlight = %d after drain, want 0", path1.bytesInFlight)
	}
	if n := h.getAppDataPath(protocol.PathIDZero).numProbesToSend; n != 0 {
		t.Errorf("PTO on a non-zero path armed %d path-0 probes, want 0", n)
	}
	// The re-armed alarm must not be stuck in the past.
	if alarm := h.GetLossDetectionTimeout(); !alarm.IsZero() && !alarm.After(late) {
		t.Errorf("loss detection alarm %v not after %v; the alarm would re-fire immediately", alarm, late)
	}
}
