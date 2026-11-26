package ackhandler

import (
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
)

// ConnectionStats.PTOs is documented as the total number of loss detection PTO
// alarms that fired, so every branch of OnLossDetectionTimeout that treats the
// alarm as a PTO must increment it. The three branches below reach that point by
// different routes; only the last one is exercised by the single-path tests, so
// each gets its own case here.

// TestPTOCounterCountsAddressValidationPTO covers the branch taken while the
// peer's address is still unvalidated and nothing is in flight: the handler
// arms an Initial probe instead of consulting getPTOTimeAndSpace.
func TestPTOCounterCountsAddressValidationPTO(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(100*time.Millisecond, 0)
	connStats := &utils.ConnectionStats{}
	h := NewSentPacketHandler(
		0,
		oracleInitialMaxDatagramSize,
		rttStats,
		connStats,
		false, // clientAddressValidated
		false,
		func(protocol.PacketNumber) {},
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	).(*sentPacketHandler)

	if h.peerCompletedAddressValidation {
		t.Fatalf("peerCompletedAddressValidation = true, want false for a fresh client")
	}
	if got := h.totalBytesInFlight(); got != 0 {
		t.Fatalf("bytesInFlight = %d, want 0", got)
	}

	if err := h.OnLossDetectionTimeout(monotime.Now()); err != nil {
		t.Fatalf("OnLossDetectionTimeout: %v", err)
	}

	appData := h.getAppDataPath(protocol.PathIDZero)
	if appData.ptoCount != 1 {
		t.Fatalf("ptoCount = %d, want 1 (the address-validation branch was not taken)", appData.ptoCount)
	}
	if appData.ptoMode != SendPTOInitial {
		t.Fatalf("ptoMode = %v, want SendPTOInitial", appData.ptoMode)
	}
	if got := connStats.PTOs.Load(); got != 1 {
		t.Errorf("connStats.PTOs = %d, want 1", got)
	}
}

// TestPTOCounterCountsNonZeroPathPTO covers the branch taken when the earliest
// 1-RTT PTO belongs to a path other than zero: the handler declares that path's
// packets lost and returns without reaching the ordinary PTO tail.
func TestPTOCounterCountsNonZeroPathPTO(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	connStats := h.connStats
	now := monotime.Now()

	if err := h.AddPath(protocol.PathID(1)); err != nil {
		t.Fatalf("AddPath(1): %v", err)
	}
	// Only path 1 has an outstanding ack-eliciting packet, so it owns the
	// earliest PTO and path 0 does not contribute one.
	h.SentPacketForPath(now, 0, protocol.InvalidPacketNumber, protocol.PathID(1),
		nil, []Frame{ackElicitingFrame()}, protocol.ECNNon, 1000, false)

	_, encLevel, pid := h.getPTOTimeAndSpace(now)
	if encLevel != protocol.Encryption1RTT || pid != protocol.PathID(1) {
		t.Fatalf("PTO space = (%v, path %d), want (1-RTT, path 1)", encLevel, pid)
	}

	if err := h.OnLossDetectionTimeout(now); err != nil {
		t.Fatalf("OnLossDetectionTimeout: %v", err)
	}

	// The branch's own effect: path 1's packet is no longer outstanding.
	if h.getAppDataPath(protocol.PathID(1)).hist.HasOutstandingPackets() {
		t.Fatalf("path 1 still has outstanding packets; the nonzero-path branch was not taken")
	}
	if got := connStats.PTOs.Load(); got != 1 {
		t.Errorf("connStats.PTOs = %d, want 1", got)
	}
}

// TestPTOCounterCountsOrdinaryPTO is the control: the branch that already
// incremented the counter must keep doing so exactly once.
func TestPTOCounterCountsOrdinaryPTO(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	connStats := h.connStats
	now := monotime.Now()
	sendAppDataPacket(h, now, 1000)

	if err := h.OnLossDetectionTimeout(now); err != nil {
		t.Fatalf("OnLossDetectionTimeout: %v", err)
	}

	if got := h.getAppDataPath(protocol.PathIDZero).ptoCount; got != 1 {
		t.Fatalf("ptoCount = %d, want 1", got)
	}
	if got := connStats.PTOs.Load(); got != 1 {
		t.Errorf("connStats.PTOs = %d, want 1", got)
	}
}

// TestPTOCounterIgnoresNonPTOTimeouts is the negative control. Not every
// OnLossDetectionTimeout is a PTO: an alarm with no PTO deadline to serve is a
// no-op, and one in loss-timer mode detects lost packets instead of probing.
// Neither may reach the counter.
func TestPTOCounterIgnoresNonPTOTimeouts(t *testing.T) {
	t.Run("no deadline", func(t *testing.T) {
		h, _ := newOracleSentHandler(t)
		now := monotime.Now()
		// Nothing outstanding, address already validated: getPTOTimeAndSpace
		// has no deadline to report.
		if pto, _, _ := h.getPTOTimeAndSpace(now); !pto.IsZero() {
			t.Fatalf("PTO time = %v, want zero", pto)
		}
		if err := h.OnLossDetectionTimeout(now); err != nil {
			t.Fatalf("OnLossDetectionTimeout: %v", err)
		}
		if got := h.connStats.PTOs.Load(); got != 0 {
			t.Errorf("connStats.PTOs = %d, want 0 for a no-op timeout", got)
		}
	})

	t.Run("loss timer mode", func(t *testing.T) {
		h, _ := newOracleSentHandler(t)
		now := monotime.Now()
		sendAppDataPacket(h, now, 1000)
		// An expired loss time takes priority over the PTO, as an ACK that
		// detected a gap would have set it.
		h.getAppDataPath(protocol.PathIDZero).space.lossTime = now

		if err := h.OnLossDetectionTimeout(now); err != nil {
			t.Fatalf("OnLossDetectionTimeout: %v", err)
		}
		if got := h.connStats.PTOs.Load(); got != 0 {
			t.Errorf("connStats.PTOs = %d, want 0 in loss-timer mode", got)
		}
	})
}
