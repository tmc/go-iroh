package ackhandler

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// lossDetectionTime cancels the alarm when nothing is outstanding. With
// multipath that question spans every application-data path, not just path
// zero: a path whose only outstanding packets live on it would otherwise lose
// its loss detection entirely, because no alarm would ever be armed for it.

// TestLossAlarmArmedForNonZeroPathOnly is the regression test for that case.
// Path zero is idle and path one holds the only outstanding packet.
func TestLossAlarmArmedForNonZeroPathOnly(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	if err := h.AddPath(protocol.PathID(1)); err != nil {
		t.Fatalf("AddPath(1): %v", err)
	}
	if got := h.lossDetectionTime(now); !got.Time.IsZero() {
		t.Fatalf("alarm armed with nothing outstanding: %v", got.Time)
	}

	h.SentPacketForPath(now, 0, protocol.InvalidPacketNumber, protocol.PathID(1),
		nil, []Frame{ackElicitingFrame()}, protocol.ECNNon, 1000, false)

	if h.getAppDataPath(protocol.PathIDZero).hist.HasOutstandingPackets() {
		t.Fatalf("path 0 has outstanding packets; the test no longer isolates path 1")
	}
	alarm := h.lossDetectionTime(now)
	if alarm.Time.IsZero() {
		t.Fatal("no loss alarm for a packet outstanding only on path 1")
	}
	if alarm.EncryptionLevel != protocol.Encryption1RTT {
		t.Errorf("alarm encryption level = %v, want 1-RTT", alarm.EncryptionLevel)
	}
}

// TestLossAlarmCancelledWhenAllPathsIdle is the control: widening the check to
// every path must not arm an alarm that should stay cancelled.
func TestLossAlarmCancelledWhenAllPathsIdle(t *testing.T) {
	h, _ := newOracleSentHandler(t)
	now := monotime.Now()

	if err := h.AddPath(protocol.PathID(1)); err != nil {
		t.Fatalf("AddPath(1): %v", err)
	}
	pn := h.PopPacketNumberForPath(protocol.PathID(1))
	h.SentPacketForPath(now, pn, protocol.InvalidPacketNumber, protocol.PathID(1),
		nil, []Frame{ackElicitingFrame()}, protocol.ECNNon, 1000, false)
	if _, err := h.ReceivedAckForPath(ackFrameForPN(pn), protocol.PathID(1), now); err != nil {
		t.Fatalf("ReceivedAckForPath: %v", err)
	}

	if got := h.lossDetectionTime(now); !got.Time.IsZero() {
		t.Errorf("alarm armed after every path drained: %v", got.Time)
	}
}
