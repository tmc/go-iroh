package ackhandler

import (
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
)

// These tests pin the behavior of the flat-field ReceivedPacketHandler so the
// Stage 4a refactor (routing 0-RTT/1-RTT through a single-entry appDataPaths
// map keyed by protocol.PathIDZero) can be shown to be a behavioral no-op.

func newOracleReceivedHandler() *ReceivedPacketHandler {
	return NewReceivedPacketHandler(utils.DefaultLogger)
}

// TestReceivedPacketHandlerDuplicateDetection pins IsPotentiallyDuplicate across
// all three packet number spaces, including before and after a packet has been
// received. After the refactor, the 0-RTT/1-RTT cases route through the map.
func TestReceivedPacketHandlerDuplicateDetection(t *testing.T) {
	tests := []struct {
		name     string
		encLevel protocol.EncryptionLevel
	}{
		{"initial", protocol.EncryptionInitial},
		{"handshake", protocol.EncryptionHandshake},
		{"1-RTT", protocol.Encryption1RTT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newOracleReceivedHandler()
			now := monotime.Now()

			// A packet not yet seen is not a duplicate.
			if h.IsPotentiallyDuplicate(10, tt.encLevel) {
				t.Errorf("pn 10 reported duplicate before being received")
			}
			if err := h.ReceivedPacket(10, protocol.ECNNon, tt.encLevel, now, true); err != nil {
				t.Fatalf("ReceivedPacket: %v", err)
			}
			// The same packet number is now potentially duplicate.
			if !h.IsPotentiallyDuplicate(10, tt.encLevel) {
				t.Errorf("pn 10 not reported duplicate after being received")
			}
			// A different packet number is not.
			if h.IsPotentiallyDuplicate(11, tt.encLevel) {
				t.Errorf("pn 11 reported duplicate although never received")
			}
		})
	}
}

// TestReceivedPacketHandlerAppDataAckFrame pins that received 1-RTT packets are
// surfaced in an ACK frame from the appData space, including the correct
// largest/lowest acked. After the refactor this comes from the PathIDZero map
// entry.
func TestReceivedPacketHandlerAppDataAckFrame(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	for _, pn := range []protocol.PacketNumber{0, 1, 2} {
		if err := h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
			t.Fatalf("ReceivedPacket(%d): %v", pn, err)
		}
	}

	// onlyIfQueued=false forces an ACK frame even if no ack is queued yet.
	ack := h.GetAckFrame(protocol.Encryption1RTT, now, false)
	if ack == nil {
		t.Fatalf("expected an ACK frame for received 1-RTT packets")
	}
	if got := ack.LargestAcked(); got != 2 {
		t.Errorf("largest acked = %d, want 2", got)
	}
	if got := ack.LowestAcked(); got != 0 {
		t.Errorf("lowest acked = %d, want 0", got)
	}
}

func TestReceivedPacketHandlerAppDataAckDecimation(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	for pn := protocol.PacketNumber(0); pn < packetsBeforeAck-1; pn++ {
		if err := h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
			t.Fatalf("ReceivedPacket(%d): %v", pn, err)
		}
		if ack := h.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil {
			t.Fatalf("ack queued after %d packets; want none before %d", pn+1, packetsBeforeAck)
		}
	}

	pn := protocol.PacketNumber(packetsBeforeAck - 1)
	if err := h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
		t.Fatalf("ReceivedPacket(%d): %v", pn, err)
	}
	ack := h.GetAckFrame(protocol.Encryption1RTT, now, true)
	if ack == nil {
		t.Fatalf("ack not queued after %d packets", packetsBeforeAck)
	}
	if got := ack.LargestAcked(); got != pn {
		t.Fatalf("largest acked = %d, want %d", got, pn)
	}
}

// TestReceivedPacketHandlerInitialHandshakeUnchanged pins that the
// Initial/Handshake spaces are independent from the appData space: an ACK frame
// for one space does not surface packet numbers from another, and dropping a
// space removes its ACK frame. These spaces are NOT moved into the path map by
// Stage 4a, so their behavior must remain byte-identical.
func TestReceivedPacketHandlerInitialHandshakeUnchanged(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	if err := h.ReceivedPacket(0, protocol.ECNNon, protocol.EncryptionInitial, now, true); err != nil {
		t.Fatalf("ReceivedPacket initial: %v", err)
	}
	if err := h.ReceivedPacket(0, protocol.ECNNon, protocol.EncryptionHandshake, now, true); err != nil {
		t.Fatalf("ReceivedPacket handshake: %v", err)
	}

	initialAck := h.GetAckFrame(protocol.EncryptionInitial, now, false)
	if initialAck == nil || initialAck.LargestAcked() != 0 {
		t.Fatalf("initial ack = %v, want largest acked 0", initialAck)
	}
	handshakeAck := h.GetAckFrame(protocol.EncryptionHandshake, now, false)
	if handshakeAck == nil || handshakeAck.LargestAcked() != 0 {
		t.Fatalf("handshake ack = %v, want largest acked 0", handshakeAck)
	}

	// No 1-RTT packets received: appData ack must be nil even with
	// onlyIfQueued=false.
	if appAck := h.GetAckFrame(protocol.Encryption1RTT, now, false); appAck != nil {
		t.Errorf("expected nil appData ack, got %v", appAck)
	}

	// Drop Initial: its ACK frame must become nil while Handshake is unaffected.
	h.DropPackets(protocol.EncryptionInitial)
	if appAck := h.GetAckFrame(protocol.EncryptionInitial, now, false); appAck != nil {
		t.Errorf("expected nil initial ack after drop, got %v", appAck)
	}
	if !h.IsPotentiallyDuplicate(0, protocol.EncryptionHandshake) {
		t.Errorf("handshake pn 0 should still be tracked after dropping initial")
	}
}

// TestReceivedPacketHandler0RTTAfter1RTTOrderingError pins the global
// lowest1RTTPacket ordering guard: a 0-RTT packet with a packet number above an
// already-received 1-RTT packet is rejected. (This field is connection-global
// today; Stage 4a keeps it so, see spec risk #7.)
func TestReceivedPacketHandler0RTTAfter1RTTOrderingError(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	if err := h.ReceivedPacket(5, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
		t.Fatalf("ReceivedPacket 1-RTT: %v", err)
	}
	// A 0-RTT packet numbered above the lowest 1-RTT packet is an ordering
	// violation.
	if err := h.ReceivedPacket(6, protocol.ECNNon, protocol.Encryption0RTT, now, true); err == nil {
		t.Errorf("expected ordering error for 0-RTT pn 6 after 1-RTT pn 5")
	}
	// A 0-RTT packet below the lowest 1-RTT packet is fine.
	if err := h.ReceivedPacket(4, protocol.ECNNon, protocol.Encryption0RTT, now, true); err != nil {
		t.Errorf("unexpected error for 0-RTT pn 4 below 1-RTT pn 5: %v", err)
	}
}

// TestReceivedPacketHandlerIgnoreBelow pins IgnorePacketsBelow on the appData
// space (the path that becomes map-routed in 4a).
func TestReceivedPacketHandlerIgnoreBelow(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	for _, pn := range []protocol.PacketNumber{0, 1, 2, 3} {
		if err := h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
			t.Fatalf("ReceivedPacket(%d): %v", pn, err)
		}
	}
	h.IgnorePacketsBelow(2)

	ack := h.GetAckFrame(protocol.Encryption1RTT, now, false)
	if ack == nil {
		t.Fatalf("expected an ACK frame")
	}
	if got := ack.LowestAcked(); got != 2 {
		t.Errorf("lowest acked after IgnorePacketsBelow(2) = %d, want 2", got)
	}
	if got := ack.LargestAcked(); got != 3 {
		t.Errorf("largest acked = %d, want 3", got)
	}
}

func TestReceivedPacketHandlerAckFrequencyParams(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	// Default threshold is 10 (packetsBeforeAck).
	for pn := protocol.PacketNumber(0); pn < 9; pn++ {
		if err := h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
			t.Fatalf("ReceivedPacket(%d): %v", pn, err)
		}
	}
	if ack := h.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil {
		t.Fatalf("unexpected ACK queued before threshold")
	}

	// Update threshold to 20.
	h.SetAckFrequencyParams(20, 50*time.Millisecond, 1, now)

	// Sending packet 9 (10th packet) should not queue ACK under threshold 20.
	if err := h.ReceivedPacket(9, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
		t.Fatalf("ReceivedPacket(9): %v", err)
	}
	if ack := h.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil {
		t.Fatalf("unexpected ACK queued under new threshold 20")
	}

	// Send up to 19 packets total (indices 10..19).
	for pn := protocol.PacketNumber(10); pn < 19; pn++ {
		if err := h.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
			t.Fatalf("ReceivedPacket(%d): %v", pn, err)
		}
	}
	if ack := h.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil {
		t.Fatalf("unexpected ACK queued at 19 packets")
	}

	// 20th packet (pn 19) hits threshold 20 and queues ACK.
	if err := h.ReceivedPacket(19, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
		t.Fatalf("ReceivedPacket(19): %v", err)
	}
	ack := h.GetAckFrame(protocol.Encryption1RTT, now, true)
	if ack == nil {
		t.Fatalf("expected ACK queued at 20 packets")
	}
	if ack.LargestAcked() != 19 {
		t.Fatalf("largest acked = %d, want 19", ack.LargestAcked())
	}
}

func TestReceivedPacketHandlerImmediateAck(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	// Receive 1 packet; under default threshold 10, no ACK is queued immediately.
	if err := h.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
		t.Fatalf("ReceivedPacket(0): %v", err)
	}
	if ack := h.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil {
		t.Fatalf("unexpected ACK queued before IMMEDIATE_ACK")
	}

	// Immediate ACK required forces ACK to be queued.
	h.SetImmediateAckRequired()
	ack := h.GetAckFrame(protocol.Encryption1RTT, now, true)
	if ack == nil {
		t.Fatalf("expected ACK after SetImmediateAckRequired")
	}
	if ack.LargestAcked() != 0 {
		t.Fatalf("largest acked = %d, want 0", ack.LargestAcked())
	}
}

func TestReceivedPacketHandlerReorderingThresholdZero(t *testing.T) {
	h := newOracleReceivedHandler()
	now := monotime.Now()

	// Reordering threshold 0 disables early ACK on reordering.
	h.SetAckFrequencyParams(10, 25*time.Millisecond, 0, now)

	// Receive packet 0 then packet 2 (gap: packet 1 missing).
	if err := h.ReceivedPacket(0, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
		t.Fatalf("ReceivedPacket(0): %v", err)
	}
	if err := h.ReceivedPacket(2, protocol.ECNNon, protocol.Encryption1RTT, now, true); err != nil {
		t.Fatalf("ReceivedPacket(2): %v", err)
	}
	// With threshold 0, gap does not trigger immediate ACK.
	if ack := h.GetAckFrame(protocol.Encryption1RTT, now, true); ack != nil {
		t.Fatalf("reorderingThreshold 0 queued ACK on gap, want none")
	}
}
