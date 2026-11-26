package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// pendingAckFrameSource always has an ACK to send, and nothing else.
type pendingAckFrameSource struct{}

func (pendingAckFrameSource) GetAckFrame(protocol.EncryptionLevel, monotime.Time, bool) *wire.AckFrame {
	return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
}

func (pendingAckFrameSource) GetAckFrameForPath(protocol.PathID, monotime.Time, bool) *wire.AckFrame {
	return nil
}

// TestCryptoPTOProbeWithPendingAckIsAckEliciting checks that a crypto PTO probe
// packed when the only thing to send is an ACK still carries an ack-eliciting
// frame. An ACK-only probe never draws an ACK back, so it cannot detect the
// loss it was sent to probe for.
func TestCryptoPTOProbeWithPendingAckIsAckEliciting(t *testing.T) {
	p := &packetPacker{
		getDestConnID:       func() protocol.ConnectionID { return protocol.ConnectionID{} },
		pnManager:           &qntProbePNManager{pn: 1},
		acks:                pendingAckFrameSource{},
		retransmissionQueue: newRetransmissionQueue(),
		cryptoStreamManager: newCryptoStreamManager(protocol.PerspectiveClient),
	}
	_, pl := p.maybeGetCryptoPacket(1200, protocol.EncryptionHandshake, monotime.Now(), true, false, protocol.Version1)
	if pl.ack == nil {
		t.Fatal("packed no ACK, so the probe is not the ACK-only case under test")
	}
	if !ackhandler.HasAckElicitingFrames(pl.frames) {
		t.Fatalf("probe payload has %d frames and none is ack-eliciting", len(pl.frames))
	}
}

// TestAppDataPTOProbeWithPendingAckIsAckEliciting is the 1-RTT counterpart of
// TestCryptoPTOProbeWithPendingAckIsAckEliciting.
func TestAppDataPTOProbeWithPendingAckIsAckEliciting(t *testing.T) {
	p := &packetPacker{
		getDestConnID:        func() protocol.ConnectionID { return protocol.ConnectionID{} },
		getDestConnIDForPath: func(protocol.PathID) (protocol.ConnectionID, bool) { return protocol.ConnectionID{}, true },
		cryptoSetup:          qntProbeCryptoSetup{},
		pnManager:            &qntProbePNManager{pn: 1},
		framer:               newFramer(noopConnFC()),
		acks:                 pendingAckFrameSource{},
		retransmissionQueue:  newRetransmissionQueue(),
	}
	packet, err := p.packPTOProbePacket1RTT(1200, false, monotime.Now(), protocol.Version1)
	if err != nil {
		t.Fatal(err)
	}
	if packet == nil || packet.shortHdrPacket == nil {
		t.Fatal("packed no 1-RTT probe packet")
	}
	if packet.shortHdrPacket.Ack == nil {
		t.Fatal("packed no ACK, so the probe is not the ACK-only case under test")
	}
	if !packet.shortHdrPacket.IsAckEliciting() {
		t.Fatal("1-RTT probe packet is not ack-eliciting")
	}
}
