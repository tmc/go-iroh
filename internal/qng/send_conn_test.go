package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/udp"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestPacketInfoOOBReservesControlMessageSpace(t *testing.T) {
	oob := packetInfoOOB(udp.PacketInfo{})
	if got := cap(oob) - len(oob); got < 64 {
		t.Fatalf("packetInfoOOB spare capacity = %d, want at least 64", got)
	}
}

func TestPacketHasDatagram(t *testing.T) {
	tests := []struct {
		name  string
		frame wire.Frame
		want  bool
	}{
		{name: "ping", frame: &wire.PingFrame{}},
		{name: "datagram", frame: &wire.DatagramFrame{}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := shortHeaderPacket{Frames: []ackhandler.Frame{{Frame: tt.frame}}}
			if got := packetHasDatagram(p); got != tt.want {
				t.Fatalf("packetHasDatagram = %v, want %v", got, tt.want)
			}
		})
	}
}
