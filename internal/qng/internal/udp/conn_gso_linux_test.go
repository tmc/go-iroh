//go:build linux

package udp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// gsoOnlyPacketConn exposes net.PacketConn + SyscallConn + WriteMsgUDP without
// ReadMsgUDP/SetReadBuffer, matching MagicConn's send-only GSO surface.
type gsoOnlyPacketConn struct {
	net.PacketConn
	udp *net.UDPConn
}

func (c *gsoOnlyPacketConn) SyscallConn() (syscall.RawConn, error) {
	return c.udp.SyscallConn()
}

func (c *gsoOnlyPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	return c.udp.WriteMsgUDP(b, oob, addr)
}

func TestIsGSOError(t *testing.T) {
	syscallErr := os.NewSyscallError("sendmsg", unix.EIO)
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"bare EIO syscall error", syscallErr, true},
		{"wrapped in net.OpError", &net.OpError{Op: "write", Net: "udp", Err: syscallErr}, true},
		{"wrapped twice", fmt.Errorf("send: %w", &net.OpError{Op: "write", Err: syscallErr}), true},
		{"different errno", os.NewSyscallError("sendmsg", unix.EPERM), false},
		{"bare errno, not a syscall error", unix.EIO, false},
		{"unrelated error", errors.New("boom"), false},
	}
	for _, tt := range tests {
		if got := IsGSOError(tt.err); got != tt.want {
			t.Errorf("IsGSOError(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestGSOSendConnSplitsSmallBatch(t *testing.T) {
	sender, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	receiver, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	conn := &gsoSendConn{basicConn: &basicConn{PacketConn: sender}}
	if n, err := conn.WritePacket([]byte("abcdefg"), receiver.LocalAddr(), nil, 3, protocol.ECNUnsupported); err != nil {
		t.Fatal(err)
	} else if n != 7 {
		t.Fatalf("WritePacket wrote %d bytes, want 7", n)
	}
	for _, want := range []string{"abc", "def", "g"} {
		buf := make([]byte, 8)
		n, _, err := receiver.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buf[:n]); got != want {
			t.Fatalf("ReadFromUDP = %q, want %q", got, want)
		}
	}
}

func TestWrapGSOSendOnly(t *testing.T) {
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	m := &gsoOnlyPacketConn{PacketConn: pc, udp: pc}
	raw, err := m.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if !isGSOEnabled(raw) {
		t.Skip("UDP GSO is unavailable")
	}

	conn, err := Wrap(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*gsoSendConn); !ok {
		t.Fatalf("Wrap returned %T, want *gsoSendConn", conn)
	}
	capabilities := conn.Capabilities()
	if !capabilities.GSO {
		t.Fatal("GSO is disabled")
	}
	if capabilities.ECN {
		t.Fatal("ECN is enabled without an OOB receive path")
	}
}

func TestWrapGSOSendDisabled(t *testing.T) {
	t.Setenv("QUIC_GO_DISABLE_GSO", "true")
	pc, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	m := &gsoOnlyPacketConn{PacketConn: pc, udp: pc}

	conn, err := Wrap(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*basicConn); !ok {
		t.Fatalf("Wrap returned %T, want *basicConn", conn)
	}
}
