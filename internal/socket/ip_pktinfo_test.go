package socket_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/socket"
)

// lanIPv4 returns a unicast IPv4 address of a non-loopback interface that is
// up, or skips the test.
func lanIPv4(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("interfaces: %v", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap()
			if ip.Is4() && ip.IsGlobalUnicast() || ip.Is4() && ip.IsPrivate() {
				return ip
			}
		}
	}
	t.Skip("no non-loopback IPv4 interface address")
	return netip.Addr{}
}

// TestIpTransportRepliesFromArrivalAddress checks that a wildcard-bound
// socket answers from the local address a datagram arrived on, not from the
// address the kernel picks by route. The client sends from 127.0.0.1 to the
// host's LAN address; by route the reply would leave from 127.0.0.1, and a
// QUIC peer would then see a packet from an address it never dialed.
func TestIpTransportRepliesFromArrivalAddress(t *testing.T) {
	lan := lanIPv4(t)

	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port

	sock := socket.NewSocket()
	m := socket.NewMagicConn(sock, udp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Serve(ctx)
	defer m.Close()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server := netip.AddrPortFrom(lan, uint16(port))
	if _, err := client.WriteToUDPAddrPort([]byte("ping"), server); err != nil {
		t.Skipf("cannot send from loopback to %s: %v", server, err)
	}

	m.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, from, err := m.ReadFrom(buf)
	if err != nil {
		t.Skipf("no datagram from loopback to %s arrived: %v", server, err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("received %q", buf[:n])
	}
	if _, err := m.WriteTo([]byte("pong"), from); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	rn, replyFrom, err := client.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:rn]) != "pong" {
		t.Fatalf("reply %q", buf[:rn])
	}
	if replyFrom != server {
		t.Fatalf("reply came from %s, want the arrival address %s", replyFrom, server)
	}
}
