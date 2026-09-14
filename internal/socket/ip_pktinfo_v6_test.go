package socket

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// pingWildcard binds a MagicConn to the wildcard address of network, sends it
// a datagram from a client bound to clientIP, and waits for it to arrive.
func pingWildcard(t *testing.T, network string, wildcard, clientIP net.IP, server netip.Addr) (*MagicConn, *net.UDPConn) {
	t.Helper()
	udp, err := net.ListenUDP(network, &net.UDPAddr{IP: wildcard})
	if err != nil {
		t.Skipf("listen %s: %v", network, err)
	}
	t.Cleanup(func() { udp.Close() })
	m := NewMagicConn(NewSocket(), udp)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go m.Serve(ctx)
	t.Cleanup(func() { m.Close() })
	if !m.transports.ip.pktinfo {
		t.Skip("packet info not available on a wildcard socket")
	}
	client, err := net.ListenUDP(network, &net.UDPAddr{IP: clientIP})
	if err != nil {
		t.Skipf("listen client: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	dst := netip.AddrPortFrom(server, uint16(udp.LocalAddr().(*net.UDPAddr).Port))
	if _, err := client.WriteToUDPAddrPort([]byte("ping"), dst); err != nil {
		t.Skipf("send to %s: %v", dst, err)
	}
	m.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if _, _, err := m.ReadFrom(buf); err != nil {
		t.Fatalf("no datagram from %s arrived: %v", client.LocalAddr(), err)
	}
	return m, client
}

// roundTrip checks that m recorded client's arrival address as want and that
// a reply to client is delivered.
func roundTrip(t *testing.T, m *MagicConn, client *net.UDPConn, want netip.Addr) {
	t.Helper()
	clientAddr := canonicalAddrPort(client.LocalAddr().(*net.UDPAddr).AddrPort())
	m.transports.ip.localMu.Lock()
	la, ok := m.transports.ip.local[clientAddr]
	m.transports.ip.localMu.Unlock()
	if !ok || la.addr != want {
		t.Fatalf("arrival address for %s = %+v, %v; want %s", clientAddr, la, ok, want)
	}
	if la.cmsg == nil {
		t.Fatalf("no packet-info message built for %s from %s", clientAddr, want)
	}
	if _, err := m.WriteTo([]byte("pong"), client.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, from, err := client.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("reply %q", buf[:n])
	}
	if from.Addr().Unmap() != want {
		t.Fatalf("reply came from %s, want %s", from, want)
	}
}

// TestIpTransportRecordsIPv6ArrivalAddress checks that IPv6 packet info is
// parsed and answered from.
func TestIpTransportRecordsIPv6ArrivalAddress(t *testing.T) {
	m, client := pingWildcard(t, "udp6", net.IPv6zero, net.IPv6loopback, netip.IPv6Loopback())
	roundTrip(t, m, client, netip.IPv6Loopback())
}

// TestIpTransportRecordsDualStackArrivalAddress checks that IPv4 traffic on
// a dual-stack socket is recorded with its IPv4 arrival address, whichever
// level the kernel reports it at.
func TestIpTransportRecordsDualStackArrivalAddress(t *testing.T) {
	m, client := pingWildcard(t, "udp", net.IPv6zero, net.IPv4(127, 0, 0, 1), netip.AddrFrom4([4]byte{127, 0, 0, 1}))
	roundTrip(t, m, client, netip.AddrFrom4([4]byte{127, 0, 0, 1}))
}
