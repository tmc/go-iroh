//go:build linux

package socket

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func testLANIPv4(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("interfaces: %v", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if pfx, err := netip.ParsePrefix(a.String()); err == nil && pfx.Addr().Unmap().Is4() {
				return pfx.Addr().Unmap()
			}
		}
	}
	t.Skip("no non-loopback IPv4 interface address")
	return netip.Addr{}
}

// TestMagicConnWriteMsgUDPKeepsArrivalAddress checks that a segmented (GSO)
// send to a peer that reached a wildcard socket carries the packet-info
// control message next to UDP_SEGMENT, so every segment leaves from the
// address the peer sent to.
func TestMagicConnWriteMsgUDPKeepsArrivalAddress(t *testing.T) {
	lan := testLANIPv4(t)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	sock := NewSocket()
	m := NewMagicConn(sock, udp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.Serve(ctx)
	defer m.Close()
	if !m.transports.ip.pktinfo {
		t.Fatal("packet info not enabled on a wildcard socket")
	}

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := netip.AddrPortFrom(lan, uint16(udp.LocalAddr().(*net.UDPAddr).Port))
	if _, err := client.WriteToUDPAddrPort([]byte("ping"), server); err != nil {
		t.Skipf("cannot send from loopback to %s: %v", server, err)
	}
	m.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if _, _, err := m.ReadFrom(buf); err != nil {
		t.Skipf("no datagram from loopback to %s arrived: %v", server, err)
	}

	payload := []byte("abcdefg")
	if _, _, err := m.WriteMsgUDP(payload, udpSegmentMessage(3), client.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	var got []string
	for range 3 {
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := client.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("segment %d: %v", len(got), err)
		}
		if from != server {
			t.Fatalf("segment %d came from %s, want %s", len(got), from, server)
		}
		got = append(got, string(buf[:n]))
	}
	if want := []string{"abc", "def", "g"}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("segments %q, want %q", got, want)
	}
}
