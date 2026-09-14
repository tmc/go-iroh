package socket

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

// pktinfoBenchConn returns a wildcard-bound MagicConn that has received a
// datagram from a loopback client, so the client's arrival address is
// recorded, with the client and its address.
func pktinfoBenchConn(b *testing.B) (*MagicConn, *net.UDPConn, netip.AddrPort) {
	b.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { udp.Close() })
	m := NewMagicConn(NewSocket(), udp)
	ctx, cancel := context.WithCancel(context.Background())
	b.Cleanup(cancel)
	go m.Serve(ctx)
	b.Cleanup(func() { m.Close() })
	if !m.transports.ip.pktinfo {
		b.Skip("packet info not available on a wildcard socket")
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { client.Close() })
	server := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(udp.LocalAddr().(*net.UDPAddr).Port))
	if _, err := client.WriteToUDPAddrPort([]byte("ping"), server); err != nil {
		b.Fatal(err)
	}
	m.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if _, _, err := m.ReadFrom(buf); err != nil {
		b.Fatal(err)
	}
	m.SetReadDeadline(time.Time{})
	return m, client, client.LocalAddr().(*net.UDPAddr).AddrPort()
}

func BenchmarkIpTransportSend(b *testing.B) {
	m, _, clientAddr := pktinfoBenchConn(b)
	payload := make([]byte, 1200)

	b.Run("recorded", func(b *testing.B) {
		dst := net.UDPAddrFromAddrPort(clientAddr)
		b.ReportAllocs()
		for b.Loop() {
			m.WriteTo(payload, dst)
		}
		b.StopTimer()
		if n := m.metrics.blackholed.Load(); n != 0 {
			b.Fatalf("%d sends blackholed", n)
		}
		if m.transports.ip.packetInfoFor(clientAddr) == nil {
			b.Fatal("arrival address was dropped during the benchmark")
		}
	})

	b.Run("unrecorded", func(b *testing.B) {
		other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			b.Fatal(err)
		}
		defer other.Close()
		dst := other.LocalAddr().(*net.UDPAddr)
		b.ReportAllocs()
		for b.Loop() {
			m.WriteTo(payload, dst)
		}
		b.StopTimer()
		if n := m.metrics.blackholed.Load(); n != 0 {
			b.Fatalf("%d sends blackholed", n)
		}
	})
}

// BenchmarkIpTransportRecordLocal measures recording an arrival address from
// control messages the kernel delivered.
func BenchmarkIpTransportRecordLocal(b *testing.B) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		b.Fatal(err)
	}
	defer udp.Close()
	t := NewIpTransport(udp, make(chan recvBatch, 1))
	if !t.pktinfo {
		b.Skip("packet info not available on a wildcard socket")
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()
	server := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(udp.LocalAddr().(*net.UDPAddr).Port))
	if _, err := client.WriteToUDPAddrPort([]byte("ping"), server); err != nil {
		b.Fatal(err)
	}
	buf, oob := make([]byte, 64), make([]byte, maxControlSize)
	udp.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, oobn, _, from, err := udp.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		b.Fatal(err)
	}
	oob = oob[:oobn]
	la, ok := parsePacketInfo(oob)
	if !ok || la.addr != server.Addr() {
		b.Fatalf("parsePacketInfo(%d bytes) = %+v, %v; want %s", oobn, la, ok, server.Addr())
	}
	b.ReportAllocs()
	for b.Loop() {
		t.recordLocal(from, oob)
	}
}

// BenchmarkIpTransportWithPacketInfo measures the control-message merge on
// the segmented (GSO) send path.
func BenchmarkIpTransportWithPacketInfo(b *testing.B) {
	m, _, clientAddr := pktinfoBenchConn(b)
	oob := make([]byte, 24) // stands in for a UDP_SEGMENT control message
	b.ReportAllocs()
	for b.Loop() {
		var cbuf [maxControlSize]byte
		_ = m.transports.ip.withPacketInfo(clientAddr, oob, cbuf[:0])
	}
}
