package netreport

// Coverage for WithQADDialer: a probe must measure the mapping of the socket
// the dialer rides, and closing the probe must leave that socket alone.

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
)

// TestQADDialerSharesCallerTransport: the observed address is the dialer
// transport's own address (on loopback, its bound ip:port); round two proves
// close left the shared transport usable.
func TestQADDialerSharesCallerTransport(t *testing.T) {
	serverAddr, stop := startLoopbackQADWithConfig(t, net.IPv4(127, 0, 0, 1), &quic.Config{
		SendObservedAddressReports: true,
		KeepAlivePeriod:            100 * time.Millisecond,
		MaxIdleTimeout:             qadMaxIdle,
	})
	defer stop()

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer udpConn.Close()
	tr := &quic.Transport{Conn: udpConn}
	defer tr.Close()

	c := NewClient(nil).
		WithQADTLSConfig(&tls.Config{InsecureSkipVerify: true}).
		WithQADDialer(func(ctx context.Context, addr netip.AddrPort, tlsConf *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return tr.Dial(ctx, net.UDPAddrFromAddrPort(addr), tlsConf, cfg)
		})

	ap := udpConn.LocalAddr().(*net.UDPAddr).AddrPort()
	want := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	ctx := context.Background()
	for round := range 2 {
		qad, err := c.dialQAD(ctx, serverAddr, "relay.iroh.invalid")
		if err != nil {
			t.Fatalf("round %d: dialQAD: %v", round, err)
		}
		got, err := qad.observedAddr(ctx)
		if err != nil {
			t.Fatalf("round %d: observedAddr: %v", round, err)
		}
		if got != want {
			t.Fatalf("round %d: observedAddr = %v, want the shared transport's address %v", round, got, want)
		}
		if err := qad.close(qadCloseCode, qadCloseReason); err != nil {
			t.Fatalf("round %d: close: %v", round, err)
		}
	}
}
