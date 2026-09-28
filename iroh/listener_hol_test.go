package iroh

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// TestStreamListenerSlowPeerDoesNotBlockOthers pins that one peer whose
// handshake is slow to finish does not hold up the listener for other peers.
func TestStreamListenerSlowPeerDoesNotBlockOthers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "iroh-listener-hol/0"
	loopback := WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0))
	slow, err := Bind(ctx, loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Shutdown(ctx)
	fast, err := Bind(ctx, loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer fast.Shutdown(ctx)

	release := make(chan struct{})
	defer close(release)
	server, err := Bind(ctx, WithALPNs(alpn), loopback, WithHooks(testHooks{
		after: func(ctx context.Context, conn *Conn) error {
			if conn.RemoteID().Equal(slow.ID()) {
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
			return nil
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	go slow.Connect(ctx, addr, alpn)
	time.Sleep(200 * time.Millisecond) // let the slow peer reach the hook first

	c, err := fast.Dial(ctx, addr, alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		a, err := ln.Accept()
		if err == nil {
			a.Close()
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a peer stalled in AfterHandshake blocked the listener for others")
	}
}
