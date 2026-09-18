package iroh

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// TestStreamListenerSurvivesRejectedPeer pins that a peer rejected by an
// AfterHandshake hook does not stop the listener: an authorized peer must still
// be admitted by the same StreamListener afterwards.
func TestStreamListenerSurvivesRejectedPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "iroh-listener-reject/0"

	authorized, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer authorized.Shutdown(ctx)

	server, err := Bind(ctx, WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithHooks(testHooks{
			after: func(_ context.Context, conn *Conn) error {
				if !conn.RemoteID().Equal(authorized.ID()) {
					return RejectHandshake(77, "unauthorized endpoint")
				}
				return nil
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	ln, err := server.ListenStreams()
	if err != nil {
		t.Fatalf("ListenStreams: %v", err)
	}
	defer ln.Close()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	// An unauthorized peer completes the handshake and is rejected by the hook.
	attacker, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Shutdown(ctx)
	if conn, err := attacker.Connect(ctx, addr, alpn); err == nil {
		defer conn.CloseWithError(0, "")
		select {
		case <-conn.Context().Done():
		case <-time.After(10 * time.Second):
			t.Fatal("rejected peer did not observe hook rejection close")
		}
	}

	// The listener must still admit the authorized peer.
	accepted := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer c.Close()
		_, err = io.Copy(c, c)
		accepted <- err
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()
	c, err := authorized.Dial(dialCtx, addr, alpn)
	if err != nil {
		select {
		case lerr := <-accepted:
			t.Fatalf("Dial: %v; listener: %v", err, lerr)
		default:
			t.Fatalf("Dial: %v", err)
		}
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// A listener stopped by the rejection never accepts this stream, so bound
	// the read rather than waiting out the test deadline.
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	var buf [4]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		t.Fatalf("ReadFull: %v (listener did not admit the authorized peer)", err)
	}
	if got := string(buf[:]); got != "ping" {
		t.Fatalf("echo = %q, want %q", got, "ping")
	}
	c.Close()
	if err := <-accepted; err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Accept: %v", err)
	}
}

// TestStreamListenerStopsOnEndpointShutdown pins the other side of the accept
// classification: an endpoint that can never accept another connection must
// stop the listener rather than retry forever.
func TestStreamListenerStopsOnEndpointShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, tt := range []struct {
		name     string
		alpns    []string
		shutdown bool
	}{
		{name: "shutdown", alpns: []string{"iroh-listener-shutdown/0"}, shutdown: true},
		{name: "no alpns"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := Bind(ctx, WithALPNs(tt.alpns...),
				WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer ep.Shutdown(ctx)

			ln, err := ep.ListenStreams()
			if err != nil {
				t.Fatalf("ListenStreams: %v", err)
			}
			defer ln.Close()

			if tt.shutdown {
				if err := ep.Shutdown(ctx); err != nil {
					t.Fatalf("Shutdown: %v", err)
				}
			}
			done := make(chan error, 1)
			go func() {
				_, err := ln.Accept()
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Accept succeeded on an endpoint that cannot accept")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Accept did not return")
			}
		})
	}
}
