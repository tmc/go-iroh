package iroh

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

type testHooks struct {
	before func(context.Context, netaddr.EndpointAddr, string) error
	after  func(context.Context, *Conn) error
}

func (h testHooks) BeforeConnect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error {
	if h.before != nil {
		return h.before(ctx, addr, alpn)
	}
	return nil
}

func (h testHooks) AfterHandshake(ctx context.Context, conn *Conn) error {
	if h.after != nil {
		return h.after(ctx, conn)
	}
	return nil
}

func TestEndpointHooksRejectBeforeConnect(t *testing.T) {
	ctx := context.Background()
	client, err := Bind(ctx, WithHooks(testHooks{
		before: func(context.Context, netaddr.EndpointAddr, string) error {
			return ErrConnectRejected
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	sk, _ := key.GenerateSecretKey()
	addr := netaddr.NewEndpointAddr(sk.Public().EndpointID()).WithIP(netip.MustParseAddrPort("127.0.0.1:1"))
	if _, err := client.Connect(ctx, addr, "iroh-hooks/0"); !errors.Is(err, ErrConnectRejected) {
		t.Fatalf("Connect err = %v, want ErrConnectRejected", err)
	}
}

func TestEndpointHooksRejectAfterHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-hooks/0"
	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithHooks(testHooks{
			after: func(context.Context, *Conn) error {
				return RejectHandshake(77, "blocked")
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(ctx)
		accepted <- err
	}()

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	if err := <-accepted; !errors.Is(err, ErrHandshakeRejected) {
		t.Fatalf("Accept err = %v, want ErrHandshakeRejected", err)
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client did not observe hook rejection close")
	}
}

// TestEndpointHooksAfterHandshakeBothSides pins that AfterHandshake fires for
// accepted connections as well as dialed ones, and that Conn.Side tells them
// apart. A hook installed on a server sees connections the server never dialed.
func TestEndpointHooksAfterHandshakeBothSides(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-hooks/0"
	sides := make(chan Side, 2)
	record := testHooks{after: func(_ context.Context, conn *Conn) error {
		sides <- conn.Side()
		return nil
	}}

	server, err := Bind(ctx,
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithHooks(record),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(ctx)
		accepted <- err
	}()

	client, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithHooks(record),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if err := <-accepted; err != nil {
		t.Fatalf("Accept: %v", err)
	}

	var got []Side
	for range 2 {
		select {
		case s := <-sides:
			got = append(got, s)
		case <-time.After(5 * time.Second):
			t.Fatalf("AfterHandshake ran %d times, want 2 (client and server)", len(got))
		}
	}
	slices.Sort(got)
	if want := []Side{SideClient, SideServer}; !slices.Equal(got, want) {
		t.Errorf("AfterHandshake sides = %v, want %v", got, want)
	}
}
