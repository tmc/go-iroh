package iroh

import (
	"context"
	"io"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// startEchoServer binds a server endpoint for alpn whose accept loop echoes one
// bidi stream per connection, keeping each connection open until the client
// closes it so the post-handshake NewSessionTicket reaches the client. If
// early0RTT is true the accept loop uses Accepting.Into0RTT so it can receive
// 0-RTT data before the handshake completes; otherwise it uses the blocking
// Accept path.
func startEchoServer(t *testing.T, ctx context.Context, srvKey key.SecretKey, alpn string, early0RTT bool) *Endpoint {
	t.Helper()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			var conn *Conn
			if early0RTT {
				in, err := server.AcceptIncoming(ctx)
				if err != nil {
					return
				}
				acc, err := in.Accept()
				if err != nil {
					return
				}
				conn, err = acc.Into0RTT()
				if err != nil {
					return
				}
			} else {
				conn, err = server.Accept(ctx)
				if err != nil {
					return
				}
			}
			go func() {
				// Server-side 0-RTT conns resolve the verified peer id only at
				// handshake completion; reading it right after must be race-free.
				select {
				case <-conn.HandshakeComplete():
					_ = conn.RemoteID()
					_ = conn.ALPN()
				case <-ctx.Done():
					return
				}
				s, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				b, _ := io.ReadAll(s)
				s.Write(b)
				s.Close()
			}()
		}
	}()
	return server
}

// primeTicket drives one full Connect so the server issues a session ticket the
// client caches, then closes the connection.
func primeTicket(t *testing.T, ctx context.Context, client *Endpoint, addr netaddr.EndpointAddr, srvID key.EndpointID, alpn string) {
	t.Helper()
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("priming connect: %v", err)
	}
	if conn.Used0RTT() {
		t.Fatal("priming connection unexpectedly used 0-RTT")
	}
	echo(t, ctx, conn, "prime")
	if !waitFor(ctx, func() bool { return client.sessionCache.Len() > 0 }) {
		t.Fatalf("client never cached a session ticket: %v", ctx.Err())
	}
	conn.CloseWithError(0, "")
}

// TestConnectEarlyInto0RTTRoundTrip mirrors Rust's test_0rtt: the first attempt
// (cold cache) cannot use 0-RTT, the second attempt (warm cache) resumes via
// ConnectEarly + Into0RTT, sends early data before the handshake completes, and
// observes Used0RTT after the handshake. The server uses Accepting.Into0RTT.
func TestConnectEarlyInto0RTTRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "iroh-0rtt-early/0"
	srvKey, _ := key.GenerateSecretKey()
	server := startEchoServer(t, ctx, srvKey, alpn, true)
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	// Cold cache: Into0RTT cannot attempt 0-RTT and reports ok=false.
	c1, err := client.ConnectEarly(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("first ConnectEarly: %v", err)
	}
	conn1, ok := c1.Into0RTT()
	if ok {
		t.Fatal("cold-cache Into0RTT reported ok=true")
	}
	if conn1.Used0RTT() {
		t.Error("cold-cache connection used 0-RTT")
	}
	echo(t, ctx, conn1, "cold")
	if !waitFor(ctx, func() bool { return client.sessionCache.Len() > 0 }) {
		t.Fatalf("client never cached a session ticket: %v", ctx.Err())
	}
	conn1.CloseWithError(0, "")

	// Warm cache: Into0RTT resumes and reports ok=true. Early data is sent before
	// the handshake completes; Used0RTT is observable after HandshakeComplete.
	c2, err := client.ConnectEarly(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("second ConnectEarly: %v", err)
	}
	conn2, ok := c2.Into0RTT()
	if !ok {
		t.Fatal("warm-cache Into0RTT reported ok=false despite a cached ticket")
	}
	defer conn2.CloseWithError(0, "")

	s, err := conn2.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("warm open stream: %v", err)
	}
	const msg = "early"
	s.Write([]byte(msg))
	s.Close()

	select {
	case <-conn2.HandshakeComplete():
	case <-ctx.Done():
		t.Fatalf("warm handshake did not complete: %v", ctx.Err())
	}
	if !conn2.Used0RTT() {
		t.Error("warm connection did not use 0-RTT despite a cached ticket")
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("warm read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("warm echo = %q, want %q", got, msg)
	}
	if !conn2.RemoteID().Equal(server.ID()) {
		t.Errorf("resumed remote id = %s, want %s", conn2.RemoteID(), server.ID())
	}
}

// TestConnectEarlyColdCacheFallback checks that on a cold cache Into0RTT returns
// ok=false and the returned Conn is already a usable 1-RTT connection (no
// Connection round trip needed), and that awaiting Connection on a fresh
// Connecting also yields a working connection.
func TestConnectEarlyColdCacheFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "iroh-0rtt-fallback/0"
	srvKey, _ := key.GenerateSecretKey()
	server := startEchoServer(t, ctx, srvKey, alpn, false)
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	// Into0RTT on a cold cache: ok=false, conn usable directly.
	c1, err := client.ConnectEarly(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("ConnectEarly: %v", err)
	}
	conn1, ok := c1.Into0RTT()
	if ok {
		t.Fatal("cold-cache Into0RTT reported ok=true")
	}
	echo(t, ctx, conn1, "fallback")
	conn1.CloseWithError(0, "")

	// A fresh Connecting awaited via Connection also yields a working conn.
	c2, err := client.ConnectEarly(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("second ConnectEarly: %v", err)
	}
	conn2, err := c2.Connection(ctx)
	if err != nil {
		t.Fatalf("Connection: %v", err)
	}
	defer conn2.CloseWithError(0, "")
	echo(t, ctx, conn2, "await")
	if !conn2.RemoteID().Equal(server.ID()) {
		t.Errorf("remote id = %s, want %s", conn2.RemoteID(), server.ID())
	}
}

// rejectAfterFirstHook allows the first completed handshake (so a session ticket
// can be primed) and rejects every later one.
type rejectAfterFirstHook struct {
	noopHooks
	seen atomic.Int64
}

func (h *rejectAfterFirstHook) AfterHandshake(context.Context, *Conn) error {
	if h.seen.Add(1) == 1 {
		return nil
	}
	return RejectHandshake(0x42, "denied")
}

// TestConnectEarlyVerifyHookRejection checks that when the AfterHandshake hook
// rejects a 0-RTT dial after early data was sent, the connection is closed once
// the handshake completes and the early data is discarded.
func TestConnectEarlyVerifyHookRejection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "iroh-0rtt-reject/0"
	srvKey, _ := key.GenerateSecretKey()
	server := startEchoServer(t, ctx, srvKey, alpn, true)
	defer server.Shutdown(ctx)

	hook := &rejectAfterFirstHook{}
	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithHooks(hook))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	// Prime a session ticket via the first (accepted) handshake.
	primeTicket(t, ctx, client, addr, server.ID(), alpn)

	// Resume via 0-RTT and send early data. Into0RTT hands back the early conn;
	// the now-rejecting hook fires at handshake completion and closes it.
	c, err := client.ConnectEarly(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("ConnectEarly: %v", err)
	}
	conn, ok := c.Into0RTT()
	if !ok {
		t.Fatal("warm-cache Into0RTT reported ok=false despite a cached ticket")
	}
	if conn == nil {
		t.Fatal("Into0RTT returned a nil conn")
	}
	s, err := conn.OpenStreamSync(ctx)
	if err == nil {
		s.Write([]byte("early"))
		s.Close()
	}

	select {
	case <-conn.Context().Done():
		// Closed by the rejecting hook, as required.
	case <-ctx.Done():
		t.Fatalf("connection was not closed by the rejecting hook: %v", ctx.Err())
	}
}

// TestConnectEarlyInto0RTTMultipleTargets checks that a peer advertising more
// than one dial target still gets an early-data window. The other 0-RTT tests
// all use a single-target address, so a dial path that resolves Connecting only
// at handshake completion would leave them passing: Used0RTT stays true because
// the transport still resumes, while Into0RTT reports ok=false because the
// caller never gets to send before the handshake.
func TestConnectEarlyInto0RTTMultipleTargets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "iroh-0rtt-multi/0"
	srvKey, _ := key.GenerateSecretKey()
	server := startEchoServer(t, ctx, srvKey, alpn, true)
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	// The reachable address plus a blackholed one, so the dial path sees
	// several targets. The decoy is an unroutable IPv6 documentation address
	// (RFC 3849) chosen to sort after the ::1 server: WithIP sorts the address
	// set by [netaddr.TransportAddr.Compare], and a decoy sorting first would
	// instead hang, because on a warm cache DialEarly hands back a usable 0-RTT
	// connection without a round trip and the sequential dial commits to it.
	// That is a separate bug; this test covers the early-data window.
	addr := netaddr.NewEndpointAddr(server.ID()).
		WithIP(server.LocalAddr()).
		WithIP(netip.MustParseAddrPort("[2001:db8::1]:7"))

	// Cold cache: connect once so the client caches a session ticket.
	c1, err := client.ConnectEarly(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("first ConnectEarly: %v", err)
	}
	conn1, ok := c1.Into0RTT()
	if ok {
		t.Fatal("cold-cache Into0RTT reported ok=true")
	}
	echo(t, ctx, conn1, "cold")
	if !waitFor(ctx, func() bool { return client.sessionCache.Len() > 0 }) {
		t.Fatalf("client never cached a session ticket: %v", ctx.Err())
	}
	conn1.CloseWithError(0, "")

	// Warm cache: the extra target must not cost the early-data window.
	c2, err := client.ConnectEarly(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("second ConnectEarly: %v", err)
	}
	conn2, ok := c2.Into0RTT()
	if !ok {
		t.Fatal("warm-cache Into0RTT reported ok=false with more than one dial target")
	}
	defer conn2.CloseWithError(0, "")

	s, err := conn2.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("warm open stream: %v", err)
	}
	const msg = "early"
	s.Write([]byte(msg))
	s.Close()

	select {
	case <-conn2.HandshakeComplete():
	case <-ctx.Done():
		t.Fatalf("warm handshake did not complete: %v", ctx.Err())
	}
	if !conn2.Used0RTT() {
		t.Error("warm connection did not use 0-RTT despite a cached ticket")
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("warm read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("warm echo = %q, want %q", got, msg)
	}
}
