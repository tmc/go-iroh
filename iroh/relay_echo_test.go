package iroh

import (
	"context"
	"io"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

type echoRelayServer struct{ ts *httptest.Server }

func newEchoRelayServer(t testing.TB, opts ...relayserver.Option) echoRelayServer {
	t.Helper()
	ts := httptest.NewServer(relayserver.New(opts...))
	t.Cleanup(ts.Close)
	return echoRelayServer{ts: ts}
}

// url returns the relay URL clients dial.
func (s echoRelayServer) url(t testing.TB) netaddr.RelayURL {
	t.Helper()
	u, err := netaddr.ParseRelayURL(s.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestRelayOnlyEcho is the slice-D integration gate: two endpoints with no
// UDP socket and no direct-IP address connect entirely through an in-process
// relay, exchange a bidi-stream echo and a datagram, and each observes the
// other's verified endpoint id.
func TestRelayOnlyEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv := newEchoRelayServer(t)
	relayURL := srv.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	const alpn = "iroh-relay-echo/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithRelayMode(mode),
		WithoutIPTransports(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithRelayMode(mode), WithoutIPTransports())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	// Wait for both endpoints to connect to the relay so the relay can route
	// the QUIC handshake between them.
	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	type srvResult struct {
		peer key.EndpointID
		err  error
	}
	done := make(chan srvResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			done <- srvResult{err: err}
			return
		}
		b, _ := io.ReadAll(s)
		s.Write(b)
		s.Close()
		dg, err := conn.ReadDatagram(ctx)
		if err == nil {
			conn.SendDatagram(dg)
		}
		done <- srvResult{peer: conn.RemoteID()}
	}()

	// Relay-only address: id + relay URL, no direct IP.
	addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)

	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !conn.RemoteID().Equal(server.ID()) {
		t.Errorf("client saw server id %s, want %s", conn.RemoteID(), server.ID())
	}

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello over relay"
	s.Write([]byte(msg))
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("stream echo = %q, want %q", got, msg)
	}

	const dmsg = "relay-dgram"
	if err := conn.SendDatagram([]byte(dmsg)); err != nil {
		t.Fatalf("send datagram: %v", err)
	}
	dg, err := conn.ReadDatagram(ctx)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	if string(dg) != dmsg {
		t.Errorf("datagram echo = %q, want %q", dg, dmsg)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if !res.peer.Equal(client.ID()) {
		t.Errorf("server saw client id %s, want %s", res.peer, client.ID())
	}
}

// TestConnectRacesDialTargets checks that unreachable direct addresses do not
// delay the relay path by a handshake timeout each.
func TestConnectRacesDialTargets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv := newEchoRelayServer(t)
	relayURL := srv.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	const alpn = "iroh-race/0"

	server, err := Bind(ctx, WithALPNs(alpn), WithRelayMode(mode), WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	client, err := Bind(ctx, WithRelayMode(mode), WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)
	if err := server.Online(ctx); err != nil {
		t.Fatal(err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatal(err)
	}
	go func() {
		if conn, err := server.Accept(ctx); err == nil {
			<-ctx.Done()
			conn.CloseWithError(0, "")
		}
	}()

	// Three blackholed direct addresses (TEST-NET-1), then the relay.
	addr := netaddr.NewEndpointAddr(server.ID()).
		WithIP(netip.MustParseAddrPort("192.0.2.1:7")).
		WithIP(netip.MustParseAddrPort("192.0.2.2:7")).
		WithIP(netip.MustParseAddrPort("192.0.2.3:7")).
		WithRelayURL(relayURL)
	start := time.Now()
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("connect took %v, direct targets were tried sequentially", d)
	}
}
