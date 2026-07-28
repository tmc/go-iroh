package iroh

// A connection dialed knowing only the relay must reach a validated,
// SELECTED direct path shortly after the handshake — punch-on-ready, not the
// 60s upgrade tick. Selection is what carries the bytes.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

func TestRelayToDirectUpgrade(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	srv := newEchoRelayServer(t)
	relayURL := srv.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	const alpn = "upgrade-test/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs(alpn),
		WithRelayMode(mode),
		WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx,
		WithRelayMode(mode),
		WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			return
		}
		<-conn.Context().Done()
	}()

	// Relay-only address, as when the relay wins a candidate race: everything
	// direct must be learned over the connection itself.
	addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("relay connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	for _, p := range conn.Paths() {
		if !p.Relayed {
			t.Fatalf("premise broken: direct path present right after a relay-only dial: %+v", p)
		}
	}

	// ~5s locally (ADD_ADDRESS round trip + 5s heartbeat reselect); 30s is
	// CI headroom. First-punch-at-60s fails this bound.
	deadline := time.Now().Add(30 * time.Second)
	start := time.Now()
	for time.Now().Before(deadline) {
		for _, p := range conn.Paths() {
			if !p.Relayed && p.Selected && p.HasAddr && p.Validated {
				t.Logf("direct path selected after %v: %v", time.Since(start).Round(time.Second), p.Addr)
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	for _, p := range conn.Paths() {
		t.Logf("path: relayed=%v addr=%v validated=%v selected=%v", p.Relayed, p.Addr, p.Validated, p.Selected)
	}
	t.Fatal("relay-only connection never migrated to a selected direct path")
}
