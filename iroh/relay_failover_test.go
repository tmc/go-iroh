package iroh

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/netreport"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// TestRelayHomeFailover exercises home-relay failover end to end: two
// relay-only endpoints share three in-process relay servers, echo over the
// initial home relay, then both remove that relay. Removing the home must
// promote exactly the next configured relay (the map's sorted order) — not the
// last one, and not several at once — and traffic must keep flowing through
// the promoted relay.
func TestRelayHomeFailover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var urls []netaddr.RelayURL
	for range 3 {
		urls = append(urls, newEchoRelayServer(t).url(t))
	}
	mode := relay.ModeCustom(relay.MapFromURLs(urls...))
	sorted := relay.MapFromURLs(urls...).URLs()

	const alpn = "iroh-relay-failover/0"

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

	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	// echoOnce accepts one connection on server and echoes one stream.
	echoOnce := func() chan error {
		done := make(chan error, 1)
		go func() {
			conn, err := server.Accept(ctx)
			if err != nil {
				done <- err
				return
			}
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				done <- err
				return
			}
			b, _ := io.ReadAll(s)
			s.Write(b)
			s.Close()
			done <- nil
		}()
		return done
	}

	// roundTrip connects to server via relayURL and echoes msg on a stream.
	roundTrip := func(relayURL netaddr.RelayURL, msg string) error {
		done := echoOnce()
		addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)
		conn, err := client.Connect(ctx, addr, alpn)
		if err != nil {
			return err
		}
		defer conn.CloseWithError(0, "")
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		s.Write([]byte(msg))
		s.Close()
		got, err := io.ReadAll(s)
		if err != nil {
			return err
		}
		if string(got) != msg {
			t.Errorf("echo = %q, want %q", got, msg)
		}
		return <-done
	}

	// homeOf reports the endpoint's current home relay URL.
	homeOf := func(e *Endpoint) netaddr.RelayURL {
		st := e.HomeRelayStatus().Current()
		if st == nil {
			t.Fatal("no home relay status")
		}
		return st.URL
	}

	home := homeOf(client)
	if err := roundTrip(home, "hello before failover"); err != nil {
		t.Fatalf("echo before failover: %v", err)
	}

	// The promoted home must be the first remaining relay in sorted order.
	var want netaddr.RelayURL
	for _, u := range sorted {
		if !u.Equal(home) {
			want = u
			break
		}
	}

	for _, e := range []*Endpoint{client, server} {
		if e.RemoveRelay(homeOf(e)) == nil {
			t.Fatal("RemoveRelay: home relay not configured")
		}
		if got := homeOf(e); !got.Equal(want) {
			t.Fatalf("home after removal = %v, want %v", got, want)
		}
	}

	// Wait for both endpoints to reconnect to the promoted relay, then verify
	// traffic flows through it.
	for _, e := range []*Endpoint{client, server} {
		w := e.HomeRelayStatus()
		for {
			st, err := w.Updated(ctx)
			if err != nil {
				t.Fatalf("home relay watcher: %v", err)
			}
			if st != nil && st.URL.Equal(want) && st.IsConnected() {
				break
			}
		}
	}
	if err := roundTrip(want, "hello after failover"); err != nil {
		t.Fatalf("echo after failover: %v", err)
	}
}

// TestRelayHomeStaysOffRemovedRelay checks that a net_report still in flight
// when a relay is removed cannot move the home relay back onto it. The report
// names the removed relay as preferred, so applying it would undo the
// promotion RemoveRelay just made.
func TestRelayHomeStaysOffRemovedRelay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var urls []netaddr.RelayURL
	for range 3 {
		urls = append(urls, newEchoRelayServer(t).url(t))
	}
	m := relay.MapFromURLs(urls...)
	sorted := m.URLs()

	// The report is held until the test releases it, so it lands after the
	// removal. It prefers the relay the test removes.
	release := make(chan struct{})
	run := func(ctx context.Context) (*netreport.Report, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &netreport.Report{PreferredRelay: sorted[0]}, nil
	}

	ep, err := Bind(ctx,
		WithRelayMode(relay.ModeCustom(m)),
		WithoutIPTransports(),
		withNetReportRunner(run),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	home := ep.HomeRelayStatus().Current()
	if home == nil || !home.URL.Equal(sorted[0]) {
		t.Fatalf("bootstrap home = %v, want %v", home, sorted[0])
	}
	if ep.RemoveRelay(sorted[0]) == nil {
		t.Fatal("RemoveRelay: home relay not configured")
	}
	if got := ep.HomeRelayStatus().Current(); got == nil || !got.URL.Equal(sorted[1]) {
		t.Fatalf("home after removal = %v, want %v", got, sorted[1])
	}

	close(release)
	for {
		if _, ok := ep.NetReport(); ok {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("net report never applied")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if got := ep.HomeRelayStatus().Current(); got == nil || !got.URL.Equal(sorted[1]) {
		t.Fatalf("home after stale net report = %v, want %v", got, sorted[1])
	}
}
