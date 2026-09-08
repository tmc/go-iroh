package iroh

// Establishment instruments: how long a connection takes to become usable, and
// how reliably a relay-only dial reaches a direct path.
//
// The rest of the benchmark suite measures the data plane — throughput, message
// rate, ping-pong — on a connection that is already up. For a peer-to-peer
// endpoint the establishment path usually dominates what a user perceives: a
// relayed connection instead of a direct one costs far more than any framing
// cost on the connection itself. These instruments give that path the same kind
// of baseline the send path already has.

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// upgradeTimeout bounds one relay-to-direct upgrade. Locally the upgrade lands
// in about 5s: an ADD_ADDRESS round trip plus the 5s heartbeat reselect. The
// rest is headroom for a loaded CI machine.
const upgradeTimeout = 30 * time.Second

// pathPollInterval is how often a wait samples Conn.Paths. It bounds the
// resolution of every duration reported here, so it is much finer than the
// upgrade it measures. Polling rather than WatchPaths keeps the measurement
// independent of which transitions the endpoint chooses to emit events for.
const pathPollInterval = 10 * time.Millisecond

// waitForDirectPath blocks until conn selects a direct path, and reports two
// durations relative to start: when a direct path first became usable
// (validated and addressed) and when it was actually selected, so that bytes
// stopped going through the relay.
//
// The two are reported separately because they are not the same event. A path
// becoming validated does not trigger a reselect: RemoteStateActor.reselect
// runs when a connection is added, when discovery resolves an address, and on
// the 5s heartbeat tick. A direct path that validates just after a tick
// therefore sits unused until the next one, and the connection keeps paying the
// relay's round trip in the meantime. Collapsing both into one number would
// hide that the second phase is a timer rather than network time.
func waitForDirectPath(ctx context.Context, conn *Conn, start time.Time) (validated, selected time.Duration, err error) {
	ticker := time.NewTicker(pathPollInterval)
	defer ticker.Stop()
	for {
		for _, p := range conn.Paths() {
			if p.Relayed || !p.HasAddr || !p.Validated {
				continue
			}
			if validated == 0 {
				validated = time.Since(start)
			}
			if p.Selected {
				return validated, time.Since(start), nil
			}
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return validated, 0, fmt.Errorf("no selected direct path: %w", ctx.Err())
		case <-conn.Context().Done():
			return validated, 0, fmt.Errorf("connection closed before a direct path was selected")
		}
	}
}

// acceptLoop answers connections until ctx is done, so a dialer measuring
// establishment is never waiting on a missing Accept.
func acceptLoop(ctx context.Context, ep *Endpoint) {
	for {
		conn, err := ep.Accept(ctx)
		if err != nil {
			return
		}
		go func() { <-conn.Context().Done() }()
	}
}

// BenchmarkEndpointConnect measures how long Connect takes to return a usable
// connection over a direct path, which is the floor for time-to-first-byte
// against a peer whose address is already known.
//
// The two cases differ in what the dialer has already learned. Warm reuses one
// client endpoint, so address discovery and the TLS session cache are primed —
// the steady state for an application reconnecting to a known peer. Cold binds
// a fresh client endpoint per iteration, which is what first contact costs.
// Only Connect is on the clock in either case.
//
// Measured on loopback the two are indistinguishable: at -benchtime 200x both
// land near 1.7ms, and at 10x or 30x they trade places by more than they differ.
// Read a warm/cold gap as a real signal only at high iteration counts. Both
// figures also fall as the count rises, because the first connection to a peer
// costs several times the steady-state one — the server's per-peer actor and
// path state are built then — and that one-time cost amortizes into ns/op.
func BenchmarkEndpointConnect(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping establishment benchmark in short mode")
	}
	const alpn = "iroh-bench-connect/0"
	loopback := netip.AddrPortFrom(netip.IPv6Loopback(), 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn), WithBindAddr(loopback))
	if err != nil {
		b.Fatal(err)
	}
	defer server.Shutdown(ctx)
	go acceptLoop(ctx, server)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	b.Run("warm", func(b *testing.B) {
		client, err := Bind(ctx, WithBindAddr(loopback))
		if err != nil {
			b.Fatal(err)
		}
		defer client.Shutdown(ctx)
		b.ResetTimer()
		for b.Loop() {
			conn, err := client.Connect(ctx, addr, alpn)
			if err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			conn.CloseWithError(0, "")
			b.StartTimer()
		}
	})

	b.Run("cold", func(b *testing.B) {
		for b.Loop() {
			b.StopTimer()
			client, err := Bind(ctx, WithBindAddr(loopback))
			if err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
			conn, err := client.Connect(ctx, addr, alpn)
			if err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			conn.CloseWithError(0, "")
			client.Shutdown(ctx)
			b.StartTimer()
		}
	})
}

// BenchmarkRelayToDirectUpgrade measures the interval between a relay-only dial
// returning and the connection selecting a validated direct path. Until that
// happens every byte is paying the relay's round trip, so this is the duration
// a user experiences as the connection "warming up".
//
// One iteration is seconds, so expect a very small b.N; the value of the
// benchmark is the reported ns/op, not a tight confidence interval.
func BenchmarkRelayToDirectUpgrade(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping upgrade benchmark in short mode")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := newEchoRelayServer(b)
	relayURL := srv.url(b)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	const alpn = "iroh-bench-upgrade/0"
	loopback := netip.MustParseAddrPort("127.0.0.1:0")

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithRelayMode(mode), WithBindAddr(loopback))
	if err != nil {
		b.Fatal(err)
	}
	defer server.Shutdown(ctx)
	if err := server.Online(ctx); err != nil {
		b.Fatalf("server online: %v", err)
	}
	go acceptLoop(ctx, server)

	// Relay-only: everything direct has to be learned over the connection.
	addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)

	// ns/op is the full time to direct. direct-ready-ns is the part that is
	// real network work; the difference is time spent waiting for a reselect.
	var totalValidated time.Duration
	iters := 0

	b.ResetTimer()
	for b.Loop() {
		iters++
		b.StopTimer()
		client, err := Bind(ctx, WithRelayMode(mode), WithBindAddr(loopback))
		if err != nil {
			b.Fatal(err)
		}
		if err := client.Online(ctx); err != nil {
			b.Fatalf("client online: %v", err)
		}
		b.StartTimer()

		start := time.Now()
		conn, err := client.Connect(ctx, addr, alpn)
		if err != nil {
			b.Fatalf("relay connect: %v", err)
		}
		waitCtx, waitCancel := context.WithTimeout(ctx, upgradeTimeout)
		valid, _, err := waitForDirectPath(waitCtx, conn, start)
		if err != nil {
			b.Fatal(err)
		}
		waitCancel()
		totalValidated += valid

		b.StopTimer()
		conn.CloseWithError(0, "")
		client.Shutdown(ctx)
		b.StartTimer()
	}
	b.StopTimer()
	if iters > 0 {
		b.ReportMetric(float64(totalValidated.Nanoseconds())/float64(iters), "direct-ready-ns/op")
	}
}

// TestRelayToDirectUpgradeSuccessRate runs the upgrade repeatedly and reports
// how often it lands and how long it takes.
//
// TestRelayToDirectUpgrade proves the upgrade happens once. Once is not a rate:
// a punch that succeeds nine times in ten is a materially worse library than one
// that always succeeds, and a single-shot test cannot tell them apart. Over
// loopback there is no NAT to defeat, so every trial is required to succeed —
// anything less is a real defect rather than an unlucky network.
func TestRelayToDirectUpgradeSuccessRate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping repeated upgrade trials in short mode")
	}
	const trials = 3

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(trials)*upgradeTimeout+time.Minute)
	defer cancel()

	srv := newEchoRelayServer(t)
	relayURL := srv.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	const alpn = "upgrade-rate-test/0"
	loopback := netip.MustParseAddrPort("127.0.0.1:0")

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithRelayMode(mode), WithBindAddr(loopback))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	go acceptLoop(ctx, server)

	addr := netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL)

	var took, ready []time.Duration
	var failures int
	for i := range trials {
		func() {
			client, err := Bind(ctx, WithRelayMode(mode), WithBindAddr(loopback))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Shutdown(ctx)
			if err := client.Online(ctx); err != nil {
				t.Fatalf("trial %d: client online: %v", i, err)
			}

			start := time.Now()
			conn, err := client.Connect(ctx, addr, alpn)
			if err != nil {
				t.Fatalf("trial %d: relay connect: %v", i, err)
			}
			defer conn.CloseWithError(0, "")

			// The dial must start relayed, or the trial measured nothing.
			for _, p := range conn.Paths() {
				if !p.Relayed {
					t.Fatalf("trial %d: premise broken, direct path present right after a relay-only dial: %+v", i, p)
				}
			}

			waitCtx, waitCancel := context.WithTimeout(ctx, upgradeTimeout)
			defer waitCancel()
			valid, d, err := waitForDirectPath(waitCtx, conn, start)
			if err != nil {
				failures++
				t.Errorf("trial %d: %v", i, err)
				for _, p := range conn.Paths() {
					t.Logf("  path: relayed=%v addr=%v validated=%v selected=%v", p.Relayed, p.Addr, p.Validated, p.Selected)
				}
				return
			}
			took = append(took, d)
			ready = append(ready, valid)
		}()
	}

	if len(took) > 0 {
		slices.Sort(took)
		slices.Sort(ready)
		t.Logf("upgrade succeeded %d/%d: selected min %v median %v max %v",
			len(took), trials,
			took[0].Round(time.Millisecond),
			took[len(took)/2].Round(time.Millisecond),
			took[len(took)-1].Round(time.Millisecond))
		t.Logf("direct path was usable much earlier: median %v, i.e. %v of the wait above is the reselect tick",
			ready[len(ready)/2].Round(time.Millisecond),
			(took[len(took)/2] - ready[len(ready)/2]).Round(time.Millisecond))
	}
	if failures > 0 {
		t.Errorf("relay-to-direct upgrade failed %d of %d trials over loopback", failures, trials)
	}
}
