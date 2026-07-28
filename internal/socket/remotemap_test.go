package socket

import (
	"context"
	"iter"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// fakeConn is a test [Connection]. Close() ends it; SmoothedRTT and RemoteAddr
// are fixed.
type fakeConn struct {
	mu                  sync.Mutex
	addr                Addr
	rtt                 time.Duration
	multipathNegotiated bool
	openPath            func(context.Context) error
	openPathCalls       atomic.Int64
	initiateRound       func(context.Context) ([]netip.AddrPort, error)
	initiateRoundCalls  atomic.Int64
	paths               []PathInfo
	natAddrs            []netip.AddrPort
	removedNAT          []netip.AddrPort
	remoteNAT           []netip.AddrPort
	addNATErr           error
	done                chan struct{}
	once                sync.Once
}

func newFakeConn(addr Addr, rtt time.Duration) *fakeConn {
	return &fakeConn{addr: addr, rtt: rtt, done: make(chan struct{})}
}

func (c *fakeConn) SmoothedRTT() time.Duration { return c.rtt }
func (c *fakeConn) Done() <-chan struct{}      { return c.done }
func (c *fakeConn) RemoteAddr() Addr           { return c.addr }
func (c *fakeConn) MultipathNegotiated() bool  { return c.multipathNegotiated }
func (c *fakeConn) Paths() []PathInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]PathInfo(nil), c.paths...)
}
func (c *fakeConn) setPaths(paths []PathInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths = append([]PathInfo(nil), paths...)
}
func (c *fakeConn) AddNATTraversalAddress(addr netip.AddrPort) error {
	if c.addNATErr != nil {
		return c.addNATErr
	}
	c.natAddrs = append(c.natAddrs, addr)
	return nil
}
func (c *fakeConn) RemoveNATTraversalAddress(addr netip.AddrPort) error {
	c.removedNAT = append(c.removedNAT, addr)
	return nil
}
func (c *fakeConn) OpenPath(ctx context.Context) error {
	c.openPathCalls.Add(1)
	if c.openPath != nil {
		return c.openPath(ctx)
	}
	return nil
}
func (c *fakeConn) InitiateNATTraversalRound(ctx context.Context) ([]netip.AddrPort, error) {
	c.initiateRoundCalls.Add(1)
	if c.initiateRound != nil {
		return c.initiateRound(ctx)
	}
	return nil, nil
}
func (c *fakeConn) NATTraversalAddresses() ([]netip.AddrPort, error) {
	return append([]netip.AddrPort(nil), c.remoteNAT...), nil
}
func (c *fakeConn) AddRemoteNATTraversalAddress(addr netip.AddrPort) error {
	c.remoteNAT = append(c.remoteNAT, addr)
	return nil
}
func (c *fakeConn) Close() { c.once.Do(func() { close(c.done) }) }

func testEndpointID(t *testing.T) key.EndpointID {
	t.Helper()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	return sk.Public().EndpointID()
}

// TestRemoteMapSingleActorRace uses a tiny idle timeout so actors are constantly
// idling out and being re-spawned while AddConnection hammers the same id. The
// registry must always hold exactly one actor per id — never two — even when an
// AddConnection lands exactly as the idle teardown fires. Run with -race.
func TestRemoteMapSingleActorRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A short idle timeout maximizes the spawn/teardown overlap while still
	// letting each registration win the race often enough to make progress.
	m := newRemoteMap(ctx, BiasedRttPathSelector{}, nil, 2*time.Millisecond, nil)
	id := testEndpointID(t)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))

	var (
		wg      sync.WaitGroup
		maxSeen atomic.Int64
		twoSeen atomic.Bool
	)

	// Track the high-water mark of registered actors throughout the test. A
	// small sleep keeps the monitor from starving the workers under -race.
	stopMonitor := make(chan struct{})
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		for {
			select {
			case <-stopMonitor:
				return
			default:
			}
			if n := int64(m.Len()); n > maxSeen.Load() {
				maxSeen.Store(n)
				if n > 1 {
					twoSeen.Store(true)
				}
			}
			time.Sleep(50 * time.Microsecond)
		}
	}()

	const workers = 8
	const rounds = 100
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				c := newFakeConn(addr, 5*time.Millisecond)
				m.AddConnection(id, c)
				// Hold the connection briefly so the actor stays alive, then
				// close it so it can idle out and recreate the spawn/teardown
				// race on the next round.
				time.Sleep(time.Millisecond)
				c.Close()
				// Let the actor idle out roughly half the time, so some rounds
				// hit a live actor and some hit the teardown window.
				if i%2 == 0 {
					time.Sleep(3 * time.Millisecond)
				}
			}
		}()
	}

	wg.Wait()
	close(stopMonitor)
	<-monitorDone

	if twoSeen.Load() {
		t.Fatalf("RemoteMap held more than one actor for a single id (max seen %d); the O12 single-actor invariant was violated", maxSeen.Load())
	}
}

// TestRemoteMapReuseActor checks a second reference to the same id reuses the
// running actor rather than spawning a new one.
func TestRemoteMapReuseActor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointID(t)

	a1 := m.Actor(id)
	a2 := m.Actor(id)
	if a1 != a2 {
		t.Error("Actor returned different actors for the same id")
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
}

// TestRemoteMapIdleTeardown checks an actor with no connections idles out and
// deregisters.
func TestRemoteMapIdleTeardown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := newRemoteMap(ctx, BiasedRttPathSelector{}, nil, 10*time.Millisecond, nil)
		id := testEndpointID(t)

		m.Actor(id) // spawns an actor with no connections
		if m.Len() != 1 {
			t.Fatalf("Len after spawn = %d, want 1", m.Len())
		}

		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		if m.Len() != 0 {
			t.Fatalf("Len after idle teardown = %d, want 0", m.Len())
		}
	})
}

// TestRemoteMapIdleTeardownWaitsForConnections checks that the idle timer does
// not deregister an actor while it has a live connection.
func TestRemoteMapIdleTeardownWaitsForConnections(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := newRemoteMap(ctx, BiasedRttPathSelector{}, nil, 10*time.Millisecond, nil)
		id := testEndpointID(t)

		addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
		c := newFakeConn(addr, time.Millisecond)
		events := m.AddConnection(id, c)
		eventsDone := make(chan struct{})
		go func() {
			for range events {
			}
			close(eventsDone)
		}()

		synctest.Wait()
		if m.Len() != 1 {
			t.Fatalf("Len after connection = %d, want 1", m.Len())
		}

		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		if m.Len() != 1 {
			t.Fatalf("Len while connection is active = %d, want 1", m.Len())
		}

		c.Close()
		synctest.Wait()
		time.Sleep(10 * time.Millisecond)
		synctest.Wait()
		if m.Len() != 0 {
			t.Fatalf("Len after connection close and idle teardown = %d, want 0", m.Len())
		}
		select {
		case <-eventsDone:
		default:
			t.Fatal("path events channel still open after idle teardown")
		}
	})
}

// TestActorPathEventsAndSelection checks that adding a connection emits Opened
// and Selected path events and that the actor selects the connection's path.
func TestActorPathEventsAndSelection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointID(t)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 4242))
	c := newFakeConn(addr, 5*time.Millisecond)
	defer c.Close()

	events := m.AddConnection(id, c)

	// Expect an Opened event for the path, and a Selected event (the sole path).
	var sawOpened, sawSelected bool
	deadline := time.After(2 * time.Second)
	for !(sawOpened && sawSelected) {
		select {
		case ev := <-events:
			switch ev.Kind {
			case PathEventOpened:
				if ev.Addr.String() == addr.String() {
					sawOpened = true
				}
			case PathEventSelected:
				if ev.Addr.String() == addr.String() {
					sawSelected = true
				}
			}
		case <-deadline:
			t.Fatalf("missing path events: opened=%v selected=%v", sawOpened, sawSelected)
		}
	}

	a := m.Actor(id)
	if sel, ok := a.SelectedPath(); !ok || sel.String() != addr.String() {
		t.Errorf("SelectedPath = (%v, %v), want %s", sel, ok, addr)
	}
}

func TestRemoteMapMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var metrics Metrics
	m := NewRemoteMapWithMetrics(ctx, BiasedRttPathSelector{}, nil, &metrics)
	id := testEndpointID(t)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 4242))
	c := newFakeConn(addr, 5*time.Millisecond)
	events := m.AddConnection(id, c)
	waitPathEvent(t, events, PathEventOpened, addr)

	snap := metrics.snapshot()
	if snap.PathsDirect != 1 || snap.NumConnsDirect != 1 || snap.NumConnsOpened != 1 || snap.TransportIPPathsAdded != 1 {
		t.Fatalf("Metrics after open = %+v, want direct open counted", snap)
	}

	c.Close()
	waitPathEvent(t, events, PathEventClosed, addr)
	snap = metrics.snapshot()
	if snap.NumConnsClosed != 1 || snap.TransportIPPathsRemoved != 1 {
		t.Fatalf("Metrics after close = %+v, want direct close counted", snap)
	}
}

func waitPathEvent(t *testing.T, events <-chan PathEvent, kind PathEventKind, addr Addr) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Kind == kind && ev.Addr.String() == addr.String() {
				return
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %v event for %s", kind, addr)
		}
	}
}

// TestActorHeartbeatSyncsQNGRoutes checks the actor heartbeat cadence used for
// path keep-alive work: newly-observed qng route paths are synced on the next
// HeartbeatInterval tick.
func TestActorHeartbeatSyncsQNGRoutes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
		a := m.Actor(testEndpointID(t))

		addr := IPAddr(netip.MustParseAddrPort("192.0.2.1:4433"))
		route := IPAddr(netip.MustParseAddrPort("[2001:db8::1]:4433"))
		conn := newFakeConn(addr, time.Millisecond)
		events, ok := a.AddConnection(conn)
		if !ok {
			t.Fatal("AddConnection failed")
		}
		eventsDone := make(chan struct{})
		go func() {
			for range events {
			}
			close(eventsDone)
		}()
		synctest.Wait()

		conn.setPaths([]PathInfo{{ID: 1, Validated: true, Addr: route, HasAddr: true}})
		time.Sleep(HeartbeatInterval - time.Nanosecond)
		synctest.Wait()
		a.mu.Lock()
		_, known := a.paths.Status(route)
		a.mu.Unlock()
		if known {
			t.Fatalf("route %s synced before HeartbeatInterval", route)
		}

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		a.mu.Lock()
		status, known := a.paths.Status(route)
		a.mu.Unlock()
		if !known || status != PathStatusOpen {
			t.Fatalf("route status after heartbeat = %v, %v, want open true", status, known)
		}
		cancel()
		synctest.Wait()
		<-eventsDone
	})
}

// TestActorUpgradeTickStartsQNT asserts the upgrade tick punches while the
// selected path is RELAYED — the state a punch can actually improve.
func TestActorUpgradeTickStartsQNT(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
		id := testEndpointID(t)

		conn := newFakeConn(relayPath(t, 1), time.Millisecond)
		conn.multipathNegotiated = true
		defer conn.Close()
		events := m.AddConnection(id, conn)
		eventsDone := make(chan struct{})
		go func() {
			for range events {
			}
			close(eventsDone)
		}()
		synctest.Wait()

		time.Sleep(UpgradeInterval - time.Nanosecond)
		synctest.Wait()
		if got := conn.initiateRoundCalls.Load(); got != 0 {
			t.Fatalf("InitiateNATTraversalRound calls before upgrade = %d, want 0", got)
		}

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if got := conn.initiateRoundCalls.Load(); got != 1 {
			t.Fatalf("InitiateNATTraversalRound calls after upgrade = %d, want 1", got)
		}
		cancel()
		synctest.Wait()
		<-eventsDone
	})
}

// TestActorUpgradeTickSkipsDirectSelected: a direct-selected connection gets
// no QNT round from the tick.
func TestActorUpgradeTickSkipsDirectSelected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
		id := testEndpointID(t)

		conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
		conn.multipathNegotiated = true
		defer conn.Close()
		events := m.AddConnection(id, conn)
		eventsDone := make(chan struct{})
		go func() {
			for range events {
			}
			close(eventsDone)
		}()
		synctest.Wait()

		time.Sleep(UpgradeInterval + time.Nanosecond)
		synctest.Wait()
		if got := conn.initiateRoundCalls.Load(); got != 0 {
			t.Fatalf("InitiateNATTraversalRound calls on a direct-selected conn = %d, want 0", got)
		}
		cancel()
		synctest.Wait()
		<-eventsDone
	})
}

// TestActorHolepunchGated asserts that hole-punching reports the negotiation
// sentinel when no active connection has negotiated qng multipath/QNT.
func TestActorHolepunchGated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))
	if err := a.TriggerHolepunch(); err != ErrExtensionNotNegotiated {
		t.Errorf("TriggerHolepunch = %v, want ErrExtensionNotNegotiated", err)
	}
}

// TestActorSendDatagramBlackhole asserts the blackhole invariant: SendDatagram
// never returns an error, even when no path is reachable (send returns false).
func TestActorSendDatagramBlackhole(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointID(t)

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 1))
	c := newFakeConn(addr, time.Millisecond)
	defer c.Close()
	m.AddConnection(id, c)

	a := m.Actor(id)
	var sent atomic.Int64
	// Every send "fails" (returns false), yet SendDatagram must report success.
	err := a.SendDatagram([]byte("hi"), func(Addr, []byte) bool {
		sent.Add(1)
		return false
	})
	if err != nil {
		t.Errorf("SendDatagram returned %v on an unreachable path, want nil (blackhole)", err)
	}
	if sent.Load() == 0 {
		t.Error("SendDatagram did not attempt any send")
	}
}

// TestActorResolveAddsPaths checks the resolve hook adds resolved addresses as
// candidate paths.
func TestActorResolveAddsPaths(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolved := []ResolvedAddr{
		{Addr: netaddr.IPAddr{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 7)}, Provenance: "test_lookup"},
	}
	resolve := func(ctx context.Context, id key.EndpointID) iter.Seq2[ResolvedAddr, error] {
		return func(yield func(ResolvedAddr, error) bool) {
			for _, addr := range resolved {
				if !yield(addr, nil) {
					return
				}
			}
		}
	}
	m := newRemoteMap(ctx, BiasedRttPathSelector{}, resolve, time.Second, nil)
	id := testEndpointID(t)

	// Keep the actor alive with a connection so it does not idle out mid-test.
	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	c := newFakeConn(addr, time.Millisecond)
	defer c.Close()
	m.AddConnection(id, c)

	if err := m.ResolveRemote(netaddr.NewEndpointAddr(id)); err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}

	// The resolved IP path must now be a candidate. We send a datagram with no
	// selected path forced by clearing selection is not exposed; instead assert
	// via the actor's known paths through a fresh SendDatagram fanout count: with
	// a selected path it only sends to one, so check the path state directly.
	a := m.Actor(id)
	want := IPAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 7))
	if !waitForActorPath(a, want, time.Second) {
		t.Fatalf("resolved path %s was not added as a candidate", want)
	}
	info, ok := m.RemoteInfo(id)
	if !ok {
		t.Fatal("RemoteInfo = false, want true")
	}
	var found bool
	for _, addr := range info.Addrs {
		if addr.Addr.String() == resolved[0].Addr.String() {
			found = true
			if addr.Provenance != "test_lookup" {
				t.Fatalf("provenance = %q, want test_lookup", addr.Provenance)
			}
		}
	}
	if !found {
		t.Fatalf("RemoteInfo addrs = %+v, want resolved addr", info.Addrs)
	}
}

func TestActorResolveStreamsPathsAfterReturn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	second := make(chan ResolvedAddr, 1)
	resolve := func(ctx context.Context, id key.EndpointID) iter.Seq2[ResolvedAddr, error] {
		return func(yield func(ResolvedAddr, error) bool) {
			first := ResolvedAddr{
				Addr:       netaddr.IPAddr{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{1, 2, 3, 4}), 7)},
				Provenance: "first",
			}
			if !yield(first, nil) {
				return
			}
			select {
			case addr := <-second:
				yield(addr, nil)
			case <-ctx.Done():
			}
		}
	}
	m := newRemoteMap(ctx, BiasedRttPathSelector{}, resolve, time.Second, nil)
	id := testEndpointID(t)
	c := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	defer c.Close()
	m.AddConnection(id, c)

	if err := m.ResolveRemote(netaddr.NewEndpointAddr(id)); err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}
	later := ResolvedAddr{
		Addr:       netaddr.IPAddr{Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 9)},
		Provenance: "later",
	}
	second <- later

	want := IPAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{5, 6, 7, 8}), 9))
	if !waitForActorPath(m.Actor(id), want, time.Second) {
		t.Fatalf("streamed path %s was not added", want)
	}
}

func waitForActorPath(a *RemoteStateActor, want Addr, timeout time.Duration) bool {
	deadline := time.After(timeout)
	for {
		a.mu.Lock()
		_, known := a.paths.Status(want)
		a.mu.Unlock()
		if known {
			return true
		}
		select {
		case <-deadline:
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestRemoteMapRemoteInfoDoesNotSpawn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointID(t)
	if _, ok := m.RemoteInfo(id); ok {
		t.Fatal("RemoteInfo for unknown remote = true, want false")
	}
	if got := m.Len(); got != 0 {
		t.Fatalf("RemoteInfo spawned %d actors, want 0", got)
	}
}

func TestRemoteMapRemoteInfo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointID(t)
	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	c := newFakeConn(addr, time.Millisecond)
	defer c.Close()
	m.AddConnection(id, c)

	info, ok := m.RemoteInfo(id)
	if !ok {
		t.Fatal("RemoteInfo = false, want true")
	}
	if info.ID != id {
		t.Fatalf("RemoteInfo ID = %v, want %v", info.ID, id)
	}
	if len(info.Addrs) != 1 {
		t.Fatalf("RemoteInfo addrs = %v, want one", info.Addrs)
	}
	if info.Addrs[0].Usage != TransportAddrActive {
		t.Fatalf("RemoteInfo usage = %v, want active", info.Addrs[0].Usage)
	}
}
