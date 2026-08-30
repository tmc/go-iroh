package socket

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/relayclient"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestTimeoutError pins the net.Error contract of the read-deadline error: its
// message is exactly "i/o timeout" (matching net.OpError's timeout wording) and
// it reports both Timeout and Temporary so quic-go treats a read timeout as a
// retriable, non-fatal condition rather than a dead socket (deadline.go:86-88).
func TestTimeoutError(t *testing.T) {
	var e error = timeoutError{}
	if got := e.Error(); got != "i/o timeout" {
		t.Errorf("Error() = %q, want %q", got, "i/o timeout")
	}
	ne, ok := e.(net.Error)
	if !ok {
		t.Fatalf("timeoutError does not satisfy net.Error")
	}
	if !ne.Timeout() {
		t.Error("Timeout() = false, want true")
	}
	//lint:ignore SA1019 This test pins the legacy method required by quic-go.
	if !ne.Temporary() {
		t.Error("Temporary() = false, want true")
	}
}

// TestNewMappedAddrConstructors checks the three allocating constructors produce
// addresses in the correct n0 ULA subnet with a monotonically increasing
// counter. The counters are process-global atomics (mapped_addrs.rs:57-64), so
// the test asserts the subnet/prefix bytes and that successive allocations
// strictly increase, rather than absolute counter values (which other tests in
// the package also consume).
func TestNewMappedAddrConstructors(t *testing.T) {
	tests := []struct {
		name   string
		gen    func() netip.Addr
		subnet [2]byte
	}{
		{"endpoint id", func() netip.Addr { return NewEndpointIDMappedAddr().Addr() }, subnetEndpointID},
		{"relay", func() netip.Addr { return NewRelayMappedAddr().Addr() }, subnetRelay},
		{"custom", func() netip.Addr { return NewCustomMappedAddr().Addr() }, subnetCustom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := tt.gen().As16()
			b := tt.gen().As16()
			// Prefix 0xfd | n0 global id 15 07 0a 51 0b | subnet.
			wantPrefix := []byte{0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, tt.subnet[0], tt.subnet[1]}
			for i, w := range wantPrefix {
				if a[i] != w {
					t.Errorf("addr byte %d = 0x%02x, want 0x%02x", i, a[i], w)
				}
				if b[i] != w {
					t.Errorf("second addr byte %d = 0x%02x, want 0x%02x", i, b[i], w)
				}
			}
			ca := uint64(a[8])<<56 | uint64(a[9])<<48 | uint64(a[10])<<40 | uint64(a[11])<<32 |
				uint64(a[12])<<24 | uint64(a[13])<<16 | uint64(a[14])<<8 | uint64(a[15])
			cb := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
				uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
			if cb <= ca {
				t.Errorf("counter did not increase: first=%d second=%d", ca, cb)
			}
			if ca == 0 {
				t.Error("counter is 0; Rust starts at 1 (AtomicU64::new(1))")
			}
		})
	}
}

// TestMappedAddrAddrAndAddrPort checks the three mapped-address types return
// their underlying IPv6 unchanged from Addr() and pin the dummy port (12345,
// MAPPED_PORT in mapped_addrs.rs:55) from AddrPort().
func TestMappedAddrAddrAndAddrPort(t *testing.T) {
	eid := NewEndpointIDMappedAddr()
	relay := NewRelayMappedAddr()
	custom := NewCustomMappedAddr()

	tests := []struct {
		name string
		addr netip.Addr
		port uint16
	}{
		{"endpoint id", eid.Addr(), eid.AddrPort().Port()},
		{"relay", relay.Addr(), relay.AddrPort().Port()},
		{"custom", custom.Addr(), custom.AddrPort().Port()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.addr.Is6() || tt.addr.Is4In6() {
				t.Errorf("Addr() = %s, want plain IPv6", tt.addr)
			}
			if tt.port != 12345 {
				t.Errorf("AddrPort port = %d, want 12345", tt.port)
			}
		})
	}

	// AddrPort's address must equal Addr().
	if eid.AddrPort().Addr() != eid.Addr() {
		t.Error("EndpointIDMappedAddr.AddrPort addr != Addr()")
	}
	if relay.AddrPort().Addr() != relay.Addr() {
		t.Error("RelayMappedAddr.AddrPort addr != Addr()")
	}
	if custom.AddrPort().Addr() != custom.Addr() {
		t.Error("CustomMappedAddr.AddrPort addr != Addr()")
	}
}

// TestRelayMappedAddrFromAddr checks the reverse-lookup wrapper returns the same
// address it wrapped without allocating a new counter (mapped_addrs.rs:25-26).
func TestRelayMappedAddrFromAddr(t *testing.T) {
	orig := netip.MustParseAddr("fd15:70a:510b:1::2a")
	m := RelayMappedAddrFromAddr(orig)
	if m.Addr() != orig {
		t.Errorf("Addr() = %s, want %s (wrap must not modify)", m.Addr(), orig)
	}
	if Classify(m.Addr()) != KindRelay {
		t.Errorf("wrapped addr classified as %v, want KindRelay", Classify(m.Addr()))
	}
}

// TestPathStatusString pins the lowercase rendering of each PathStatus, including
// the out-of-range fallback (path_state.go:38).
func TestPathStatusString(t *testing.T) {
	tests := []struct {
		s    PathStatus
		want string
	}{
		{PathStatusUnknown, "unknown"},
		{PathStatusOpen, "open"},
		{PathStatusInactive, "inactive"},
		{PathStatusUnusable, "unusable"},
		{PathStatus(99), "invalid"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("PathStatus(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

// TestPathEventKindString pins the lowercase rendering of each PathEventKind,
// including the out-of-range fallback (path_watcher.go:29).
func TestPathEventKindString(t *testing.T) {
	tests := []struct {
		k    PathEventKind
		want string
	}{
		{PathEventOpened, "opened"},
		{PathEventClosed, "closed"},
		{PathEventSelected, "selected"},
		{PathEventLagged, "lagged"},
		{PathEventKind(42), "invalid"},
	}
	for _, tt := range tests {
		if got := tt.k.String(); got != tt.want {
			t.Errorf("PathEventKind(%d).String() = %q, want %q", tt.k, got, tt.want)
		}
	}
}

// TestRemotePathStateIsEmptyAndAddrs checks IsEmpty flips false on the first
// path and that Addrs returns every known address (order-independent), nil-ish
// for an empty state (path_state.go:96,102).
func TestRemotePathStateIsEmptyAndAddrs(t *testing.T) {
	p := NewRemotePathState()
	if !p.IsEmpty() {
		t.Error("fresh RemotePathState is not empty")
	}
	if got := p.Addrs(); len(got) != 0 {
		t.Errorf("empty Addrs() len = %d, want 0", len(got))
	}

	want := []Addr{ipPath(1), ipPath(2), ipPath(3)}
	for _, a := range want {
		p.SetOpen(a)
	}
	if p.IsEmpty() {
		t.Error("RemotePathState with 3 paths reports empty")
	}
	got := p.Addrs()
	if len(got) != 3 {
		t.Fatalf("Addrs() len = %d, want 3", len(got))
	}
	have := map[string]bool{}
	for _, a := range got {
		have[a.String()] = true
	}
	for _, a := range want {
		if !have[a.String()] {
			t.Errorf("Addrs() missing %s", a)
		}
	}
}

// TestAddrRelayAndCustom checks the Addr type's Relay/Custom extractors: they
// return true with the embedded value only for the matching kind, and false for
// an IP addr. This backs the recvBatch routing (a RelayAddr surfaces a relay
// path, a CustomAddr a custom path), recvbatch.go Addr.Relay/Addr.Custom.
func TestAddrRelayAndCustom(t *testing.T) {
	u, err := netaddr.ParseRelayURL("https://relay.example.")
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := key.GenerateSecretKey()
	eid := sk.Public().EndpointID()

	relay := RelayAddr(u, eid)
	if gotURL, gotEID, ok := relay.Relay(); !ok {
		t.Error("RelayAddr.Relay() ok = false, want true")
	} else if !gotURL.Equal(u) || !gotEID.Equal(eid) {
		t.Errorf("Relay() = (%s, %s), want (%s, %s)", gotURL, gotEID, u, eid)
	}
	if _, ok := relay.Custom(); ok {
		t.Error("RelayAddr.Custom() ok = true, want false")
	}

	c := netaddr.CustomAddr{}
	custom := CustomAddr(c)
	if _, ok := custom.Custom(); !ok {
		t.Error("CustomAddr.Custom() ok = false, want true")
	}
	if _, _, ok := custom.Relay(); ok {
		t.Error("CustomAddr.Relay() ok = true, want false")
	}

	ip := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	if _, _, ok := ip.Relay(); ok {
		t.Error("IPAddr.Relay() ok = true, want false")
	}
	if _, ok := ip.Custom(); ok {
		t.Error("IPAddr.Custom() ok = true, want false")
	}
}

// TestAddrStringForms pins the "kind:value" rendering of each Addr variant
// (recvbatch.go Addr.String); the relay form joins url and eid with '|'.
func TestAddrStringForms(t *testing.T) {
	ip := IPAddr(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 7))
	if got := ip.String(); !strings.HasPrefix(got, "ip:") {
		t.Errorf("IP Addr.String() = %q, want ip: prefix", got)
	}
	u, _ := netaddr.ParseRelayURL("https://relay.example.")
	var eid key.EndpointID
	relay := RelayAddr(u, eid)
	if got := relay.String(); !strings.HasPrefix(got, "relay:") || !strings.Contains(got, "|") {
		t.Errorf("relay Addr.String() = %q, want relay:...|... form", got)
	}
	if got := CustomAddr(netaddr.CustomAddr{}).String(); !strings.HasPrefix(got, "custom:") {
		t.Errorf("custom Addr.String() = %q, want custom: prefix", got)
	}
	// Out-of-range kind renders "unknown".
	if got := (Addr{kind: AddrKind(99)}).String(); got != "unknown" {
		t.Errorf("unknown Addr.String() = %q, want unknown", got)
	}
}

// TestActiveRelaySetHomeHome checks the mutex-protected home flag round-trips.
func TestActiveRelaySetHomeHome(t *testing.T) {
	r := newActiveRelay(&RelayActor{}, netaddr.RelayURL{}, false)
	if r.home() {
		t.Error("newActiveRelay(home=false).home() = true")
	}
	r.setHome(true)
	if !r.home() {
		t.Error("after setHome(true), home() = false")
	}
	r.setHome(false)
	if r.home() {
		t.Error("after setHome(false), home() = true")
	}

	// Construct home=true.
	r2 := newActiveRelay(&RelayActor{}, netaddr.RelayURL{}, true)
	if !r2.home() {
		t.Error("newActiveRelay(home=true).home() = false")
	}
}

// TestActiveRelayRoutes checks the routes map lifecycle: an unseen endpoint has
// no route; noteRoute records it (hasRoute=true); dropRoute (EndpointGone)
// removes it again (relay_actor.go:448,456,468).
func TestActiveRelayRoutes(t *testing.T) {
	r := newActiveRelay(&RelayActor{}, netaddr.RelayURL{}, false)
	sk, _ := key.GenerateSecretKey()
	eid := sk.Public().EndpointID()

	if r.hasRoute(eid) {
		t.Error("fresh activeRelay hasRoute = true, want false")
	}
	r.noteRoute(eid)
	if !r.hasRoute(eid) {
		t.Error("after noteRoute, hasRoute = false, want true")
	}
	r.dropRoute(eid)
	if r.hasRoute(eid) {
		t.Error("after dropRoute, hasRoute = true, want false")
	}
}

// TestRouteForEndpointLocked checks the actor picks the active relay that knows
// a route to an endpoint, or nil when none does (relay_actor.go:301).
func TestRouteForEndpointLocked(t *testing.T) {
	a := NewRelayActor(RelayActorConfig{})
	u1, _ := netaddr.ParseRelayURL("https://relay1.example.")
	u2, _ := netaddr.ParseRelayURL("https://relay2.example.")
	r1 := newActiveRelay(a, u1, false)
	r2 := newActiveRelay(a, u2, false)
	a.active[u1.String()] = r1
	a.active[u2.String()] = r2

	sk, _ := key.GenerateSecretKey()
	eid := sk.Public().EndpointID()

	a.mu.Lock()
	if got := a.routeForEndpointLocked(eid); got != nil {
		a.mu.Unlock()
		t.Fatal("routeForEndpointLocked found a route before any noteRoute")
	}
	a.mu.Unlock()

	r2.noteRoute(eid)

	a.mu.Lock()
	got := a.routeForEndpointLocked(eid)
	a.mu.Unlock()
	if got != r2 {
		t.Errorf("routeForEndpointLocked = %p, want r2 (%p)", got, r2)
	}
}

// TestJitterBounds checks jitter scales a duration by a factor in [0.5, 1.5),
// matching the Rust ExponentialBuilder jitter (relay_actor.go:760).
func TestJitterBounds(t *testing.T) {
	const base = 100 * time.Millisecond
	lo := base / 2
	hi := base * 3 / 2
	var sum time.Duration
	const n = 1000
	for i := 0; i < n; i++ {
		got := jitter(base)
		if got < lo || got >= hi {
			t.Fatalf("jitter(%v) = %v, want in [%v, %v)", base, got, lo, hi)
		}
		sum += got
	}
	mean := sum / n
	// Mean should be near base (the midpoint of [0.5,1.5) is 1.0); allow slop.
	if mean < base*3/4 || mean > base*5/4 {
		t.Errorf("jitter mean = %v, want near %v", mean, base)
	}
}

func TestRelayPingTimeoutDuration(t *testing.T) {
	if got := pingTimeoutDuration(&connectedState{}); got != relayPingTimeoutMax {
		t.Fatalf("pingTimeoutDuration(no RTT) = %v, want %v", got, relayPingTimeoutMax)
	}
	if got := pingTimeoutDuration(&connectedState{lastRTT: time.Millisecond}); got != relayPingTimeoutMin {
		t.Fatalf("pingTimeoutDuration(min clamp) = %v, want %v", got, relayPingTimeoutMin)
	}
	if got := pingTimeoutDuration(&connectedState{lastRTT: 3 * time.Second}); got != relayPingTimeoutMax {
		t.Fatalf("pingTimeoutDuration(max clamp) = %v, want %v", got, relayPingTimeoutMax)
	}

	var ping [8]byte
	copy(ping[:], "pingpong")
	now := time.Unix(100, 0)
	st := &connectedState{
		pingSent:    ping,
		pingSentAt:  now.Add(-200 * time.Millisecond),
		awaitingPng: true,
	}
	(&activeRelay{}).handleFrameAt(relayproto.RelayToClientMsg{
		Type: relayproto.FramePong,
		Ping: ping,
	}, st, now)
	if got := st.lastRTT; got != 200*time.Millisecond {
		t.Fatalf("lastRTT = %v, want 200ms", got)
	}
	if got := pingTimeoutDuration(st); got != 600*time.Millisecond {
		t.Fatalf("pingTimeoutDuration(after pong) = %v, want 600ms", got)
	}
}

// TestDrain checks drain empties a channel without blocking and is a no-op on an
// already-empty channel (relay_actor.go:765).
func TestDrain(t *testing.T) {
	ch := make(chan int, 4)
	ch <- 1
	ch <- 2
	ch <- 3
	drain(ch)
	if len(ch) != 0 {
		t.Errorf("after drain, len = %d, want 0", len(ch))
	}
	// Idempotent: draining an empty channel does not block or panic.
	drain(ch)
	if len(ch) != 0 {
		t.Errorf("after second drain, len = %d, want 0", len(ch))
	}
}

// TestRelayConnStateString pins the lowercase rendering of each RelayConnState,
// including the out-of-range fallback (relay_actor.go:75).
func TestRelayConnStateString(t *testing.T) {
	tests := []struct {
		s    RelayConnState
		want string
	}{
		{RelayConnecting, "connecting"},
		{RelayConnected, "connected"},
		{RelayDisconnected, "disconnected"},
		{RelayConnState(7), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("RelayConnState(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

// TestRemoteStateActorID checks ID returns the endpoint the actor manages.
func TestRemoteStateActorID(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointID(t)
	a := m.Actor(id)
	if !a.ID().Equal(id) {
		t.Errorf("ID() = %s, want %s", a.ID(), id)
	}
}

// TestRemoteStateActorPathEvents checks PathEvents returns a fresh subscription
// that receives events and a cancel that closes the channel.
func TestRemoteStateActorPathEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	ch, cancelSub := a.PathEvents()

	// Adding a connection drives Opened/Selected events to all subscribers,
	// including this one.
	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 4243))
	c := newFakeConn(addr, 5*time.Millisecond)
	defer c.Close()
	m.AddConnection(a.ID(), c)

	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("PathEvents channel closed before any event")
		}
		if ev.Kind != PathEventOpened && ev.Kind != PathEventSelected {
			t.Errorf("event kind = %v, want opened or selected", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PathEvents subscription received no event")
	}

	// Cancelling the subscription closes its channel.
	cancelSub()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // closed: success
			}
		case <-deadline:
			t.Fatal("PathEvents channel not closed after cancel")
		}
	}
}

// TestRemoteMapDropIfStopped checks the identity guard in dropIfStopped: it
// removes the actor only when the instance passed is the one registered under id
// (remotemap.go:156). The "is it stopped" decision is the caller's
// (AddConnection guards on donec before calling); dropIfStopped's own invariant
// is that it never evicts a *different* actor that has since taken the id, which
// is what makes the spawn/teardown retry in AddConnection safe (O12).
func TestRemoteMapDropIfStopped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	id := testEndpointID(t)

	// A stale actor reference whose registration was already replaced must not
	// evict the current actor: m.actors[id] != stale, so dropIfStopped is a
	// no-op. Use the live actor's own pointer offset by a fresh, unregistered
	// actor under a different id to stand in as "stale for this id".
	current := m.Actor(id)
	other := m.Actor(testEndpointID(t)) // registered under a different id
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2 after two distinct Actor() calls", m.Len())
	}

	// dropIfStopped(id, other): other != m.actors[id], so nothing is removed.
	m.dropIfStopped(id, other)
	if m.Len() != 2 {
		t.Errorf("dropIfStopped with a non-matching actor evicted something; Len = %d, want 2", m.Len())
	}
	if got := m.Actor(id); got != current {
		t.Error("dropIfStopped with a non-matching actor replaced the live actor")
	}

	// dropIfStopped(id, current): current == m.actors[id], so it is removed,
	// freeing the id for a fresh actor on the next reference.
	m.dropIfStopped(id, current)
	if got := m.Actor(id); got == current {
		t.Error("after dropIfStopped(id, current), Actor returned the dropped actor")
	}
}

// TestTriggerHolepunchSentinel asserts the no-negotiated-extension contract
// using errors.Is against the exact ErrExtensionNotNegotiated sentinel.
// Hole-punching must fail closed when no active connection negotiated QNT,
// never silently pretend success.
func TestTriggerHolepunchSentinel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))
	err := a.TriggerHolepunch()
	if !errors.Is(err, ErrExtensionNotNegotiated) {
		t.Errorf("TriggerHolepunch() = %v, want errors.Is ErrExtensionNotNegotiated", err)
	}
}

func TestValidateDirectPathAfterMultipathNegotiated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))
	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}

	if err := a.ValidateDirectPath(ctx); err != nil {
		t.Fatalf("ValidateDirectPath: %v", err)
	}
	if conn.openPathCalls.Load() != 1 {
		t.Fatalf("OpenPath calls = %d, want 1", conn.openPathCalls.Load())
	}
	if conn.initiateRoundCalls.Load() != 0 {
		t.Fatalf("InitiateNATTraversalRound calls = %d, want 0", conn.initiateRoundCalls.Load())
	}
}

func TestValidateDirectPathRequiresMultipath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))
	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}
	if err := a.ValidateDirectPath(ctx); !errors.Is(err, ErrExtensionNotNegotiated) {
		t.Fatalf("ValidateDirectPath = %v, want %v", err, ErrExtensionNotNegotiated)
	}
	if conn.openPathCalls.Load() != 0 {
		t.Fatalf("OpenPath calls = %d, want 0", conn.openPathCalls.Load())
	}
}

func TestTriggerHolepunchAfterMultipathNegotiated(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))
	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}
	candidates := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:1111"),
		netip.MustParseAddrPort("[2001:db8::10]:2222"),
	}
	if err := a.AddNATTraversalAddresses(candidates); err != nil {
		t.Fatalf("AddNATTraversalAddresses: %v", err)
	}

	err := a.TriggerHolepunch()
	if errors.Is(err, ErrExtensionNotNegotiated) {
		t.Fatalf("TriggerHolepunch() = %v, still reports extension not negotiated", err)
	}
	if err != nil {
		t.Fatalf("TriggerHolepunch() = %v, want nil", err)
	}
	if conn.initiateRoundCalls.Load() != 1 {
		t.Fatalf("InitiateNATTraversalRound calls = %d, want 1", conn.initiateRoundCalls.Load())
	}
	if conn.openPathCalls.Load() != 0 {
		t.Fatalf("OpenPath calls = %d, want 0", conn.openPathCalls.Load())
	}
	if len(conn.natAddrs) != 2*len(candidates) {
		t.Fatalf("advertised addrs = %v, want AddNATTraversalAddresses plus TriggerHolepunch re-advertise", conn.natAddrs)
	}
	for i, want := range append(candidates, candidates...) {
		if conn.natAddrs[i] != want {
			t.Fatalf("advertised addr %d = %v, want %v", i, conn.natAddrs[i], want)
		}
	}
}

func TestActorMultipathPathsDoNotFabricateQNGRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	conn := newFakeConn(addr, time.Millisecond)
	conn.paths = []PathInfo{{ID: 1, Validated: true}}
	events, ok := a.AddConnection(conn)
	if !ok {
		t.Fatal("AddConnection failed")
	}
	select {
	case ev := <-events:
		if ev.Kind != PathEventOpened && ev.Kind != PathEventSelected {
			t.Fatalf("first path event = %v, want opened or selected", ev.Kind)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connection path event")
	}

	paths := a.MultipathPaths()
	if len(paths) != 1 {
		t.Fatalf("MultipathPaths len = %d, want 1; paths=%v", len(paths), paths)
	}
	if paths[0].ID != 1 || !paths[0].Validated || paths[0].HasAddr {
		t.Fatalf("MultipathPaths()[0] = %+v, want path 1 validated without addr", paths[0])
	}
	a.mu.Lock()
	if _, known := a.paths.Status(addr); !known {
		a.mu.Unlock()
		t.Fatalf("original connection path %s not registered", addr)
	}
	got := a.paths.Addrs()
	a.mu.Unlock()
	if len(got) != 1 || got[0].String() != addr.String() {
		t.Fatalf("RemotePathState addrs = %v, want only original %s", got, addr)
	}
}

func TestActorMultipathPathsEmitQNGRouteEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	addr := IPAddr(netip.MustParseAddrPort("192.0.2.1:4433"))
	route := IPAddr(netip.MustParseAddrPort("[2001:db8::1]:4433"))
	conn := newFakeConn(addr, time.Millisecond)
	conn.paths = []PathInfo{{ID: 1, Validated: true, Addr: route, HasAddr: true}}
	events, ok := a.AddConnection(conn)
	if !ok {
		t.Fatal("AddConnection failed")
	}

	var sawOpened, sawSelected bool
	deadline := time.After(2 * time.Second)
	for !sawOpened || !sawSelected {
		select {
		case ev := <-events:
			if ev.Addr.String() != route.String() {
				continue
			}
			switch ev.Kind {
			case PathEventOpened:
				sawOpened = true
			case PathEventSelected:
				sawSelected = true
			}
		case <-deadline:
			t.Fatalf("timed out waiting for QNT route events; opened=%v selected=%v", sawOpened, sawSelected)
		}
	}

	a.mu.Lock()
	status, known := a.paths.Status(route)
	a.mu.Unlock()
	if !known || status != PathStatusOpen {
		t.Fatalf("QNT route status = %v, %v, want open true", status, known)
	}

	conn.Close()
	deadline = time.After(2 * time.Second)
	for {
		select {
		case ev := <-events:
			if ev.Kind == PathEventClosed && ev.Addr.String() == route.String() {
				a.mu.Lock()
				status, known := a.paths.Status(route)
				selected := a.selected
				a.mu.Unlock()
				if !known || status != PathStatusInactive {
					t.Fatalf("QNT route status after close = %v, %v, want inactive true", status, known)
				}
				if selected != nil && selected.String() == route.String() {
					t.Fatalf("selected route = %s after close", route)
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for QNT route close event")
		}
	}
}

func TestMultipathCandidatesUsePathRTT(t *testing.T) {
	route := IPAddr(netip.MustParseAddrPort("[2001:db8::1]:4433"))
	candidates := appendMultipathCandidates(nil, map[string]struct{}{}, []PathInfo{{
		ID:        1,
		Validated: true,
		Addr:      route,
		HasAddr:   true,
		RTT:       7 * time.Millisecond,
		HasRTT:    true,
	}}, 100*time.Millisecond)
	if len(candidates) != 1 {
		t.Fatalf("candidates len = %d, want 1", len(candidates))
	}
	if candidates[0].RTT != 7*time.Millisecond {
		t.Fatalf("candidate RTT = %v, want per-path RTT", candidates[0].RTT)
	}
}

func TestActorAddConnectionSeedsExistingNATTraversalAddresses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	candidates := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:1111"),
		netip.MustParseAddrPort("[2001:db8::10]:2222"),
	}
	if err := a.AddNATTraversalAddresses(candidates); !errors.Is(err, ErrExtensionNotNegotiated) {
		t.Fatalf("AddNATTraversalAddresses without connections = %v, want %v", err, ErrExtensionNotNegotiated)
	}

	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	events, ok := a.AddConnection(conn)
	if !ok {
		t.Fatal("AddConnection failed")
	}
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	if len(conn.natAddrs) != len(candidates) {
		t.Fatalf("seeded addrs = %v, want %v", conn.natAddrs, candidates)
	}
	for i := range candidates {
		if conn.natAddrs[i] != candidates[i] {
			t.Fatalf("seeded addr %d = %v, want %v", i, conn.natAddrs[i], candidates[i])
		}
	}
}

func TestActorAddNATTraversalAddressesHandoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}

	addrs := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:1111"),
		netip.MustParseAddrPort("[2001:db8::10]:2222"),
	}
	if err := a.AddNATTraversalAddresses(addrs); err != nil {
		t.Fatalf("AddNATTraversalAddresses: %v", err)
	}
	if len(conn.natAddrs) != len(addrs) {
		t.Fatalf("forwarded addrs = %v, want %v", conn.natAddrs, addrs)
	}
	for i := range addrs {
		if conn.natAddrs[i] != addrs[i] {
			t.Fatalf("forwarded addr %d = %v, want %v", i, conn.natAddrs[i], addrs[i])
		}
	}
}

func TestActorNATTraversalAddresses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	if addrs, err := a.NATTraversalAddresses(); !errors.Is(err, ErrExtensionNotNegotiated) {
		t.Fatalf("NATTraversalAddresses without QNT = %v, %v, want ErrExtensionNotNegotiated", addrs, err)
	}

	addr1 := netip.MustParseAddrPort("192.0.2.10:1111")
	addr2 := netip.MustParseAddrPort("[2001:db8::10]:2222")
	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	conn.remoteNAT = []netip.AddrPort{addr1, addr2, addr1}
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}

	addrs, err := a.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	want := []netip.AddrPort{addr1, addr2}
	if len(addrs) != len(want) {
		t.Fatalf("NATTraversalAddresses = %v, want %v", addrs, want)
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Fatalf("NATTraversalAddresses[%d] = %v, want %v", i, addrs[i], want[i])
		}
	}
}

func TestActorAddRemoteNATTraversalAddressesHandoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}

	addrs := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.10:1111"),
		netip.MustParseAddrPort("[2001:db8::10]:2222"),
	}
	if err := a.AddRemoteNATTraversalAddresses(addrs); err != nil {
		t.Fatalf("AddRemoteNATTraversalAddresses: %v", err)
	}
	if len(conn.remoteNAT) != len(addrs) {
		t.Fatalf("forwarded remote addrs = %v, want %v", conn.remoteNAT, addrs)
	}
	for i := range addrs {
		if conn.remoteNAT[i] != addrs[i] {
			t.Fatalf("forwarded remote addr %d = %v, want %v", i, conn.remoteNAT[i], addrs[i])
		}
	}
}

func TestActorAddNATTraversalAddressesCanonicalizesAndDedups(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}

	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.10]:1111")
	canon := netip.MustParseAddrPort("192.0.2.10:1111")
	if err := a.AddNATTraversalAddresses([]netip.AddrPort{
		mapped,
		canon,
		netip.AddrPort{},
		netip.MustParseAddrPort("192.0.2.11:0"),
	}); err != nil {
		t.Fatalf("AddNATTraversalAddresses: %v", err)
	}
	if len(conn.natAddrs) != 1 || conn.natAddrs[0] != canon {
		t.Fatalf("forwarded addrs = %v, want [%v]", conn.natAddrs, canon)
	}

	if err := a.TriggerHolepunch(); err != nil {
		t.Fatalf("TriggerHolepunch: %v", err)
	}
	if conn.initiateRoundCalls.Load() != 1 {
		t.Fatalf("InitiateNATTraversalRound calls = %d, want 1", conn.initiateRoundCalls.Load())
	}
	if len(conn.natAddrs) != 2 || conn.natAddrs[1] != canon {
		t.Fatalf("forwarded addrs after TriggerHolepunch = %v, want two canonical entries", conn.natAddrs)
	}
}

func TestActorAddNATTraversalAddressesRemovesStaleCandidates(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))

	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}

	oldAddr := netip.MustParseAddrPort("192.0.2.10:1111")
	newAddr := netip.MustParseAddrPort("192.0.2.11:2222")
	if err := a.AddNATTraversalAddresses([]netip.AddrPort{oldAddr}); err != nil {
		t.Fatalf("first AddNATTraversalAddresses: %v", err)
	}
	if err := a.AddNATTraversalAddresses([]netip.AddrPort{newAddr}); err != nil {
		t.Fatalf("replacement AddNATTraversalAddresses: %v", err)
	}
	if len(conn.removedNAT) != 1 || conn.removedNAT[0] != oldAddr {
		t.Fatalf("removed NAT candidates = %v, want [%v]", conn.removedNAT, oldAddr)
	}

	if err := a.TriggerHolepunch(); err != nil {
		t.Fatalf("TriggerHolepunch: %v", err)
	}
	if got := conn.natAddrs[len(conn.natAddrs)-1]; got != newAddr {
		t.Fatalf("TriggerHolepunch re-advertised %v, want only replacement %v", got, newAddr)
	}
}

func TestTriggerHolepunchInitiateRoundError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewRemoteMap(ctx, BiasedRttPathSelector{}, nil)
	a := m.Actor(testEndpointID(t))
	want := errors.New("round refused")
	conn := newFakeConn(IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9)), time.Millisecond)
	conn.multipathNegotiated = true
	conn.initiateRound = func(context.Context) ([]netip.AddrPort, error) { return nil, want }
	if _, ok := a.AddConnection(conn); !ok {
		t.Fatal("AddConnection failed")
	}

	err := a.TriggerHolepunch()
	if !errors.Is(err, want) {
		t.Fatalf("TriggerHolepunch() = %v, want wrapped %v", err, want)
	}
	if conn.openPathCalls.Load() != 0 {
		t.Fatalf("OpenPath calls = %d, want 0", conn.openPathCalls.Load())
	}
}

// TestSocketCustomMappedAddrFor checks the custom mapped-address table is stable
// for the same CustomAddr and that LookupCustom round-trips it (socket.go:101,
// 137).
func TestSocketCustomMappedAddrFor(t *testing.T) {
	s := NewSocket()
	c := netaddr.CustomAddr{}

	m1 := s.CustomMappedAddrFor(c)
	m2 := s.CustomMappedAddrFor(c)
	if m1 != m2 {
		t.Error("CustomMappedAddrFor is not stable for the same CustomAddr")
	}
	if Classify(m1.Addr()) != KindCustom {
		t.Errorf("custom mapped addr %s did not classify as custom", m1.Addr())
	}

	got, ok := s.LookupCustom(m1)
	if !ok {
		t.Fatal("LookupCustom(known) ok = false, want true")
	}
	if got.String() != c.String() {
		t.Errorf("LookupCustom = %s, want %s", got, c)
	}

	// An unregistered custom mapped address is unknown.
	if _, ok := s.LookupCustom(NewCustomMappedAddr()); ok {
		t.Error("LookupCustom(unknown) ok = true, want false")
	}
}

// TestSocketPathAddr checks PathAddr classifies a real IP as an IP path, a
// registered relay mapped ULA back to its RelayAddr, and an unknown mapped ULA
// down to a fallback IP path (socket.go:115).
func TestSocketPathAddr(t *testing.T) {
	s := NewSocket()
	u, _ := netaddr.ParseRelayURL("https://relay.example.")
	sk, _ := key.GenerateSecretKey()
	eid := sk.Public().EndpointID()

	// Real IP -> IP path, port preserved.
	realIP := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 9}), 443))
	got := s.PathAddr(eid, realIP)
	if ap, ok := got.IP(); !ok {
		t.Errorf("PathAddr(real IP) kind = %v, want IP", got.Kind())
	} else if ap.Port() != 443 {
		t.Errorf("PathAddr(real IP) port = %d, want 443", ap.Port())
	}

	// Registered relay mapped ULA -> RelayAddr with the original (url, eid).
	relayMapped := s.RelayMappedAddrFor(u, eid)
	gotRelay := s.PathAddr(eid, mappedUDPAddr(relayMapped.Addr()))
	if gu, ge, ok := gotRelay.Relay(); !ok {
		t.Errorf("PathAddr(relay mapped) kind = %v, want relay", gotRelay.Kind())
	} else if !gu.Equal(u) || !ge.Equal(eid) {
		t.Errorf("PathAddr(relay mapped) = (%s, %s), want (%s, %s)", gu, ge, u, eid)
	}

	// Unknown relay mapped ULA (never registered) -> fallback IP path.
	unknown := NewRelayMappedAddr()
	gotFallback := s.PathAddr(eid, mappedUDPAddr(unknown.Addr()))
	if _, ok := gotFallback.IP(); !ok {
		t.Errorf("PathAddr(unknown mapped) kind = %v, want IP fallback", gotFallback.Kind())
	}
}

// TestIpTransportLocalAddr checks LocalAddr reflects the bound UDP socket
// (ip.go:33).
func TestIpTransportLocalAddr(t *testing.T) {
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()

	ch := make(chan recvBatch, 1)
	tr := NewIpTransport(udp, ch)
	if tr.LocalAddr().String() != udp.LocalAddr().String() {
		t.Errorf("LocalAddr() = %s, want %s", tr.LocalAddr(), udp.LocalAddr())
	}
}

// TestRelayTransportSetHomeAndStatus checks the RelayTransport delegates
// SetHomeRelay and HomeRelayStatus to its actor: setting the home relay drives
// the watcher to a connected status for that URL (relay.go:115,119).
func TestRelayTransportSetHomeAndStatus(t *testing.T) {
	client := newFakeRelayClient()
	a, _ := startActorWith(t, client)
	sock := NewSocket()
	recvCh := make(chan recvBatch, 8)
	rt := NewRelayTransport(sock, a, recvCh)

	w := rt.HomeRelayStatus()
	url := testURL(t)
	rt.SetHomeRelay(url)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		st, err := w.Updated(ctx)
		if err != nil {
			t.Fatalf("watcher: %v", err)
		}
		if st != nil && st.URL.Equal(url) && st.IsConnected() {
			return
		}
	}
}

// TestRelayTransportServeForwardsRecv drives the full Serve/forwardRecv/deliver
// path: a relay-to-client datagram fed through the fake client surfaces on the
// transport's recv channel as a recvBatch tagged with the relay Addr, and a
// GRO-batched datagram is split into one recvBatch per segment
// (relay.go:35,46,62).
func TestRelayTransportServeForwardsRecv(t *testing.T) {
	client := newFakeRelayClient()
	// Build the actor but do not run it here: RelayTransport.Serve runs it
	// exactly once. (startActorWith would run a second Run, double-closing recvCh.)
	sk, _ := key.GenerateSecretKey()
	a := NewRelayActor(RelayActorConfig{
		SecretKey: sk,
		dialer:    func(context.Context, netaddr.RelayURL, relayclient.Options) (relayClient, error) { return client, nil },
	})
	sock := NewSocket()
	recvCh := make(chan recvBatch, 16)
	rt := NewRelayTransport(sock, a, recvCh)

	ctx, cancel := context.WithCancel(context.Background())
	go rt.Serve(ctx)
	t.Cleanup(cancel)

	url := testURL(t)
	src, _ := key.GenerateSecretKey()
	a.SetHomeRelay(url)

	// Kick the active relay alive so it begins draining recv frames.
	dst, _ := key.GenerateSecretKey()
	a.Send(RelaySendItem{RemoteEndpoint: dst.Public().EndpointID(), URL: url, Datagrams: relayproto.DatagramsFromBytes([]byte("x"))})
	waitDatagramSend(t, client)

	// A GRO batch with segment size 2 over 6 bytes -> three recvBatches.
	client.recv <- relayproto.RelayToClientMsg{
		Type:             relayproto.FrameRelayToClientDatagramBat,
		RemoteEndpointID: src.Public().EndpointID(),
		Datagrams:        relayproto.Datagrams{SegmentSize: 2, Contents: []byte("aabbcc")},
	}

	select {
	case b := <-recvCh:
		if got := batchSegments(b); !slices.Equal(got, []string{"aa", "bb", "cc"}) {
			t.Errorf("segments = %q", got)
		}
		// The batch must be tagged with the relay Addr it arrived on.
		gu, ge, ok := b.info.Remote.Relay()
		if !ok {
			t.Errorf("Remote kind = %v, want relay", b.info.Remote.Kind())
		} else if !gu.Equal(url) || !ge.Equal(src.Public().EndpointID()) {
			t.Errorf("Remote = (%s, %s), want (%s, %s)", gu, ge, url, src.Public().EndpointID())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for batch")
	}
}

// batchSegments splits b the way MagicConn.ReadFrom does.
func batchSegments(b recvBatch) []string {
	var out []string
	d := b.data
	for len(d) > 0 {
		n := len(d)
		if b.stride > 0 && n > b.stride {
			n = b.stride
		}
		out = append(out, string(d[:n]))
		d = d[n:]
	}
	return out
}

// TestRelayTransportDeliverSegments unit-tests deliver directly: an 8-byte
// datagram with segment size 3 yields three recvBatches of 3, 3, 2 bytes, and a
// cancelled context stops delivery early (relay.go:62).
func TestRelayTransportDeliverSegments(t *testing.T) {
	sock := NewSocket()
	recvCh := make(chan recvBatch, 8)
	rt := NewRelayTransport(sock, NewRelayActor(RelayActorConfig{}), recvCh)

	url := testURL(t)
	src, _ := key.GenerateSecretKey()
	dm := RelayRecvDatagram{
		URL:       url,
		Src:       src.Public().EndpointID(),
		Datagrams: relayproto.Datagrams{SegmentSize: 3, Contents: []byte("aaabbbcc")},
	}

	rt.deliver(context.Background(), dm)
	select {
	case b := <-recvCh:
		if got := batchSegments(b); !slices.Equal(got, []string{"aaa", "bbb", "cc"}) {
			t.Errorf("segments = %q", got)
		}
	default:
		t.Fatal("missing batch")
	}

	// A cancelled context makes deliver return before enqueuing into a full
	// channel; with no reader, only the channel's free slots fill, then it stops.
	full := make(chan recvBatch) // unbuffered, no reader -> blocks immediately
	rt2 := NewRelayTransport(sock, NewRelayActor(RelayActorConfig{}), full)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		rt2.deliver(ctx, dm)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deliver did not return on cancelled context")
	}
}

// TestDefaultRelayDialer checks the default dialer attempts a real relayclient
// connection. With no usable relay reachable the dial fails (or the supplied
// already-cancelled context aborts it); either way it must return promptly
// without panicking, exercising the relayclient.Connect indirection
// (relay_actor.go:143).
func TestDefaultRelayDialer(t *testing.T) {
	url := testURL(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // abort before any network work

	sk, _ := key.GenerateSecretKey()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := defaultRelayDialer(ctx, url, relayclient.Options{SecretKey: sk})
		if err == nil && c != nil {
			c.Close()
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("defaultRelayDialer did not return on a cancelled context")
	}
}

// TestMagicConnRelayAccessor pins the Relay accessor (nil without a relay actor,
// non-nil with one) and the SetDeadline/SetWriteDeadline behavior. SyscallConn,
// SetReadBuffer and SetWriteBuffer delegate to the underlying live UDP socket and
// so succeed here; this test pins the accessor and deadline surface that has no
// UDP delegation failure mode (transport.go:83,198,213).
func TestMagicConnRelayAccessor(t *testing.T) {
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	sock := NewSocket()

	// No relay actor: Relay() is nil.
	m := NewMagicConn(sock, udp)
	if m.Relay() != nil {
		t.Error("MagicConn without relay actor: Relay() != nil")
	}

	// With a relay actor: Relay() is non-nil.
	udp2, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer udp2.Close()
	a := NewRelayActor(RelayActorConfig{})
	m2 := NewMagicConnWithRelay(NewSocket(), udp2, a)
	if m2.Relay() == nil {
		t.Error("MagicConn with relay actor: Relay() == nil")
	}

	// SetDeadline(future) then SetDeadline(zero) clears: a read after the future
	// deadline expires returns a timeout, but a cleared deadline does not.
	m.SetDeadline(time.Now().Add(-time.Second))
	if _, _, err := m.ReadFrom(make([]byte, 8)); err == nil {
		t.Error("ReadFrom after past SetDeadline returned nil error, want timeout")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Errorf("ReadFrom err = %v, want timeout net.Error", err)
	}
	// Clear the deadline; SetWriteDeadline is accepted (no enforcement on WriteTo).
	if err := m.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline(zero) = %v, want nil", err)
	}
	if err := m.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Errorf("SetWriteDeadline = %v, want nil", err)
	}
	// WriteTo still succeeds (deadline not enforced on the blackhole path).
	if n, err := m.WriteTo([]byte("hi"), net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 9))); err != nil || n != 2 {
		t.Errorf("WriteTo after SetWriteDeadline = (%d, %v), want (2, nil)", n, err)
	}

	m.Close()
}

// TestReadFromSplitsBatch checks ReadFrom hands out one segment per call from a
// strided recvBatch and releases the batch after the last one.
func TestReadFromSplitsBatch(t *testing.T) {
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	m := NewMagicConnWithTransports(NewSocket(), udp, nil)
	released := 0
	src := netip.MustParseAddrPort("192.0.2.1:7")
	m.recvCh <- recvBatch{data: []byte("aaabbbcc"), stride: 3, ip: src, releaseFn: func() { released++ }}
	buf := make([]byte, 16)
	for i, want := range []string{"aaa", "bbb", "cc"} {
		n, addr, err := m.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:n]) != want {
			t.Errorf("segment %d = %q, want %q", i, buf[:n], want)
		}
		if addr.(*net.UDPAddr).AddrPort() != src {
			t.Errorf("segment %d addr = %v", i, addr)
		}
		if i < 2 && released != 0 {
			t.Errorf("released before last segment")
		}
	}
	if released != 1 {
		t.Errorf("released = %d, want 1", released)
	}
	if got := m.Metrics().RecvDatagrams; got != 3 {
		t.Errorf("RecvDatagrams = %d, want 3", got)
	}
}
