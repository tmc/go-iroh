package gossip_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// newGossipPeer returns a loopback endpoint serving gossip. Both are shut
// down when the test ends.
func newGossipPeer(ctx context.Context, t *testing.T) (*iroh.Endpoint, *gossip.Gossip) {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	g := gossip.NewGossip(ep)
	r, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{gossip.ALPN: g.Handler()}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_ = r.Shutdown(ctx)
		g.Shutdown(ctx)
		_ = ep.Shutdown(ctx)
	})
	return ep, g
}

// TestGossipTopicResubscribeAfterEarlyClose checks that a peer which closes
// its subscription before the Neighbor answer to its Join arrives is answered
// when it subscribes again. The answering side still holds the peer as active
// with that answer pending, and used to ignore every later Join from it: the
// new subscription got no NeighborUp and its broadcasts reached nobody.
func TestGossipTopicResubscribeAfterEarlyClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "resubscribe")

	a, ga := newGossipPeer(ctx, t)
	_, gb := newGossipPeer(ctx, t)
	aAddr := netaddr.NewEndpointAddr(a.ID()).WithIP(a.LocalAddr())

	ta, err := ga.Subscribe(ctx, topic, nil)
	if err != nil {
		t.Fatalf("a subscribe: %v", err)
	}
	defer ta.Close()

	// Subscribe sends Join to a; Close quits before a's answer is back.
	tb, err := gb.Subscribe(ctx, topic, []netaddr.EndpointAddr{aAddr})
	if err != nil {
		t.Fatalf("b subscribe: %v", err)
	}
	tb.Close()
	time.Sleep(time.Second)

	tb, err = gb.Subscribe(ctx, topic, []netaddr.EndpointAddr{aAddr})
	if err != nil {
		t.Fatalf("b resubscribe: %v", err)
	}
	defer tb.Close()

	up := make(chan struct{})
	go func() {
		for ev, err := range tb.Events() {
			if err != nil {
				return
			}
			if ev.Kind == gossip.NeighborUp {
				close(up)
				return
			}
		}
	}()
	heard := make(chan struct{})
	go func() {
		for ev, err := range ta.Events() {
			if err != nil {
				return
			}
			if ev.Kind == gossip.Received {
				close(heard)
				return
			}
		}
	}()

	deadline := time.After(10 * time.Second)
	select {
	case <-up:
	case <-deadline:
		t.Fatal("b's resubscription never got NeighborUp")
	}
	for {
		if err := tb.Broadcast(ctx, []byte("hello")); err != nil {
			t.Fatalf("broadcast: %v", err)
		}
		select {
		case <-heard:
			return
		case <-deadline:
			t.Fatal("a never heard b's resubscription")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// TestGossipTopicCloseClearsNeighbors checks that closing a topic's last
// subscription forgets its neighbors, so a later subscription starts with
// none rather than reporting the old ones.
func TestGossipTopicCloseClearsNeighbors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var topic gossip.TopicID
	copy(topic[:], "close-clears")

	a, ga := newGossipPeer(ctx, t)
	_, gb := newGossipPeer(ctx, t)
	aAddr := netaddr.NewEndpointAddr(a.ID()).WithIP(a.LocalAddr())

	ta, err := ga.Subscribe(ctx, topic, nil)
	if err != nil {
		t.Fatalf("a subscribe: %v", err)
	}
	defer ta.Close()

	tb, err := gb.SubscribeAndJoin(ctx, topic, []netaddr.EndpointAddr{aAddr})
	if err != nil {
		t.Fatalf("b subscribe and join: %v", err)
	}
	if n := len(tb.Neighbors()); n != 1 {
		t.Fatalf("joined: %d neighbors, want 1", n)
	}
	tb.Close()

	tb, err = gb.Subscribe(ctx, topic, nil)
	if err != nil {
		t.Fatalf("b resubscribe: %v", err)
	}
	defer tb.Close()
	if got := tb.Neighbors(); len(got) != 0 {
		t.Fatalf("resubscribed without bootstrap: neighbors = %v, want none", got)
	}
	if tb.IsJoined() {
		t.Fatal("resubscribed without bootstrap: IsJoined = true, want false")
	}
}
