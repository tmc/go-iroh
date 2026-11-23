package gossip

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// TestTopicLaggedReportsGapAndKeepsStream checks that a subscriber that falls
// behind loses the dropped events but keeps the stream: the gap is reported
// once, as a Lagged event, and delivery resumes.
func TestTopicLaggedReportsGapAndKeepsStream(t *testing.T) {
	topic := &Topic{events: make(chan Event, 2)}
	topic.sendEvent(Event{Kind: NeighborUp})
	topic.sendEvent(Event{Kind: NeighborUp})
	topic.sendEvent(Event{Kind: Received})     // no room: dropped
	topic.sendEvent(Event{Kind: NeighborDown}) // no room: dropped

	if got := (<-topic.events).Kind; got != NeighborUp {
		t.Fatalf("first event = %v, want NeighborUp", got)
	}
	if got := (<-topic.events).Kind; got != NeighborUp {
		t.Fatalf("second event = %v, want NeighborUp", got)
	}
	if topic.isClosed() {
		t.Fatal("topic closed by a dropped event")
	}

	topic.sendEvent(Event{Kind: Received})
	ev := <-topic.events
	if ev.Kind != Lagged {
		t.Fatalf("event after gap = %v, want Lagged", ev.Kind)
	}
	if ev.Dropped != 2 {
		t.Fatalf("Lagged Dropped = %d, want 2", ev.Dropped)
	}
	if got := (<-topic.events).Kind; got != Received {
		t.Fatalf("event after Lagged = %v, want Received", got)
	}

	// One gap reports once: the stream is caught up again.
	topic.sendEvent(Event{Kind: NeighborDown})
	if got := (<-topic.events).Kind; got != NeighborDown {
		t.Fatalf("next event = %v, want NeighborDown", got)
	}

	topic.closeEvents()
	if _, ok := <-topic.events; ok {
		t.Fatal("events still open after closeEvents")
	}
}

// TestFinishUnwantedTopicStream checks that when a peer leaves one of two
// shared topics, the departed topic's send stream is closed while the
// remaining topic's stream and connection stay open.
func TestFinishUnwantedTopicStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	bindNode := func() (*iroh.Endpoint, *Gossip, *iroh.Router) {
		ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
		if err != nil {
			t.Fatalf("bind: %v", err)
		}
		g := NewGossip(ep)
		r, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{ALPN: g.Handler()}, nil)
		if err != nil {
			t.Fatalf("router: %v", err)
		}
		t.Cleanup(func() { _ = r.Shutdown(context.Background()) })
		return ep, g, r
	}

	epA, gA, _ := bindNode()
	epB, gB, _ := bindNode()
	addrA := netaddr.NewEndpointAddr(epA.ID()).WithIP(epA.LocalAddr())
	peerB := peerIDFromEndpoint(epB.ID())

	var t1ID, t2ID TopicID
	t1ID[0] = 1
	t2ID[0] = 2

	a1, err := gA.Subscribe(ctx, t1ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a1.Close()
	a2, err := gA.Subscribe(ctx, t2ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()

	b1, err := gB.SubscribeAndJoin(ctx, t1ID, []netaddr.EndpointAddr{addrA})
	if err != nil {
		t.Fatal(err)
	}
	defer b1.Close()
	b2, err := gB.SubscribeAndJoin(ctx, t2ID, []netaddr.EndpointAddr{addrA})
	if err != nil {
		t.Fatal(err)
	}

	if err := a1.Joined(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a2.Joined(ctx); err != nil {
		t.Fatal(err)
	}

	// Send one message on each topic from A so both topic streams are open on A->B.
	if err := a1.Broadcast(ctx, []byte("keep")); err != nil {
		t.Fatal(err)
	}
	if err := a2.Broadcast(ctx, []byte("drop")); err != nil {
		t.Fatal(err)
	}

	waitOpen := func(topic TopicID, want bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			gA.mu.Lock()
			s := gA.peerSenders[peerB]
			gA.mu.Unlock()
			if s != nil && s.hasOpenStream(topic) == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("topic %x stream open != %v before deadline", topic[:4], want)
	}

	waitOpen(t1ID, true)
	waitOpen(t2ID, true)

	// B leaves topic 2; A should finish topic 2's stream while keeping topic 1's stream open.
	if err := b2.Close(); err != nil {
		t.Fatal(err)
	}
	waitOpen(t2ID, false)
	waitOpen(t1ID, true)
}
