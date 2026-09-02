package gossip

import "testing"

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
