package gossipproto

import (
	"math/rand"
	"testing"
	"time"
)

func TestHyparviewRejoinsThroughRecentNeighbor(t *testing.T) {
	me := PeerID{1}
	neighbor := PeerID{2}
	s := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), rand.New(rand.NewSource(1)))

	// Neighbor joins us directly (never passed via HandleRequestJoin).
	s.Handle(HyparviewInEvent{
		Kind:    HyparviewRecvMessage,
		From:    neighbor,
		Message: HyparviewMessage{Kind: HyparviewJoin},
	})
	if len(s.ActivePeers()) != 1 {
		t.Fatalf("ActivePeers = %v, want 1 peer", s.ActivePeers())
	}

	// Neighbor disconnects without Alive, emptying both views.
	s.Handle(HyparviewInEvent{
		Kind:    HyparviewRecvMessage,
		From:    neighbor,
		Message: HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: false}},
	})
	if len(s.ActivePeers()) != 0 || len(s.PassivePeers()) != 0 {
		t.Fatalf("expected both views empty, active=%d passive=%d", len(s.ActivePeers()), len(s.PassivePeers()))
	}

	// Maintenance pass when alone should attempt to rejoin through the recent neighbor.
	out := s.Handle(HyparviewInEvent{
		Kind:  HyparviewTimerExpired,
		Timer: HyparviewTimer{Kind: HyparviewTimerDoMaintenance},
	})
	var rejoined bool
	for _, ev := range out {
		if ev.Kind == HyparviewSendMessage && ev.To == neighbor && ev.Message.Kind == HyparviewJoin {
			rejoined = true
		}
	}
	if !rejoined {
		t.Fatal("expected maintenance pass to send Join to recent neighbor")
	}
}

func TestPlumtreeNewlyGraftedPeerNotImmediatelyPruned(t *testing.T) {
	me := PeerID{1}
	peer := PeerID{2}
	now := time.Unix(1000, 0)
	s := NewPlumtreeState(me, DefaultPlumtreeConfig())
	s.Handle(PlumtreeInEvent{Kind: PlumtreeNeighborUp, Neighbor: peer, Now: now})

	// Receive a Graft from peer, which should mark peer as recently grafted.
	s.Handle(PlumtreeInEvent{
		Kind:    PlumtreeRecvMessage,
		From:    peer,
		Message: PlumtreeMessage{Kind: PlumtreeGraft},
		Now:     now,
	})

	content := []byte("hello")
	id := MessageIDFromContent(content)
	msg := PlumtreeMessage{
		Kind: PlumtreeGossip,
		Gossip: Gossip{
			ID:      id,
			Content: content,
			Scope:   DeliveryScope{Kind: DeliveryScopeSwarm},
		},
	}

	// First delivery records the message ID.
	s.Handle(PlumtreeInEvent{Kind: PlumtreeRecvMessage, From: peer, Message: msg, Now: now.Add(10 * time.Millisecond)})

	// Duplicate within the graft grace window must not prune peer.
	out := s.Handle(PlumtreeInEvent{Kind: PlumtreeRecvMessage, From: peer, Message: msg, Now: now.Add(20 * time.Millisecond)})
	for _, ev := range out {
		if ev.Kind == PlumtreeSendMessage && ev.Message.Kind == PlumtreePrune {
			t.Fatal("unexpected Prune sent to newly grafted peer within grace window")
		}
	}

	// Duplicate after the grace window expires should prune peer as usual.
	out = s.Handle(PlumtreeInEvent{Kind: PlumtreeRecvMessage, From: peer, Message: msg, Now: now.Add(5 * time.Second)})
	var pruned bool
	for _, ev := range out {
		if ev.Kind == PlumtreeSendMessage && ev.To == peer && ev.Message.Kind == PlumtreePrune {
			pruned = true
		}
	}
	if !pruned {
		t.Fatal("expected Prune after graft grace window expired")
	}
}
