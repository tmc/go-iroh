package gossip

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// receive releases g.mu before dispatching its outputs. A topic can close and
// reopen in that interval; the old outputs must not change the new topic.
func TestTopicReopenIgnoresPendingNeighborEvents(t *testing.T) {
	for _, tt := range []struct {
		name   string
		kind   gossipproto.TopicEventKind
		joined bool
	}{
		{"up", gossipproto.TopicNeighborUp, false},
		{"down", gossipproto.TopicNeighborDown, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
			if err != nil {
				t.Fatal(err)
			}
			defer ep.Shutdown(ctx)
			g := NewGossip(ep)
			defer g.Shutdown(ctx)
			secret, err := key.GenerateSecretKey()
			if err != nil {
				t.Fatal(err)
			}
			peer := peerIDFromEndpoint(secret.Public().EndpointID())
			id := TopicID{1}
			old, err := g.Subscribe(ctx, id, nil)
			if err != nil {
				t.Fatal(err)
			}

			// Generate real protocol outputs, but hold their dispatch so the
			// close/reopen ordering is deterministic and needs no sleeps.
			join := gossipproto.InEvent{
				Kind: gossipproto.RecvMessage, From: peer, Now: time.Now(),
				Message: gossipproto.Message{Topic: id, Message: gossipproto.TopicMessage{
					Kind:  gossipproto.TopicMessageSwarm,
					Swarm: gossipproto.HyparviewMessage{Kind: gossipproto.HyparviewJoin},
				}},
			}
			g.mu.Lock()
			pending := g.handleLocked(join)
			if tt.kind == gossipproto.TopicNeighborDown {
				pending = g.handleLocked(gossipproto.InEvent{Kind: gossipproto.PeerDisconnected, Peer: peer, Now: time.Now()})
			}
			g.mu.Unlock()
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			fresh, err := g.Subscribe(ctx, id, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()

			// Dispatch only local events: this test controls lifecycle ordering,
			// and does not need a connection to the simulated protocol peer.
			dispatch := func(events []gossipproto.OutEvent) int {
				n := 0
				for _, ev := range events {
					if ev.Kind == gossipproto.EmitEvent {
						g.dispatch(context.Background(), []gossipproto.OutEvent{ev})
						n++
					}
				}
				return n
			}
			if tt.joined {
				g.mu.Lock()
				current := g.handleLocked(join)
				g.mu.Unlock()
				if dispatch(current) != 1 {
					t.Fatal("missing new topic's NeighborUp")
				}
				select {
				case ev := <-fresh.events:
					if ev.Kind != NeighborUp {
						t.Fatalf("new topic event = %v, want NeighborUp", ev.Kind)
					}
				default:
					t.Fatal("new topic did not receive NeighborUp")
				}
			}
			if got := fresh.IsJoined(); got != tt.joined {
				t.Fatalf("IsJoined before delayed event = %v, want %v", got, tt.joined)
			}
			if dispatch(pending) != 1 {
				t.Fatal("missing pending neighbor event")
			}
			g.mu.Lock()
			active := g.state.HasActivePeers(id)
			g.mu.Unlock()
			if active != tt.joined {
				t.Fatalf("protocol has active peers = %v, want %v", active, tt.joined)
			}
			if got := fresh.IsJoined(); got != tt.joined {
				t.Errorf("IsJoined after old %s event = %v, want %v", tt.name, got, tt.joined)
			}
			select {
			case ev := <-fresh.events:
				t.Errorf("new subscription received old event: %v", ev.Kind)
			default:
			}
		})
	}
}
