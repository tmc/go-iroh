package gossip_test

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/netaddr"
)

// TestJoinBeforeBootstrapSubscribes checks that a topic still gets its
// bootstrap peer as a neighbor when its first Join arrived, and was dropped,
// before that peer subscribed.
func TestJoinBeforeBootstrapSubscribes(t *testing.T) {
	joins := []struct {
		name string
		join func(ctx context.Context, gc *gossip.Gossip, topic gossip.TopicID, srv netaddr.EndpointAddr) (*gossip.Topic, error)
	}{
		{"Subscribe", func(ctx context.Context, gc *gossip.Gossip, topic gossip.TopicID, srv netaddr.EndpointAddr) (*gossip.Topic, error) {
			return gc.Subscribe(ctx, topic, []netaddr.EndpointAddr{srv})
		}},
		{"JoinPeers", func(ctx context.Context, gc *gossip.Gossip, topic gossip.TopicID, srv netaddr.EndpointAddr) (*gossip.Topic, error) {
			tc, err := gc.Subscribe(ctx, topic, nil)
			if err != nil {
				return nil, err
			}
			return tc, tc.JoinPeers(ctx, []netaddr.EndpointAddr{srv})
		}},
	}
	for _, j := range joins {
		t.Run(j.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				var topic gossip.TopicID
				copy(topic[:], "rejoin")

				n := irohtest.NewNet(t)
				srv, gs := netGossipPeer(t, n)
				_, gc := netGossipPeer(t, n)

				start := time.Now()
				tc, err := j.join(ctx, gc, topic, srv.Addr())
				if err != nil {
					t.Fatal(err)
				}
				defer tc.Close()
				// Wait for the server to receive the first Join and, with
				// no topic to give it to, drop it.
				for gs.Metrics().MsgsCtrlRecv == 0 {
					time.Sleep(time.Millisecond)
				}
				synctest.Wait()
				if d := time.Since(start); d >= gossip.RejoinDelay {
					t.Fatalf("first Join took %v, want < %v", d, gossip.RejoinDelay)
				}

				ts, err := gs.Subscribe(ctx, topic, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer ts.Close()
				irohtest.Within(t, 5*time.Second, tc.Joined)
			})
		})
	}
}
