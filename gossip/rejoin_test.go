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
					if time.Since(start) >= gossip.RejoinDelay {
						t.Fatalf("first Join not received within %v", gossip.RejoinDelay)
					}
					time.Sleep(time.Millisecond)
				}
				synctest.Wait()

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

// TestRepeatedJoinPeersRetriesOnce checks that joining the same peer again
// adds nothing to the topic's Join retries.
func TestRepeatedJoinPeersRetriesOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		var topic gossip.TopicID
		copy(topic[:], "rejoin")

		n := irohtest.NewNet(t)
		srv, gs := netGossipPeer(t, n)
		_, gc := netGossipPeer(t, n)
		bootstrap := []netaddr.EndpointAddr{srv.Addr()}

		tc, err := gc.Subscribe(ctx, topic, bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		defer tc.Close()
		const joins = 10
		for range joins - 1 {
			if err := tc.JoinPeers(ctx, bootstrap); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(gossip.RejoinDelay / 2)
		synctest.Wait()
		if got := gs.Metrics().MsgsCtrlRecv; got != joins {
			t.Fatalf("server received %d Joins, want %d", got, joins)
		}

		// Retries go out after 1s, 3s and 7s.
		time.Sleep(7 * gossip.RejoinDelay)
		synctest.Wait()
		if got := gs.Metrics().MsgsCtrlRecv - joins; got != 3 {
			t.Errorf("server received %d retried Joins, want 3", got)
		}
	})
}
