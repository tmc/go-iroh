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
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		var topic gossip.TopicID
		copy(topic[:], "rejoin")

		n := irohtest.NewNet(t)
		srv, gs := netGossipPeer(t, n)
		_, gc := netGossipPeer(t, n)

		tc, err := gc.Subscribe(ctx, topic, []netaddr.EndpointAddr{srv.Addr()})
		if err != nil {
			t.Fatal(err)
		}
		defer tc.Close()
		time.Sleep(100 * time.Millisecond) // let the Join arrive
		synctest.Wait()

		ts, err := gs.Subscribe(ctx, topic, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ts.Close()
		irohtest.Within(t, 5*time.Second, tc.Joined)
	})
}
