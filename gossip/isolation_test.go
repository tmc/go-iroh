package gossip_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// isolationBudget is how long a well-behaved peer may wait for gossip while
// another neighbor misbehaves. The in-memory link adds 1ms each way, so this
// is hundreds of round trips.
const isolationBudget = 5 * time.Second

// netGossipPeer returns a peer on n serving gossip. It is shut down when the
// test ends.
func netGossipPeer(t *testing.T, n *irohtest.Net) (*irohtest.Peer, *gossip.Gossip) {
	t.Helper()
	p := n.Peer(iroh.WithALPNs(gossip.ALPN))
	g := gossip.NewGossip(p.Endpoint)
	r, err := iroh.NewRouter(p.Endpoint, map[string]iroh.ProtocolHandler{gossip.ALPN: g.Handler()}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		g.Shutdown(ctx)
		_ = r.Shutdown(ctx)
	})
	return p, g
}

// joinNeverReading adds a peer on n that joins topic at srvAddr and never
// accepts, so never reads, the stream the server opens to it.
func joinNeverReading(ctx context.Context, t *testing.T, n *irohtest.Net, srvAddr netaddr.EndpointAddr, topic gossip.TopicID) {
	t.Helper()
	bad := n.Peer()
	conn, err := bad.Connect(ctx, srvAddr, gossip.ALPN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	join := gossip.Message{Topic: topic, Message: gossip.TopicMessage{
		Kind:  gossipproto.TopicMessageSwarm,
		Swarm: gossipproto.HyparviewMessage{Kind: gossipproto.HyparviewJoin},
	}}
	if err := gossip.NewSender(conn, 0).Send(ctx, join); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the Join arrive
}

// TestGossipStalledNeighborDoesNotBlockOthers checks that a neighbor which
// stays connected but never reads its gossip stream cannot hold up the rest
// of the topic. Once it has filled QUIC flow control, writes to it block;
// they used to block local Broadcast, and with it delivery to every other
// neighbor, for good. Now the stalled neighbor is dropped.
func TestGossipStalledNeighborDoesNotBlockOthers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var topic gossip.TopicID
		copy(topic[:], "isolation")

		n := irohtest.NewNet(t)
		srv, gs := netGossipPeer(t, n)
		good, gg := netGossipPeer(t, n)
		srvAddr := srv.Addr()

		ts, err := gs.Subscribe(ctx, topic, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ts.Close()
		tg, err := gg.SubscribeAndJoin(ctx, topic, []netaddr.EndpointAddr{srvAddr})
		if err != nil {
			t.Fatal(err)
		}
		defer tg.Close()

		joinNeverReading(ctx, t, n, srvAddr, topic)
		if len(ts.Neighbors()) != 2 {
			t.Fatalf("srv has %d neighbors, want 2", len(ts.Neighbors()))
		}

		// 400 messages of 2 KiB is well past the 512 KiB stream window.
		const count = 400
		content := func(i int) []byte {
			return fmt.Appendf(bytes.Repeat([]byte{'x'}, 2<<10), "%d", i)
		}
		irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
			// A Broadcast stuck in a write does not watch ctx, so wait
			// for it here instead.
			done := make(chan error, 1)
			go func() {
				for i := range count {
					if err := ts.Broadcast(ctx, content(i)); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			select {
			case err := <-done:
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
			stop := context.AfterFunc(ctx, func() { _ = tg.Close() })
			defer stop()
			want := content(count - 1)
			for ev, err := range tg.Events() {
				if err != nil {
					return err
				}
				if ev.Kind == gossip.Received && bytes.Equal(ev.Content, want) {
					return nil
				}
			}
			return ctx.Err()
		})
		if got := ts.Neighbors(); len(got) != 1 || !got[0].Equal(good.ID()) {
			t.Errorf("srv neighbors = %v, want only the good peer", got)
		}
	})
}

// TestGossipShutdownStalledNeighbor checks that Shutdown returns, even with a
// context that never ends, when a neighbor has stopped reading but its send
// queue never filled, so nothing else ever timed the peer out.
func TestGossipShutdownStalledNeighbor(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var topic gossip.TopicID
		copy(topic[:], "isolation")

		n := irohtest.NewNet(t)
		srv, gs := netGossipPeer(t, n)
		ts, err := gs.Subscribe(ctx, topic, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ts.Close()
		joinNeverReading(ctx, t, n, srv.Addr(), topic)
		if len(ts.Neighbors()) != 1 {
			t.Fatalf("srv has %d neighbors, want 1", len(ts.Neighbors()))
		}

		// 300 messages of 2 KiB fill the 512 KiB stream window and leave
		// fewer than the 64 a send queue holds waiting behind it.
		for i := range 300 {
			if err := ts.Broadcast(ctx, fmt.Appendf(bytes.Repeat([]byte{'x'}, 2<<10), "%d", i)); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()

		// The drain is bounded by the 2s stall timeout.
		irohtest.Within(t, 3*time.Second, func(ctx context.Context) error {
			done := make(chan struct{})
			go func() {
				gs.Shutdown(context.Background())
				close(done)
			}()
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})
}
