package gossip_test

import (
	"bytes"
	"context"
	"errors"
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
// other neighbors misbehave: one write limit, after which the misbehaving
// neighbors are dropped, and slack. The in-memory link adds 1ms each way, so
// the slack is hundreds of round trips.
const isolationBudget = gossip.SendWriteTimeout + 2*time.Second

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
// accepts, so never reads, the stream the server opens to it. It returns the
// peer.
func joinNeverReading(ctx context.Context, t *testing.T, n *irohtest.Net, srvAddr netaddr.EndpointAddr, topic gossip.TopicID) *irohtest.Peer {
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
	return bad
}

// fill is 2 KiB of content numbered i. 300 of them are well past the
// 512 KiB stream window.
func fill(i int) []byte {
	return fmt.Appendf(bytes.Repeat([]byte{'x'}, 2<<10), "%d", i)
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

		const count = 400
		irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
			for i := range count {
				if err := ts.Broadcast(ctx, fill(i)); err != nil {
					return err
				}
			}
			return nil
		})
		irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
			stop := context.AfterFunc(ctx, func() { _ = tg.Close() })
			defer stop()
			want := fill(count - 1)
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
			if err := ts.Broadcast(ctx, fill(i)); err != nil {
				t.Fatal(err)
			}
		}
		synctest.Wait()

		// The drain is bounded by the write limit.
		irohtest.Within(t, gossip.SendWriteTimeout+time.Second, func(ctx context.Context) error {
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

// TestGossipStalledNeighborsWaitTogether checks that several neighbors that
// stop reading hold up the rest of the topic for about one write limit, not
// one limit each: their writes stall together, so their limits run out
// together.
func TestGossipStalledNeighborsWaitTogether(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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

		for range 3 {
			joinNeverReading(ctx, t, n, srvAddr, topic)
		}
		if len(ts.Neighbors()) != 4 {
			t.Fatalf("srv has %d neighbors, want 4", len(ts.Neighbors()))
		}

		const count = 400
		done := make(chan error, 1)
		go func() {
			for i := range count {
				if err := ts.Broadcast(ctx, fill(i)); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
			stop := context.AfterFunc(ctx, func() { _ = tg.Close() })
			defer stop()
			want := fill(count - 1)
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
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got := ts.Neighbors(); len(got) != 1 || !got[0].Equal(good.ID()) {
			t.Errorf("srv neighbors = %v, want only the good peer", got)
		}
	})
}

// TestGossipStalledWriteDropsNeighbor checks that a neighbor whose stream is
// stalled is dropped after one write limit even though its send queue never
// fills, so no sender ever waits on it.
func TestGossipStalledWriteDropsNeighbor(t *testing.T) {
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
		bad := joinNeverReading(ctx, t, n, srv.Addr(), topic)

		// Fewer than the 64 a send queue holds wait behind the stall.
		for i := range 300 {
			if err := ts.Broadcast(ctx, fill(i)); err != nil {
				t.Fatal(err)
			}
		}
		irohtest.Within(t, gossip.SendWriteTimeout+time.Second, func(ctx context.Context) error {
			stop := context.AfterFunc(ctx, func() { _ = ts.Close() })
			defer stop()
			for ev, err := range ts.Events() {
				if err != nil {
					return err
				}
				if ev.Kind == gossip.NeighborDown && ev.Peer.Equal(bad.ID()) {
					return nil
				}
			}
			return ctx.Err()
		})
	})
}

// TestGossipBroadcastHonorsContext checks that a Broadcast waiting for room
// in a stalled neighbor's send queue returns when its context ends.
func TestGossipBroadcastHonorsContext(t *testing.T) {
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

		const wait = time.Second
		bctx, bcancel := context.WithTimeout(ctx, wait)
		defer bcancel()
		start := time.Now()
		for i := range 400 {
			err = ts.Broadcast(bctx, fill(i))
			if err != nil {
				break
			}
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Broadcast = %v, want %v", err, context.DeadlineExceeded)
		}
		if d := time.Since(start); d > wait+10*time.Millisecond {
			t.Errorf("Broadcast returned %v after its context, want promptly", d-wait)
		}
	})
}

// TestGossipDropDuringDialLeavesNoSender checks that a send queue dropped
// while its writer is dialing, as a timed-out write drops it, does not leave
// the connection the dial then completes published and unowned.
func TestGossipDropDuringDialLeavesNoSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()

		var topic gossip.TopicID
		copy(topic[:], "isolation")

		n := irohtest.NewNet(t)
		_, ga := netGossipPeer(t, n)
		b, _ := netGossipPeer(t, n)
		dropped := false
		ga.SetDialedHook(func(peer gossip.PeerID) {
			if !dropped && peer == gossip.PeerID(b.ID().Bytes()) {
				dropped = true
				ga.DropPeer(peer)
			}
		})
		ts, err := ga.Subscribe(ctx, topic, []netaddr.EndpointAddr{b.Addr()})
		if err != nil {
			t.Fatal(err)
		}
		defer ts.Close()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if !dropped {
			t.Fatal("dial hook never ran")
		}
		if ga.HasSender(gossip.PeerID(b.ID().Bytes())) {
			t.Fatal("connection dialed for a dropped send queue was published")
		}
	})
}

// fillQueue broadcasts on ts until the send queue of a neighbor that never
// reads is full, which it reports by a Broadcast waiting out its context.
func fillQueue(ctx context.Context, t *testing.T, ts *gossip.Topic) {
	t.Helper()
	for i := 0; ; i++ {
		bctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		err := ts.Broadcast(bctx, fill(i))
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestGossipCallsHonorContextBehindFullQueue checks that Subscribe and
// Shutdown, when what they send must wait behind a stalled neighbor's full
// send queue, return when their context ends rather than at the write limit.
func TestGossipCallsHonorContextBehindFullQueue(t *testing.T) {
	calls := []struct {
		name string
		call func(ctx context.Context, gs *gossip.Gossip, bad *irohtest.Peer) error
	}{
		{"Subscribe", func(ctx context.Context, gs *gossip.Gossip, bad *irohtest.Peer) error {
			var other gossip.TopicID
			copy(other[:], "other")
			_, err := gs.SubscribeWithOpts(ctx, other, gossip.JoinOptions{Bootstrap: []netaddr.EndpointAddr{bad.Addr()}})
			return err
		}},
		{"Shutdown", func(ctx context.Context, gs *gossip.Gossip, _ *irohtest.Peer) error {
			gs.Shutdown(ctx)
			return nil
		}},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
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
				bad := joinNeverReading(ctx, t, n, srv.Addr(), topic)
				fillQueue(ctx, t, ts)

				const wait = time.Second
				cctx, ccancel := context.WithTimeout(ctx, wait)
				defer ccancel()
				start := time.Now()
				if err := c.call(cctx, gs, bad); err != nil {
					t.Fatal(err)
				}
				if d := time.Since(start); d > wait+10*time.Millisecond {
					t.Errorf("%s returned %v after its context, want promptly", c.name, d-wait)
				}
			})
		})
	}
}
