package iroh_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// isolationBudget is how long a well-behaved peer may wait to be accepted while
// another peer misbehaves. The in-memory link adds 1ms each way, so this is
// hundreds of round trips; a server that is held up by the bad peer instead
// waits out a handshake timeout (5s) or forever.
const isolationBudget = time.Second

// An acceptServer runs one of the endpoint's accept paths and reports each
// accepted connection's remote id.
type acceptServer func(t *testing.T, ep *iroh.Endpoint, alpn string, accepted chan<- key.EndpointID)

var acceptServers = []struct {
	name string
	run  acceptServer
}{
	{"Accept", func(t *testing.T, ep *iroh.Endpoint, _ string, accepted chan<- key.EndpointID) {
		go func() {
			for {
				conn, err := ep.Accept(context.Background())
				if errors.Is(err, iroh.ErrEndpointClosed) {
					return
				}
				if err != nil {
					continue // a per-peer error; the caller moves on
				}
				accepted <- conn.RemoteID()
			}
		}()
	}},
	{"ListenStreams", func(t *testing.T, ep *iroh.Endpoint, _ string, accepted chan<- key.EndpointID) {
		ln, err := ep.ListenStreams()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				accepted <- c.(interface{ RemoteID() key.EndpointID }).RemoteID()
				c.Close()
			}
		}()
	}},
	{"Router", func(t *testing.T, ep *iroh.Endpoint, alpn string, accepted chan<- key.EndpointID) {
		r, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
			alpn: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
				accepted <- conn.RemoteID()
				return nil
			}),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Shutdown(context.Background()) })
	}},
}

// A misbehavior is what the bad peer does. hooks, if set, are installed on the
// server and given the bad peer; act runs on the bad peer.
type misbehavior struct {
	name  string
	hooks func(release <-chan struct{}, bad *irohtest.Peer) irohtest.Hooks
	act   func(ctx context.Context, bad *irohtest.Peer, srv *irohtest.Peer, alpn string)
}

var misbehaviors = []misbehavior{
	{
		// The ClientHello spans two datagrams; after them the peer is silent,
		// leaving the server mid-handshake until its handshake timeout.
		name: "silent after ClientHello",
		act: func(ctx context.Context, bad *irohtest.Peer, srv *irohtest.Peer, alpn string) {
			bad.Impair(irohtest.Impairment{StallAfter: 2})
			go bad.Connect(ctx, srv.Addr(), alpn)
		},
	},
	{
		name: "hook stalls",
		hooks: func(release <-chan struct{}, bad *irohtest.Peer) irohtest.Hooks {
			return irohtest.StallFrom(release, bad)
		},
		act: dialOnly,
	},
	{
		name: "hook rejects",
		hooks: func(_ <-chan struct{}, bad *irohtest.Peer) irohtest.Hooks {
			return irohtest.RejectFrom(iroh.RejectHandshake(77, "blocked"), bad)
		},
		act: dialOnly,
	},
	{
		name: "hook errors",
		hooks: func(_ <-chan struct{}, bad *irohtest.Peer) irohtest.Hooks {
			return irohtest.RejectFrom(errors.New("blocked"), bad)
		},
		act: dialOnly,
	},
}

func dialOnly(ctx context.Context, bad *irohtest.Peer, srv *irohtest.Peer, alpn string) {
	go bad.Connect(ctx, srv.Addr(), alpn)
}

// TestAcceptIsolation pins that no accept path lets one misbehaving peer delay
// or stop the acceptance of another.
func TestAcceptIsolation(t *testing.T) {
	for _, srv := range acceptServers {
		for _, mb := range misbehaviors {
			t.Run(srv.name+"/"+mb.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					testAcceptIsolation(t, srv.run, mb)
				})
			})
		}
	}
}

func testAcceptIsolation(t *testing.T, run acceptServer, mb misbehavior) {
	const alpn = "iroh-isolation/0"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)

	n := irohtest.NewNet(t)
	bad := n.Peer()
	good := n.Peer()
	opts := []iroh.Option{iroh.WithALPNs(alpn)}
	if mb.hooks != nil {
		opts = append(opts, iroh.WithHooks(mb.hooks(release, bad)))
	}
	srv := n.Peer(opts...)
	accepted := make(chan key.EndpointID, 16)
	run(t, srv.Endpoint, alpn, accepted)

	mb.act(ctx, bad, srv, alpn)
	// Let the bad peer get as far as it can. synctest.Wait alone would not
	// advance the clock, so no datagram in flight would arrive.
	time.Sleep(100 * time.Millisecond)
	synctest.Wait()

	acceptedWithin(t, good, srv, alpn, accepted)
}

// acceptedWithin checks that good can connect to srv and open a stream, and
// that srv accepts it, within isolationBudget.
func acceptedWithin(t *testing.T, good, srv *irohtest.Peer, alpn string, accepted <-chan key.EndpointID) {
	t.Helper()
	irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
		conn, err := good.Connect(ctx, srv.Addr(), alpn)
		if err != nil {
			return err
		}
		defer conn.CloseWithError(0, "")
		s, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		defer s.Close()
		if _, err := s.Write([]byte("hi")); err != nil {
			return err
		}
		for {
			select {
			case id := <-accepted:
				if id.Equal(good.ID()) {
					return nil
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	})
}

// TestAcceptStaleHandshake pins that a handshake started by an Accept that has
// since returned, and that finishes after another loop has taken over
// accepting, is closed rather than kept for a later Accept.
func TestAcceptStaleHandshake(t *testing.T) {
	owners := []struct {
		name string
		take func(t *testing.T, ep *iroh.Endpoint, alpn string) (release func())
	}{
		{"ListenStreams", func(t *testing.T, ep *iroh.Endpoint, _ string) func() {
			ln, err := ep.ListenStreams()
			if err != nil {
				t.Fatal(err)
			}
			return func() { ln.Close() }
		}},
		{"Router", func(t *testing.T, ep *iroh.Endpoint, alpn string) func() {
			r, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
				alpn: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
					return nil
				}),
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			return func() { r.Shutdown(context.Background()) }
		}},
	}
	for _, o := range owners {
		t.Run(o.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const alpn = "iroh-stale/0"
				release := make(chan struct{})
				n := irohtest.NewNet(t)
				bad := n.Peer()
				srv := n.Peer(iroh.WithALPNs(alpn), iroh.WithHooks(irohtest.StallFrom(release, bad)))

				ctx, cancel := context.WithCancel(context.Background())
				acceptErr := make(chan error, 1)
				go func() {
					_, err := srv.Accept(ctx)
					acceptErr <- err
				}()
				dialed := make(chan *iroh.Conn, 1)
				go func() {
					conn, err := bad.Connect(context.Background(), srv.Addr(), alpn)
					if err != nil {
						t.Error(err)
					}
					dialed <- conn
				}()
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				cancel()
				if err := <-acceptErr; !errors.Is(err, context.Canceled) {
					t.Fatalf("Accept = %v, want context.Canceled", err)
				}

				releaseOwner := o.take(t, srv.Endpoint, alpn)
				defer releaseOwner()
				close(release)
				conn := <-dialed
				if conn == nil {
					t.FailNow()
				}
				irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
					select {
					case <-conn.Context().Done():
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})

				releaseOwner()
				ctx, cancel = context.WithTimeout(context.Background(), isolationBudget)
				defer cancel()
				if c, err := srv.Accept(ctx); err == nil {
					t.Fatalf("Accept returned stale conn from %v", c.RemoteID())
				}
			})
		})
	}
}

// TestAdmissionsAbandonOldest pins that every accept path admits at most
// the endpoint's maximum of handshakes at once, and that a new peer abandons
// the oldest pending one rather than waiting behind it: peers stalled in a
// hook cannot keep a good peer out, however many there are.
func TestAdmissionsAbandonOldest(t *testing.T) {
	for _, srv := range acceptServers {
		t.Run(srv.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				testAdmissionsAbandonOldest(t, srv.run)
			})
		})
	}
}

func testAdmissionsAbandonOldest(t *testing.T, run acceptServer) {
	const (
		alpn  = "iroh-admit/0"
		limit = 4
		flood = 3 * limit
	)
	release := make(chan struct{})
	defer close(release)
	n := irohtest.NewNet(t)
	var bad []*irohtest.Peer
	for range flood {
		bad = append(bad, n.Peer())
	}
	good := n.Peer()
	stall := irohtest.StallFrom(release, bad...)
	var mu sync.Mutex
	stalled, maxStalled := 0, 0
	hooks := irohtest.Hooks{After: func(ctx context.Context, conn *iroh.Conn) error {
		mu.Lock()
		stalled++
		maxStalled = max(maxStalled, stalled)
		mu.Unlock()
		defer func() {
			mu.Lock()
			stalled--
			mu.Unlock()
		}()
		return stall.After(ctx, conn)
	}}
	srv := n.Peer(iroh.WithALPNs(alpn), iroh.WithHooks(hooks))
	iroh.SetMaxAdmitting(srv.Endpoint, limit)
	accepted := make(chan key.EndpointID, flood+1)
	run(t, srv.Endpoint, alpn, accepted)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conns := make(chan *iroh.Conn, flood)
	for _, p := range bad {
		go func() {
			conn, err := p.Connect(ctx, srv.Addr(), alpn)
			if err != nil {
				conn = nil
			}
			conns <- conn
		}()
	}
	time.Sleep(time.Second)
	synctest.Wait()

	abandoned := 0
	for range flood {
		conn := <-conns
		if conn == nil || conn.Context().Err() != nil {
			abandoned++
		}
	}
	if want := flood - limit; abandoned != want {
		t.Errorf("abandoned bad peers = %d, want %d", abandoned, want)
	}

	acceptedWithin(t, good, srv, alpn, accepted)
	mu.Lock()
	defer mu.Unlock()
	if maxStalled > limit {
		t.Fatalf("max stalled handshakes = %d, want <= %d", maxStalled, limit)
	}
}
