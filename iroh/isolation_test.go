package iroh_test

import (
	"context"
	"errors"
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
	synctest.Wait() // let the bad peer get as far as it can

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
