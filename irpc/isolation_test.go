package irpc_test

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/irpc"
)

const isolationALPN = "go-iroh/irpc/isolation/0"

// call makes one request on conn and returns its responses.
func call(ctx context.Context, conn *iroh.Conn, req string) ([]string, error) {
	seq, err := irpc.Call[string, string](ctx, conn, req, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	for resp, err := range seq {
		if err != nil {
			return out, err
		}
		out = append(out, resp)
	}
	return out, nil
}

// TestHandlerPanicIsolation pins that a request which makes Handle panic
// fails only that request: the process survives, the caller gets an error
// rather than a clean end of responses, and later requests on the same
// connection and from other peers are served.
func TestHandlerPanicIsolation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		n := irohtest.NewNet(t)
		srv := n.Peer(iroh.WithALPNs(isolationALPN))
		h := irpc.Handler[string, string]{
			Handle: func(ctx context.Context, req string, r *irpc.Responder[string]) error {
				if req == "panic" {
					r.Send("partial")
					panic("bad request")
				}
				return r.Send(req)
			},
		}
		router, err := iroh.NewRouter(srv.Endpoint, map[string]iroh.ProtocolHandler{isolationALPN: h}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer router.Shutdown(ctx)

		bad := n.Peer()
		badConn, err := bad.Connect(ctx, srv.Addr(), isolationALPN)
		if err != nil {
			t.Fatal(err)
		}
		defer badConn.CloseWithError(0, "")
		if _, err := call(ctx, badConn, "panic"); err == nil {
			t.Fatal("panicking request succeeded, want error")
		}

		good := n.Peer()
		irohtest.Within(t, time.Second, func(ctx context.Context) error {
			for _, c := range []struct {
				name string
				conn func() (*iroh.Conn, error)
			}{
				{"same connection", func() (*iroh.Conn, error) { return badConn, nil }},
				{"other peer", func() (*iroh.Conn, error) { return good.Connect(ctx, srv.Addr(), isolationALPN) }},
			} {
				conn, err := c.conn()
				if err != nil {
					return err
				}
				got, err := call(ctx, conn, "hi")
				if err != nil {
					return errors.Join(errors.New(c.name), err)
				}
				if len(got) != 1 || got[0] != "hi" {
					t.Errorf("%s: got %q, want [hi]", c.name, got)
				}
			}
			return nil
		})
	})
}
