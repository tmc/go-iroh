package irohtest_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/iroh"
)

const alpn = "irohtest/0"

// echo serves one stream on srv, echoing it back.
func echo(t *testing.T, srv *irohtest.Peer) {
	go func() {
		conn, err := srv.Accept(context.Background())
		if err != nil {
			return
		}
		s, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		io.Copy(s, s)
		s.Close()
	}()
}

// roundTrip sends p to srv's echo and returns how long the reply took.
func roundTrip(ctx context.Context, cli, srv *irohtest.Peer, p []byte) (time.Duration, error) {
	start := time.Now()
	conn, err := cli.Connect(ctx, srv.Addr(), alpn)
	if err != nil {
		return 0, err
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	go func() {
		s.Write(p)
		s.CloseWrite()
	}()
	got, err := io.ReadAll(s)
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(got, p) {
		return 0, io.ErrUnexpectedEOF
	}
	return time.Since(start), nil
}

func TestNetImpairments(t *testing.T) {
	payload := bytes.Repeat([]byte("irohtest"), 32<<10/8) // 32 KiB
	for _, tt := range []struct {
		name    string
		imp     irohtest.Impairment
		min     time.Duration // lower bound on the round trip, in virtual time
		wantErr bool
	}{
		{name: "clean", min: 4 * irohtest.DefaultDelay},
		{name: "delay", imp: irohtest.Impairment{Delay: 50 * time.Millisecond}, min: 100 * time.Millisecond},
		{name: "loss", imp: irohtest.Impairment{Loss: 0.1}},
		{name: "jitter reorders", imp: irohtest.Impairment{Jitter: 20 * time.Millisecond}},
		{name: "duplicate", imp: irohtest.Impairment{Duplicate: 0.2}},
		// 32 KiB each way at 64 KiB/s is at least half a second.
		{name: "rate", imp: irohtest.Impairment{Rate: 64 << 10}, min: 500 * time.Millisecond},
		{name: "down", imp: irohtest.Impairment{Down: true}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := irohtest.NewNet(t)
				srv := n.Peer(iroh.WithALPNs(alpn))
				cli := n.Peer()
				n.Link(cli, srv).Impair(tt.imp)
				n.Link(srv, cli).Impair(tt.imp)
				echo(t, srv)

				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				d, err := roundTrip(ctx, cli, srv, payload)
				if tt.wantErr {
					if err == nil {
						t.Fatal("round trip over a down link succeeded")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if d < tt.min {
					t.Errorf("round trip took %v, want at least %v", d, tt.min)
				}
			})
		})
	}
}

// TestPeerImpairIsPerSender pins that Peer.Impair affects only what that peer
// sends: a silent peer cannot connect, and another peer is unaffected.
func TestPeerImpairIsPerSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := irohtest.NewNet(t)
		srv := n.Peer(iroh.WithALPNs(alpn))
		silent := n.Peer()
		silent.Impair(irohtest.Impairment{Down: true})
		ok := n.Peer()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := silent.Connect(ctx, srv.Addr(), alpn); err == nil {
			t.Fatal("silent peer connected")
		}
		echo(t, srv)
		irohtest.Within(t, time.Second, func(ctx context.Context) error {
			_, err := roundTrip(ctx, ok, srv, []byte("ping"))
			return err
		})
	})
}

// TestStallAfter pins that StallAfter delivers exactly the first n datagrams.
// Two datagrams carry the ClientHello. With them delivered and nothing after,
// the client still completes its side (it has the server's whole flight), but
// its Finished never arrives, so the server never accepts the connection.
func TestStallAfter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := irohtest.NewNet(t)
		srv := n.Peer(iroh.WithALPNs(alpn))
		cli := n.Peer()
		cli.Impair(irohtest.Impairment{StallAfter: 2})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		go cli.Connect(ctx, srv.Addr(), alpn)
		actx, acancel := context.WithTimeout(ctx, 10*time.Second)
		defer acancel()
		if conn, err := srv.Accept(actx); err == nil {
			t.Fatalf("server accepted a stalled peer: %v", conn.RemoteID())
		}

		cli.Impair(irohtest.Impairment{}) // healed
		go cli.Connect(ctx, srv.Addr(), alpn)
		conn, err := srv.Accept(ctx)
		if err != nil {
			t.Fatalf("healed peer: %v", err)
		}
		if !conn.RemoteID().Equal(cli.ID()) {
			t.Fatalf("accepted %v, want %v", conn.RemoteID(), cli.ID())
		}
	})
}
