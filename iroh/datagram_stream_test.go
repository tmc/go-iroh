package iroh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// TestDatagramAndStreamPipelined sends datagrams, bidirectional streams, and
// unidirectional streams back-to-back without waiting for datagram echoes,
// verifying that DATAGRAM frames keep their length field when packed ahead of
// STREAM frames over both direct loopback and relay transports.
func TestDatagramAndStreamPipelined(t *testing.T) {
	const alpn = "iroh-datagram-stream-pipeline/0"

	modes := []struct {
		name  string
		setup func(t *testing.T, ctx context.Context) (server, client *Endpoint, target netaddr.EndpointAddr)
	}{
		{
			name: "direct",
			setup: func(t *testing.T, ctx context.Context) (*Endpoint, *Endpoint, netaddr.EndpointAddr) {
				lo := netip.MustParseAddrPort("127.0.0.1:0")
				server, err := Bind(ctx, WithALPNs(alpn), WithBindAddr(lo), WithRelayMode(relay.ModeDisabled()))
				if err != nil {
					t.Fatalf("bind server: %v", err)
				}
				t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

				client, err := Bind(ctx, WithBindAddr(lo), WithRelayMode(relay.ModeDisabled()))
				if err != nil {
					t.Fatalf("bind client: %v", err)
				}
				t.Cleanup(func() { _ = client.Shutdown(context.Background()) })

				return server, client, server.Addr()
			},
		},
		{
			name: "relay",
			setup: func(t *testing.T, ctx context.Context) (*Endpoint, *Endpoint, netaddr.EndpointAddr) {
				srv := newEchoRelayServer(t)
				relayURL := srv.url(t)
				mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

				server, err := Bind(ctx, WithALPNs(alpn), WithRelayMode(mode), WithoutIPTransports())
				if err != nil {
					t.Fatalf("bind server: %v", err)
				}
				t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

				client, err := Bind(ctx, WithRelayMode(mode), WithoutIPTransports())
				if err != nil {
					t.Fatalf("bind client: %v", err)
				}
				t.Cleanup(func() { _ = client.Shutdown(context.Background()) })

				if err := server.Online(ctx); err != nil {
					t.Fatalf("server online: %v", err)
				}
				if err := client.Online(ctx); err != nil {
					t.Fatalf("client online: %v", err)
				}
				return server, client, server.Addr()
			},
		},
	}

	for _, tc := range modes {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			server, client, target := tc.setup(t, ctx)

			const rounds = 10
			wantBidi := make([][]byte, rounds)
			wantUni := make([][]byte, rounds)
			wantDG := make(map[string]struct{}, rounds)
			for i := range rounds {
				wantBidi[i] = []byte(fmt.Sprintf("bidi-payload-%02d-exact", i))
				wantUni[i] = []byte(fmt.Sprintf("uni-payload-%02d-exact!", i))
				wantDG[fmt.Sprintf("dg-%02d-20bytes-exact!", i)] = struct{}{}
			}

			clientDone := make(chan struct{})
			srvErr := make(chan error, 1)
			go func() {
				conn, err := server.Accept(ctx)
				if err != nil {
					srvErr <- fmt.Errorf("accept: %w", err)
					return
				}
				defer conn.Close()

				dgErr := make(chan error, 1)
				go func() {
					var gotCount int
					for {
						dg, err := conn.ReadDatagram(ctx)
						if err != nil {
							if gotCount == 0 {
								dgErr <- fmt.Errorf("received 0 datagrams (err=%v)", err)
								return
							}
							dgErr <- nil
							return
						}
						if len(dg) != 20 {
							dgErr <- fmt.Errorf("datagram len = %d (%q), want 20", len(dg), dg)
							return
						}
						if _, ok := wantDG[string(dg)]; !ok {
							dgErr <- fmt.Errorf("unexpected datagram payload %q", dg)
							return
						}
						gotCount++
					}
				}()

				uniErr := make(chan error, 1)
				go func() {
					for i := range rounds {
						u, err := conn.AcceptUniStream(ctx)
						if err != nil {
							uniErr <- fmt.Errorf("accept uni %d: %w", i, err)
							return
						}
						got, err := io.ReadAll(u)
						if err != nil {
							uniErr <- fmt.Errorf("read uni %d: %w", i, err)
							return
						}
						if !bytes.Equal(got, wantUni[i]) {
							uniErr <- fmt.Errorf("uni[%d] = %q (%d bytes), want %q (%d bytes)", i, got, len(got), wantUni[i], len(wantUni[i]))
							return
						}
					}
					uniErr <- nil
				}()

				for i := range rounds {
					s, err := conn.AcceptStream(ctx)
					if err != nil {
						srvErr <- fmt.Errorf("accept bidi %d: %w", i, err)
						return
					}
					got, err := io.ReadAll(s)
					if err != nil {
						srvErr <- fmt.Errorf("read bidi %d: %w", i, err)
						return
					}
					if !bytes.Equal(got, wantBidi[i]) {
						srvErr <- fmt.Errorf("bidi[%d] = %q (%d bytes), want %q (%d bytes)", i, got, len(got), wantBidi[i], len(wantBidi[i]))
						return
					}
					if _, err := s.Write(got); err != nil {
						srvErr <- fmt.Errorf("write bidi %d: %w", i, err)
						return
					}
					if err := s.Close(); err != nil {
						srvErr <- fmt.Errorf("close bidi %d: %w", i, err)
						return
					}
				}

				if err := <-uniErr; err != nil {
					srvErr <- err
					return
				}
				select {
				case <-clientDone:
				case <-ctx.Done():
					srvErr <- ctx.Err()
					return
				}
				conn.Close()
				srvErr <- <-dgErr
			}()

			conn, err := client.Connect(ctx, target, alpn)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer conn.Close()

			// Pipeline datagram + bidi stream + uni stream back-to-back without
			// waiting for any datagram echo so frames coalesce into the same packets.
			bidiStreams := make([]*Stream, rounds)
			for i := range rounds {
				dg := fmt.Sprintf("dg-%02d-20bytes-exact!", i)
				if err := conn.SendDatagram([]byte(dg)); err != nil {
					t.Fatalf("SendDatagram %d: %v", i, err)
				}

				s, err := conn.OpenStreamSync(ctx)
				if err != nil {
					t.Fatalf("OpenStreamSync %d: %v", i, err)
				}
				if _, err := s.Write(wantBidi[i]); err != nil {
					t.Fatalf("bidi write %d: %v", i, err)
				}
				if err := s.Close(); err != nil {
					t.Fatalf("bidi close %d: %v", i, err)
				}
				bidiStreams[i] = s

				u, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					t.Fatalf("OpenUniStreamSync %d: %v", i, err)
				}
				if _, err := u.Write(wantUni[i]); err != nil {
					t.Fatalf("uni write %d: %v", i, err)
				}
				if err := u.Close(); err != nil {
					t.Fatalf("uni close %d: %v", i, err)
				}
			}

			for i, s := range bidiStreams {
				got, err := io.ReadAll(s)
				if err != nil {
					t.Fatalf("bidi echo read %d: %v", i, err)
				}
				if !bytes.Equal(got, wantBidi[i]) {
					t.Fatalf("bidi echo[%d] = %q, want %q", i, got, wantBidi[i])
				}
			}
			close(clientDone)

			if err := <-srvErr; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}
