package blobs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// isolationBudget is how long a download may take while a provider
// misbehaves. The in-memory link adds 1ms each way, so a download that is
// not held up by the bad provider finishes far inside it.
const isolationBudget = time.Second

// provide starts a blob provider on n that handles each connection with h.
func provide(t *testing.T, n *irohtest.Net, h iroh.ProtocolHandlerFunc) *irohtest.Peer {
	p := n.Peer(iroh.WithALPNs(blobs.ALPN))
	r, err := iroh.NewRouter(p.Endpoint, map[string]iroh.ProtocolHandler{blobs.ALPN: h}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Shutdown(context.Background()) })
	return p
}

// serve is a provider that serves one request per stream from store.
func serve(store blobs.Store) iroh.ProtocolHandlerFunc {
	return func(ctx context.Context, conn *iroh.Conn) error {
		return blobs.ServeBlobStreams(ctx, func(ctx context.Context) (blobs.BidiStream, error) {
			return conn.AcceptStream(ctx)
		}, store)
	}
}

// stall is a provider that accepts a request and never answers it, while
// keeping the connection alive.
func stall(ctx context.Context, conn *iroh.Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	<-ctx.Done()
	return nil
}

// finishes fails t unless f returns within budget. Unlike [irohtest.Within],
// it does not rely on f honoring its context, which is what is under test.
func finishes(t *testing.T, budget time.Duration, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(budget):
		t.Fatalf("not done within %v", budget)
		return nil
	}
}

type blobConn struct{ *iroh.Conn }

func (c blobConn) OpenStreamSync(ctx context.Context) (blobs.BidiStream, error) {
	return c.Conn.OpenStreamSync(ctx)
}

func connector(ep *irohtest.Peer) blobs.BlobConnector {
	return blobs.BlobConnectorFunc(func(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (blobs.BlobConn, error) {
		conn, err := ep.Connect(ctx, addr, alpn)
		if err != nil {
			return nil, err
		}
		return blobConn{conn}, nil
	})
}

// TestFetchCanceledByStalledProvider pins that every fetch helper returns
// when its context ends, even if the provider never answers.
func TestFetchCanceledByStalledProvider(t *testing.T) {
	hash := blobs.NewHash([]byte("never sent"))
	tests := []struct {
		name  string
		fetch func(context.Context, blobs.BidiStream) error
	}{
		{"DownloadBlob", func(ctx context.Context, s blobs.BidiStream) error {
			return blobs.DownloadBlob(ctx, s, hash, new(bytes.Buffer))
		}},
		{"DownloadBlobRange", func(ctx context.Context, s blobs.BidiStream) error {
			return blobs.DownloadBlobRange(ctx, s, hash, 0, 1, new(bytes.Buffer))
		}},
		{"GetBlobBytes", func(ctx context.Context, s blobs.BidiStream) error {
			_, err := blobs.GetBlobBytes(ctx, s, hash)
			return err
		}},
		{"GetSingleLeaf", func(ctx context.Context, s blobs.BidiStream) error {
			_, err := blobs.GetSingleLeaf(ctx, s, hash)
			return err
		}},
		{"GetManyBlobBytes", func(ctx context.Context, s blobs.BidiStream) error {
			_, err := blobs.GetManyBlobBytes(ctx, s, []blobs.Hash{hash})
			return err
		}},
		{"GetHashSequenceBytes", func(ctx context.Context, s blobs.BidiStream) error {
			_, _, err := blobs.GetHashSequenceBytes(ctx, s, hash)
			return err
		}},
		{"Observe", func(ctx context.Context, s blobs.BidiStream) error {
			for _, err := range blobs.Observe(ctx, s, hash) {
				return err
			}
			return nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := irohtest.NewNet(t)
				bad := provide(t, n, stall)
				client := n.Peer()
				conn, err := client.Connect(context.Background(), bad.Addr(), blobs.ALPN)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.CloseWithError(0, "")
				s, err := conn.OpenStreamSync(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), isolationBudget/2)
				defer cancel()
				err = finishes(t, isolationBudget, func() error { return tt.fetch(ctx, s) })
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("fetch error = %v, want %v", err, context.DeadlineExceeded)
				}
			})
		})
	}
}

// TestDownloaderStalledProvider pins that a provider that never answers does
// not keep Download from returning once another provider has delivered.
func TestDownloaderStalledProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		data := []byte("download me")
		hash := blobs.NewHash(data)
		n := irohtest.NewNet(t)
		bad := provide(t, n, stall)
		good := provide(t, n, serve(mustBlobStore(t, data)))
		client := n.Peer()

		dst := mustBlobStore(t)
		d := blobs.NewDownloader(dst, connector(client), blobs.DownloaderOptions{Concurrency: 2})
		defer d.Close()
		providers := []netaddr.EndpointAddr{bad.Addr(), good.Addr()}
		err := finishes(t, isolationBudget, func() error {
			tag, err := d.Download(context.Background(), hash, providers)
			if err != nil {
				return err
			}
			return tag.Close()
		})
		if err != nil {
			t.Fatalf("Download: %v", err)
		}
		got, err := blobs.ReadBlob(context.Background(), dst, hash)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("ReadBlob = %q, %v; want %q", got, err, data)
		}
	})
}

// TestServeBlobStreamsStreamError pins that a request that fails ends only
// its own stream, not the connection's other streams.
func TestServeBlobStreamsStreamError(t *testing.T) {
	data := []byte("still served")
	hash := blobs.NewHash(data)
	tests := []struct {
		name string
		req  []byte
	}{
		{"missing blob", blobs.EncodeGetRequestBytes(blobs.GetBlob(blobs.NewHash([]byte("missing"))))},
		{"garbage request", []byte{0xff, 0xff, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := irohtest.NewNet(t)
				srv := provide(t, n, serve(mustBlobStore(t, data)))
				client := n.Peer()
				ctx := context.Background()
				conn, err := client.Connect(ctx, srv.Addr(), blobs.ALPN)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.CloseWithError(0, "")

				bad, err := conn.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := bad.Write(tt.req); err != nil {
					t.Fatal(err)
				}
				bad.CloseWrite()
				// The server ends the stream once it has failed the request.
				if _, err := io.ReadAll(bad); err != nil {
					t.Fatal(err)
				}

				irohtest.Within(t, isolationBudget, func(ctx context.Context) error {
					s, err := conn.OpenStreamSync(ctx)
					if err != nil {
						return err
					}
					got, err := blobs.GetBlobBytes(ctx, s, hash)
					if err != nil {
						return err
					}
					if !bytes.Equal(got, data) {
						t.Errorf("GetBlobBytes = %q, want %q", got, data)
					}
					return nil
				})
			})
		})
	}
}
