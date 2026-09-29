package blobs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
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

var stalledHash = blobs.NewHash([]byte("never sent"))

// fetchers are the fetch helpers, each fetching stalledHash, which no
// provider in these tests ever sends.
var fetchers = []struct {
	name  string
	fetch func(context.Context, blobs.BidiStream) error
}{
	{"DownloadBlob", func(ctx context.Context, s blobs.BidiStream) error {
		return blobs.DownloadBlob(ctx, s, stalledHash, new(bytes.Buffer))
	}},
	{"DownloadBlobRange", func(ctx context.Context, s blobs.BidiStream) error {
		return blobs.DownloadBlobRange(ctx, s, stalledHash, 0, 1, new(bytes.Buffer))
	}},
	{"GetBlobBytes", func(ctx context.Context, s blobs.BidiStream) error {
		_, err := blobs.GetBlobBytes(ctx, s, stalledHash)
		return err
	}},
	{"GetSingleLeaf", func(ctx context.Context, s blobs.BidiStream) error {
		_, err := blobs.GetSingleLeaf(ctx, s, stalledHash)
		return err
	}},
	{"GetManyBlobBytes", func(ctx context.Context, s blobs.BidiStream) error {
		_, err := blobs.GetManyBlobBytes(ctx, s, []blobs.Hash{stalledHash})
		return err
	}},
	{"GetHashSequenceBytes", func(ctx context.Context, s blobs.BidiStream) error {
		_, _, err := blobs.GetHashSequenceBytes(ctx, s, stalledHash)
		return err
	}},
	{"Observe", func(ctx context.Context, s blobs.BidiStream) error {
		for _, err := range blobs.Observe(ctx, s, stalledHash) {
			return err
		}
		return nil
	}},
}

// TestFetchCanceledByStalledProvider pins that every fetch helper returns
// when its context ends, even if the provider never answers.
func TestFetchCanceledByStalledProvider(t *testing.T) {
	for _, tt := range fetchers {
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

// hungStream is a BidiStream without CancelRead whose Read waits until the
// test releases it. Its Close ends only the send side, as the BidiStream
// contract allows, so nothing a helper can do unblocks a pending Read.
type hungStream struct{ release chan struct{} }

func (s hungStream) Read([]byte) (int, error) {
	<-s.release
	return 0, io.EOF
}

func (s hungStream) Write(p []byte) (int, error) { return len(p), nil }
func (s hungStream) Close() error                { return nil }

// TestFetchCanceledWithoutCancelRead pins that the helpers return when their
// context ends even if the stream cannot abandon a pending Read.
func TestFetchCanceledWithoutCancelRead(t *testing.T) {
	tests := append(slices.Clip(fetchers), struct {
		name  string
		fetch func(context.Context, blobs.BidiStream) error
	}{"ServeBlob", func(ctx context.Context, s blobs.BidiStream) error {
		return blobs.ServeBlob(ctx, s, mustBlobStore(t))
	}})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := hungStream{release: make(chan struct{})}
				defer close(s.release)
				ctx, cancel := context.WithTimeout(context.Background(), isolationBudget/2)
				defer cancel()
				err := finishes(t, isolationBudget, func() error { return tt.fetch(ctx, s) })
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("fetch error = %v, want %v", err, context.DeadlineExceeded)
				}
			})
		})
	}
}

// trickleStream is a BidiStream without CancelRead that delivers its data
// 256 bytes per millisecond and ignores Close.
type trickleStream struct{ r io.Reader }

func (s trickleStream) Read(p []byte) (int, error) {
	time.Sleep(time.Millisecond)
	return s.r.Read(p[:min(len(p), 256)])
}

func (s trickleStream) Write(p []byte) (int, error) { return len(p), nil }
func (s trickleStream) Close() error                { return nil }

// TestDownloadBlobCanceledStopsWriting pins that a download abandoned on a
// stream that cannot cancel its read does not write to the caller's writer
// after it returns.
func TestDownloadBlobCanceledStopsWriting(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 64<<10)
	hash, encoded, err := blobs.EncodeBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		download func(context.Context, blobs.BidiStream, io.Writer) error
	}{
		{"DownloadBlob", func(ctx context.Context, s blobs.BidiStream, w io.Writer) error {
			return blobs.DownloadBlob(ctx, s, hash, w)
		}},
		{"DownloadBlobRange", func(ctx context.Context, s blobs.BidiStream, w io.Writer) error {
			return blobs.DownloadBlobRange(ctx, s, hash, 0, uint64(len(data)), w)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := trickleStream{r: bytes.NewReader(encoded)}
				// Cancel halfway through the response.
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(len(encoded)/512)*time.Millisecond)
				defer cancel()
				var buf bytes.Buffer
				err := finishes(t, isolationBudget, func() error { return tt.download(ctx, s, &buf) })
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("download error = %v, want %v", err, context.DeadlineExceeded)
				}
				n := buf.Len()
				if n == 0 {
					t.Fatal("nothing written before cancel")
				}
				// Let the stream deliver the rest.
				time.Sleep(isolationBudget)
				if buf.Len() != n {
					t.Fatalf("writer grew from %d to %d bytes after download returned", n, buf.Len())
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

// TestServeBlobStreamsAcceptError pins that ServeBlobStreams reports an
// accept failure unless the connection closed or ctx ended.
func TestServeBlobStreamsAcceptError(t *testing.T) {
	errBroken := errors.New("broken accept")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want error // nil means ServeBlobStreams must return nil
	}{
		{"accept failure", context.Background(), errBroken, errBroken},
		{"connection closed", context.Background(), &iroh.ApplicationError{Remote: true}, nil},
		{"context canceled", canceled, context.Canceled, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accept := func(context.Context) (blobs.BidiStream, error) { return nil, tt.err }
			err := blobs.ServeBlobStreams(tt.ctx, accept, mustBlobStore(t))
			if tt.want == nil {
				if err != nil {
					t.Fatalf("ServeBlobStreams = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("ServeBlobStreams = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestServeBlobStreamsPeerClose pins that a peer closing its connection
// ends ServeBlobStreams without an error.
func TestServeBlobStreamsPeerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := irohtest.NewNet(t)
		served := make(chan error, 1)
		srv := provide(t, n, func(ctx context.Context, conn *iroh.Conn) error {
			err := blobs.ServeBlobStreams(ctx, func(ctx context.Context) (blobs.BidiStream, error) {
				return conn.AcceptStream(ctx)
			}, mustBlobStore(t))
			served <- err
			return err
		})
		client := n.Peer()
		conn, err := client.Connect(context.Background(), srv.Addr(), blobs.ALPN)
		if err != nil {
			t.Fatal(err)
		}
		// Open a stream so the server has accepted the connection.
		s, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Write([]byte{0}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
		conn.CloseWithError(0, "")
		err = finishes(t, isolationBudget, func() error { return <-served })
		if err != nil {
			t.Fatalf("ServeBlobStreams = %v, want nil", err)
		}
	})
}
