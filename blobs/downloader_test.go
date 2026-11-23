package blobs

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestDownloaderFailover(t *testing.T) {
	data := []byte("download me")
	hash := NewHash(data)
	store := &downloadStore{}
	bad := testEndpointAddr(1)
	good := testEndpointAddr(2)
	conn := &fakeBlobConnector{
		blobs: map[string]map[Hash][]byte{
			good.String(): {hash: data},
		},
		fail: map[string]error{
			bad.String(): errors.New("dial failed"),
		},
	}
	var events []DownloadEventKind
	d := NewDownloader(store, conn, DownloaderOptions{
		Concurrency: 1,
		OnEvent: func(ev DownloadEvent) {
			events = append(events, ev.Kind)
		},
	})
	t.Cleanup(func() { _ = d.Close() })

	if _, err := d.Download(context.Background(), hash, []netaddr.EndpointAddr{bad, good}); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if got := store.blobs[hash]; string(got) != string(data) {
		t.Fatalf("stored blob = %q, want %q", got, data)
	}
	if conn.connects[good.String()] != 1 {
		t.Fatalf("good provider connects = %d, want 1", conn.connects[good.String()])
	}
	if conn.connects[bad.String()] != 1 {
		t.Fatalf("bad provider connects = %d, want 1", conn.connects[bad.String()])
	}
	want := []DownloadEventKind{DownloadTryProvider, DownloadProviderFailed, DownloadTryProvider, DownloadComplete}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

func TestDownloaderReusesConnection(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	firstHash := NewHash(first)
	secondHash := NewHash(second)
	addr := testEndpointAddr(3)
	store := &downloadStore{}
	conn := &fakeBlobConnector{
		blobs: map[string]map[Hash][]byte{
			addr.String(): {
				firstHash:  first,
				secondHash: second,
			},
		},
	}
	d := NewDownloader(store, conn, DownloaderOptions{Concurrency: 1})
	t.Cleanup(func() { _ = d.Close() })

	if _, err := d.Download(context.Background(), firstHash, []netaddr.EndpointAddr{addr}); err != nil {
		t.Fatalf("first Download: %v", err)
	}
	if _, err := d.Download(context.Background(), secondHash, []netaddr.EndpointAddr{addr}); err != nil {
		t.Fatalf("second Download: %v", err)
	}
	if conn.connects[addr.String()] != 1 {
		t.Fatalf("connects = %d, want 1", conn.connects[addr.String()])
	}
	if conn.streams[addr.String()] != 2 {
		t.Fatalf("streams = %d, want 2", conn.streams[addr.String()])
	}
}

func TestDownloaderConcurrentFailover(t *testing.T) {
	data := []byte("winner")
	hash := NewHash(data)
	store := &downloadStore{}
	one := testEndpointAddr(4)
	two := testEndpointAddr(5)
	conn := &fakeBlobConnector{
		blobs: map[string]map[Hash][]byte{
			one.String(): {},
			two.String(): {hash: data},
		},
	}
	d := NewDownloader(store, conn, DownloaderOptions{Concurrency: 2})
	t.Cleanup(func() { _ = d.Close() })

	if _, err := d.Download(context.Background(), hash, []netaddr.EndpointAddr{one, two}); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if got := store.blobs[hash]; string(got) != string(data) {
		t.Fatalf("stored blob = %q, want %q", got, data)
	}
}

// TestDownloaderConcurrentOnEvent is a regression test: with Concurrency > 1
// the worker fan-out calls OnEvent from multiple goroutines, so an unsynchronized
// callback (the natural append-to-slice shape) must not data-race. Run under
// -race to catch a regression. OnEvent is documented as called serially, so the
// unlocked append below is a legitimate caller pattern.
func TestDownloaderConcurrentOnEvent(t *testing.T) {
	data := []byte("winner")
	hash := NewHash(data)
	store := &downloadStore{}
	one := testEndpointAddr(6)
	two := testEndpointAddr(7)
	conn := &fakeBlobConnector{
		blobs: map[string]map[Hash][]byte{
			one.String(): {},
			two.String(): {hash: data},
		},
	}
	var events []DownloadEventKind // intentionally unsynchronized
	d := NewDownloader(store, conn, DownloaderOptions{
		Concurrency: 4,
		OnEvent: func(ev DownloadEvent) {
			events = append(events, ev.Kind)
		},
	})
	t.Cleanup(func() { _ = d.Close() })

	if _, err := d.Download(context.Background(), hash, []netaddr.EndpointAddr{one, two}); err != nil {
		t.Fatalf("Download: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("OnEvent never called")
	}
}

func TestDownloaderCustomALPN(t *testing.T) {
	const customALPN = "/custom-blobs/1"
	data := []byte("hello custom alpn")
	hash := NewHash(data)
	addr := testEndpointAddr(8)
	conn := &fakeBlobConnector{
		alpn: customALPN,
		blobs: map[string]map[Hash][]byte{
			addr.String(): {hash: data},
		},
	}

	// Default downloader uses blobs.ALPN and fails against a custom-ALPN provider.
	defaultStore := &downloadStore{}
	defaultDownloader := NewDownloader(defaultStore, conn, DownloaderOptions{})
	t.Cleanup(func() { _ = defaultDownloader.Close() })
	if _, err := defaultDownloader.Download(context.Background(), hash, []netaddr.EndpointAddr{addr}); err == nil {
		t.Fatal("default Downloader succeeded against custom-ALPN provider, want error")
	}

	// Downloader configured with customALPN succeeds.
	customStore := &downloadStore{}
	customDownloader := NewDownloader(customStore, conn, DownloaderOptions{ALPN: customALPN})
	t.Cleanup(func() { _ = customDownloader.Close() })
	tag, err := customDownloader.Download(context.Background(), hash, []netaddr.EndpointAddr{addr})
	if err != nil {
		t.Fatalf("custom-ALPN Download: %v", err)
	}
	defer tag.Close()
	if got := customStore.blobs[hash]; !bytes.Equal(got, data) {
		t.Fatalf("stored blob = %q, want %q", got, data)
	}
}

type downloadStore struct {
	mu    sync.Mutex
	blobs map[Hash][]byte
}

func (s *downloadStore) NewBlob(context.Context) (BlobWriter, error) {
	return &downloadStoreWriter{store: s}, nil
}

type downloadStoreWriter struct {
	store *downloadStore
	buf   bytes.Buffer
	done  bool
}

func (w *downloadStoreWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func (w *downloadStoreWriter) Commit() (*TempTag, error) {
	data := w.buf.Bytes()
	hash := NewHash(data)
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	if w.store.blobs == nil {
		w.store.blobs = make(map[Hash][]byte)
	}
	w.store.blobs[hash] = append([]byte(nil), data...)
	w.done = true
	return &TempTag{value: RawHash(hash)}, nil
}

func (w *downloadStoreWriter) Close() error { w.done = true; return nil }

type fakeBlobConnector struct {
	mu       sync.Mutex
	alpn     string
	blobs    map[string]map[Hash][]byte
	fail     map[string]error
	connects map[string]int
	streams  map[string]int
}

func (c *fakeBlobConnector) Connect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (BlobConn, error) {
	wantALPN := c.alpn
	if wantALPN == "" {
		wantALPN = ALPN
	}
	if alpn != wantALPN {
		return nil, errors.New("wrong alpn")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := addr.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.connects == nil {
		c.connects = make(map[string]int)
	}
	c.connects[key]++
	if err := c.fail[key]; err != nil {
		return nil, err
	}
	return &fakeBlobConn{parent: c, key: key}, nil
}

type fakeBlobConn struct {
	parent *fakeBlobConnector
	key    string
}

func (c *fakeBlobConn) OpenStreamSync(ctx context.Context) (BidiStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.parent.mu.Lock()
	c.parent.streamsInit()
	c.parent.streams[c.key]++
	blobs := c.parent.blobs[c.key]
	c.parent.mu.Unlock()

	client, server := newTestBidiStreamPair()
	go func() {
		store, err := NewMemStore(mapValues(blobs)...)
		if err != nil {
			return
		}
		_ = ServeBlob(ctx, server, store)
	}()
	return client, nil
}

func (c *fakeBlobConn) CloseWithError(uint64, string) error { return nil }

func (c *fakeBlobConnector) streamsInit() {
	if c.streams == nil {
		c.streams = make(map[string]int)
	}
}

func testEndpointAddr(seed byte) netaddr.EndpointAddr {
	var b [key.SeedSize]byte
	b[0] = seed
	id := key.NewSecretKey(b).Public().EndpointID()
	return netaddr.NewEndpointAddr(id)
}

func mapValues(m map[Hash][]byte) [][]byte {
	out := make([][]byte, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
