package blobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// BlobConnector opens blob protocol connections to providers.
type BlobConnector interface {
	Connect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (BlobConn, error)
}

// BlobConnectorFunc adapts a function to [BlobConnector].
type BlobConnectorFunc func(context.Context, netaddr.EndpointAddr, string) (BlobConn, error)

// Connect calls f(ctx, addr, alpn).
func (f BlobConnectorFunc) Connect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (BlobConn, error) {
	return f(ctx, addr, alpn)
}

// BlobConn is the subset of an iroh connection used by Downloader.
type BlobConn interface {
	OpenStreamSync(context.Context) (BidiStream, error)
	CloseWithError(code uint64, reason string) error
}

// BlobConnFunc adapts a stream-opening function to [BlobConn].
type BlobConnFunc func(context.Context) (BidiStream, error)

// OpenStreamSync calls f(ctx).
func (f BlobConnFunc) OpenStreamSync(ctx context.Context) (BidiStream, error) {
	return f(ctx)
}

// CloseWithError implements [BlobConn].
func (f BlobConnFunc) CloseWithError(uint64, string) error {
	return nil
}

// DownloadEventKind identifies a downloader progress event.
type DownloadEventKind int

const (
	// DownloadTryProvider reports that a provider is being tried.
	DownloadTryProvider DownloadEventKind = iota
	// DownloadProviderFailed reports that a provider failed.
	DownloadProviderFailed
	// DownloadComplete reports that a provider completed the download.
	DownloadComplete
)

// DownloadEvent reports downloader progress.
type DownloadEvent struct {
	Kind     DownloadEventKind
	Hash     Hash
	Provider netaddr.EndpointAddr
	Err      error
}

// DefaultStallTimeout is the [DownloaderOptions.StallTimeout] used when it
// is zero. It matches [github.com/tmc/go-iroh/iroh.RelayPathMaxIdleTimeout],
// the longest an iroh connection waits on a silent peer: a provider that
// keeps its connection alive but sends nothing for that long is as good as
// gone.
const DefaultStallTimeout = 30 * time.Second

// ErrProviderStalled reports a provider that delivered no verified content
// for [DownloaderOptions.StallTimeout].
var ErrProviderStalled = errors.New("blobs: provider stalled")

// DownloaderOptions configures a Downloader.
type DownloaderOptions struct {
	// Concurrency is the maximum number of providers tried at once.
	// Values <= 0 use 1.
	Concurrency int
	// OnEvent, if non-nil, receives progress events. It is called serially,
	// so it need not be safe for concurrent use even when Concurrency > 1.
	OnEvent func(DownloadEvent)
	// StallTimeout is how long a provider may go without delivering
	// verified content, counting from when it is first tried, before
	// Download abandons it with [ErrProviderStalled] and tries the next.
	// Zero means [DefaultStallTimeout]; a negative value disables the limit.
	StallTimeout time.Duration
}

// Downloader downloads blobs from multiple providers.
type Downloader struct {
	store Sink
	conn  BlobConnector
	opts  DownloaderOptions

	mu    sync.Mutex
	conns map[string]BlobConn

	// eventMu serializes OnEvent so a worker fan-out (Concurrency > 1) does
	// not deliver events concurrently; callers need not make OnEvent
	// concurrency-safe.
	eventMu sync.Mutex
}

// NewDownloader returns a downloader using store and conn.
//
// store must implement [Sink]; downloaded content is streamed into a
// [BlobWriter] rather than buffered.
func NewDownloader(store Sink, conn BlobConnector, opts DownloaderOptions) *Downloader {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 1
	}
	if opts.StallTimeout == 0 {
		opts.StallTimeout = DefaultStallTimeout
	}
	return &Downloader{store: store, conn: conn, opts: opts, conns: make(map[string]BlobConn)}
}

// Close closes cached provider connections.
func (d *Downloader) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	conns := d.conns
	d.conns = make(map[string]BlobConn)
	d.mu.Unlock()
	var err error
	for _, conn := range conns {
		if e := conn.CloseWithError(0, ""); e != nil {
			err = errors.Join(err, e)
		}
	}
	return err
}

// Download downloads hash from one of providers and stores it locally.
//
// Download returns the [TempTag] protecting the stored blob. The blob is
// collectible as soon as the tag is closed, so a caller that runs
// [FSStore.GC] must hold it until it has established durable ownership,
// usually by naming the blob with [FSStore.SetTag]. A caller that does not
// collect garbage can close it immediately.
func (d *Downloader) Download(ctx context.Context, hash Hash, providers []netaddr.EndpointAddr) (*TempTag, error) {
	if d == nil {
		return nil, errors.New("blobs: nil downloader")
	}
	if d.store == nil {
		return nil, errors.New("blobs: nil downloader store")
	}
	if d.conn == nil {
		return nil, errors.New("blobs: nil downloader connector")
	}
	if hash == EmptyHash {
		tag, err := d.commitEmpty(ctx)
		if err != nil {
			return nil, fmt.Errorf("blobs: store empty blob: %w", err)
		}
		if tag.Hash() != hash {
			tag.Close()
			return nil, fmt.Errorf("blobs: stored blob hash mismatch")
		}
		return tag, nil
	}
	if len(providers) == 0 {
		return nil, errors.New("blobs: no providers")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	concurrency := d.opts.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > len(providers) {
		concurrency = len(providers)
	}

	jobs := make(chan netaddr.EndpointAddr)
	results := make(chan downloadResult, concurrency)
	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				results <- d.tryProvider(ctx, hash, addr)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, addr := range providers {
			select {
			case jobs <- addr:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var err error
	var won *TempTag
	for res := range results {
		if res.err == nil {
			// First success wins. Cancel the remaining providers, but keep
			// draining results so every worker (and its OnEvent delivery)
			// finishes before Download returns — otherwise a late event races
			// the caller's post-Download reads. Later winners are redundant
			// copies of the same content, so release their tags.
			if won == nil {
				won = res.tag
				cancel()
			} else {
				res.tag.Close()
			}
			continue
		}
		res.tag.Close()
		err = errors.Join(err, res.err)
	}
	if won != nil {
		return won, nil
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = errors.New("blobs: download failed")
	}
	return nil, err
}

type downloadResult struct {
	addr netaddr.EndpointAddr
	tag  *TempTag
	err  error
}

func (d *Downloader) tryProvider(ctx context.Context, hash Hash, addr netaddr.EndpointAddr) downloadResult {
	d.event(DownloadEvent{Kind: DownloadTryProvider, Hash: hash, Provider: addr})
	progress := func() {}
	if timeout := d.opts.StallTimeout; timeout > 0 {
		var cancel context.CancelCauseFunc
		ctx, cancel = context.WithCancelCause(ctx)
		defer cancel(nil)
		timer := time.AfterFunc(timeout, func() { cancel(ErrProviderStalled) })
		defer timer.Stop()
		progress = func() { timer.Reset(timeout) }
	}
	tag, err := d.fetch(ctx, hash, addr, progress)
	if err != nil && errors.Is(context.Cause(ctx), ErrProviderStalled) {
		err = fmt.Errorf("%w: %s", ErrProviderStalled, addr.ID)
	}
	if err != nil {
		d.event(DownloadEvent{Kind: DownloadProviderFailed, Hash: hash, Provider: addr, Err: err})
		return downloadResult{addr: addr, err: err}
	}
	d.event(DownloadEvent{Kind: DownloadComplete, Hash: hash, Provider: addr})
	return downloadResult{addr: addr, tag: tag}
}

// fetch downloads hash from addr, calling progress after each write of
// verified content.
func (d *Downloader) fetch(ctx context.Context, hash Hash, addr netaddr.EndpointAddr, progress func()) (*TempTag, error) {
	conn, err := d.connection(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("blobs: connect provider %s: %w", addr.ID, err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		d.drop(addr)
		return nil, fmt.Errorf("blobs: open provider stream %s: %w", addr.ID, err)
	}
	tag, err := d.streamBlob(ctx, stream, hash, progress)
	if err != nil {
		return nil, fmt.Errorf("blobs: get blob from provider %s: %w", addr.ID, err)
	}
	if tag.Hash() != hash {
		tag.Close()
		return nil, fmt.Errorf("blobs: stored blob hash mismatch")
	}
	return tag, nil
}

func (d *Downloader) connection(ctx context.Context, addr netaddr.EndpointAddr) (BlobConn, error) {
	key := addr.String()
	d.mu.Lock()
	conn := d.conns[key]
	d.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	conn, err := d.conn.Connect(ctx, addr, ALPN)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if old := d.conns[key]; old != nil {
		d.mu.Unlock()
		_ = conn.CloseWithError(0, "")
		return old, nil
	}
	d.conns[key] = conn
	d.mu.Unlock()
	return conn, nil
}

func (d *Downloader) drop(addr netaddr.EndpointAddr) {
	key := addr.String()
	d.mu.Lock()
	conn := d.conns[key]
	delete(d.conns, key)
	d.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
}

func (d *Downloader) event(ev DownloadEvent) {
	if d.opts.OnEvent == nil {
		return
	}
	d.eventMu.Lock()
	defer d.eventMu.Unlock()
	d.opts.OnEvent(ev)
}

// streamBlob downloads hash from stream straight into a [BlobWriter], so the
// blob is never held in memory, and returns the tag protecting it. It calls
// progress after each write of verified content.
func (d *Downloader) streamBlob(ctx context.Context, stream BidiStream, hash Hash, progress func()) (*TempTag, error) {
	w, err := d.store.NewBlob(ctx)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	if err := DownloadBlob(ctx, stream, hash, progressWriter{w, progress}); err != nil {
		return nil, err
	}
	return w.Commit()
}

// progressWriter calls progress after each write to w.
type progressWriter struct {
	w        io.Writer
	progress func()
}

func (w progressWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.progress()
	}
	return n, err
}

// commitEmpty stores the zero-length blob.
func (d *Downloader) commitEmpty(ctx context.Context) (*TempTag, error) {
	w, err := d.store.NewBlob(ctx)
	if err != nil {
		return nil, err
	}
	defer w.Close()
	return w.Commit()
}
