package docs

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// LiveSyncOptions configures live document synchronization over iroh-gossip.
type LiveSyncOptions struct {
	// Bootstrap is the initial set of peers to join and sync with.
	Bootstrap []netaddr.EndpointAddr
	// Resolver resolves neighbor IDs to endpoint addresses before syncing.
	Resolver iroh.AddressResolver
	// BlobStore reports which entry content is locally available.
	BlobStore blobs.Store
	// Config configures range reconciliation.
	Config SyncConfig
	// DownloadPolicy selects which entry content live sync downloads. The zero
	// value downloads every key.
	DownloadPolicy DownloadPolicy
	// OnSync, if non-nil, is called after each sync attempt.
	OnSync func(SyncResult)
}

// DownloadPolicy selects document entry keys for live-sync content downloads.
type DownloadPolicy struct {
	// IncludePrefixes, when non-empty, allows only keys with one of these prefixes.
	IncludePrefixes []string
	// ExcludePrefixes rejects keys with one of these prefixes.
	ExcludePrefixes []string
	// IncludeGlobs, when non-empty, allows only keys matching one of these globs.
	IncludeGlobs []string
	// ExcludeGlobs rejects keys matching one of these globs.
	ExcludeGlobs []string
}

func (p DownloadPolicy) allow(key []byte) bool {
	s := string(key)
	if len(p.IncludePrefixes) != 0 && !matchPrefix(s, p.IncludePrefixes) {
		return false
	}
	if len(p.IncludeGlobs) != 0 && !matchGlob(s, p.IncludeGlobs) {
		return false
	}
	return !matchPrefix(s, p.ExcludePrefixes) && !matchGlob(s, p.ExcludeGlobs)
}

func matchPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func matchGlob(s string, globs []string) bool {
	for _, glob := range globs {
		if ok, _ := path.Match(glob, s); ok {
			return true
		}
	}
	return false
}

type liveSyncOptions struct {
	LiveSyncOptions
	syncPeer             func(context.Context, netaddr.EndpointAddr) (SyncOutcome, error)
	downloadBlob         func(context.Context, []netaddr.EndpointAddr, blobs.Hash) error
	maxGossipPayloadSize int
}

const liveDownloadQueueSize = 16

// LiveSync keeps a document store synchronized over an iroh-gossip topic.
type LiveSync struct {
	cancel      context.CancelFunc
	done        chan struct{}
	topic       *gossip.Topic
	cancelStore func()
	downloads   chan liveDownload

	mu      sync.Mutex
	pending map[blobs.Hash]*pendingDownload // queued or in-flight downloads
}

// StartLiveSync starts live synchronization for namespace.
//
// Local store inserts are broadcast over gossip. Received inserts are added as
// remote entries. New neighbors and bootstrap peers are synchronized with the
// iroh-docs range-reconciliation protocol. The content of remote entries,
// received either way, is downloaded as opts.DownloadPolicy allows.
func StartLiveSync(ctx context.Context, ep *iroh.Endpoint, g *gossip.Gossip, namespace NamespaceID, store *MemoryStore, opts LiveSyncOptions) (*LiveSync, error) {
	if ep == nil {
		return nil, errors.New("docs: nil endpoint")
	}
	if g == nil {
		return nil, errors.New("docs: nil gossip")
	}
	if store == nil {
		return nil, errors.New("docs: nil store")
	}
	topic, err := g.Subscribe(ctx, gossip.TopicID(namespace.Bytes()), opts.Bootstrap)
	if err != nil {
		return nil, fmt.Errorf("docs: subscribe gossip: %w", err)
	}
	cfg := liveSyncOptions{LiveSyncOptions: opts}
	cfg.maxGossipPayloadSize = gossipproto.MaxPayloadSize(g.MaxMessageSize())
	cfg.syncPeer = func(ctx context.Context, addr netaddr.EndpointAddr) (SyncOutcome, error) {
		return Sync(ctx, ep, addr, namespace, store, opts.BlobStore, opts.Config)
	}
	cfg.downloadBlob = func(ctx context.Context, providers []netaddr.EndpointAddr, hash blobs.Hash) error {
		return downloadBlob(ctx, ep, providers, opts.BlobStore, hash)
	}
	ctx, cancel := context.WithCancel(ctx)
	events, cancelStore := store.Subscribe()
	l := &LiveSync{
		cancel:      cancel,
		done:        make(chan struct{}),
		topic:       topic,
		cancelStore: cancelStore,
		downloads:   make(chan liveDownload, liveDownloadQueueSize),
		pending:     make(map[blobs.Hash]*pendingDownload),
	}
	go l.run(ctx, namespace, store, cfg, events)
	return l, nil
}

// Close stops the live synchronization background task.
func (l *LiveSync) Close() error {
	if l == nil {
		return nil
	}
	l.cancel()
	if l.cancelStore != nil {
		l.cancelStore()
	}
	err := l.topic.Close()
	<-l.done
	return err
}

func (l *LiveSync) run(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, storeEvents <-chan StoreEvent) {
	defer close(l.done)
	topicEvents := make(chan gossip.Event)
	go func() {
		defer close(topicEvents)
		for ev, err := range l.topic.Events() {
			if err != nil {
				continue
			}
			select {
			case topicEvents <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	if len(opts.Bootstrap) != 0 {
		go l.syncPeers(ctx, namespace, store, opts, opts.Bootstrap)
	}
	go l.runDownloader(ctx, store, opts)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-storeEvents:
			if !ok {
				return
			}
			l.handleStoreEvent(ctx, namespace, opts, ev)
		case ev, ok := <-topicEvents:
			if !ok {
				return
			}
			l.handleTopicEvent(ctx, namespace, store, opts, ev)
		}
	}
}

func (l *LiveSync) handleStoreEvent(ctx context.Context, namespace NamespaceID, opts liveSyncOptions, ev StoreEvent) {
	// A store can hold several namespaces, but this topic carries one: an
	// entry from another namespace must not reach these neighbors.
	if ev.Entry.Entry.Namespace() != namespace {
		return
	}
	switch ev.Kind {
	case StoreEventInsertRemote:
		// An entry synced by range reconciliation carries the sending
		// peer's content status. Fetch the content from that peer if it
		// has all of it; otherwise wait for its ContentReady, as iroh-docs
		// does (engine/live.rs:719-736). A gossip Put queues its own
		// download in handleReceived and records the local status, which
		// is complete only when there is nothing to fetch.
		if ev.ContentStatus == ContentComplete && !ev.From.IsZero() {
			l.queueDownload(ctx, opts, ev.Entry.Entry.ContentHash(), ev.Entry.Entry.Key(), true, ev.From)
		}
		return
	case StoreEventInsertLocal:
	default:
		return
	}
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: ev.Entry})
	if err != nil {
		return
	}
	_ = l.topic.Broadcast(ctx, msg)
	hash := ev.Entry.Entry.ContentHash()
	if contentComplete(ctx, opts.BlobStore, hash) {
		l.broadcastContentReady(ctx, hash)
	}
}

func (l *LiveSync) handleTopicEvent(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, ev gossip.Event) {
	switch ev.Kind {
	case gossip.Received:
		l.handleReceived(ctx, namespace, store, opts, ev)
	case gossip.NeighborUp:
		addr, ok := l.resolvePeer(ctx, opts.Resolver, ev.Peer)
		if !ok {
			addr = netaddr.EndpointAddr{ID: ev.Peer}
		}
		go l.syncPeers(ctx, namespace, store, opts, []netaddr.EndpointAddr{addr})
	case gossip.Lagged:
		// A missed gossip event means we may have missed a Put. Sync known peers.
		go l.syncPeers(ctx, namespace, store, opts, opts.Bootstrap)
	}
}

func (l *LiveSync) handleReceived(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, ev gossip.Event) {
	var op liveOp
	if err := postcard.Unmarshal(ev.Content, &op); err != nil {
		return
	}
	switch op.Kind {
	case liveOpPut:
		if op.Entry.Entry.Namespace() != namespace || !acceptTimestamp(op.Entry.Entry) || op.Entry.Verify() != nil {
			return
		}
		hash := op.Entry.Entry.ContentHash()
		status := ContentMissing
		if contentComplete(ctx, opts.BlobStore, hash) {
			status = ContentComplete
		}
		outcome := store.PutWithOrigin(op.Entry, InsertOrigin{
			Kind:          InsertOriginRemote,
			From:          ev.DeliveredFrom,
			ContentStatus: status,
		})
		if outcome.Inserted() && status != ContentComplete {
			l.queueDownload(ctx, opts, hash, op.Entry.Entry.Key(), true, ev.DeliveredFrom)
		}
	case liveOpContentReady:
		if op.Hash != blobs.EmptyHash && store.downloadAllowed(namespace, op.Hash, opts.DownloadPolicy) {
			// The policy was already applied by downloadAllowed above.
			l.queueDownload(ctx, opts, op.Hash, nil, false, ev.DeliveredFrom)
		}
	case liveOpSyncReport:
		if op.Report.Namespace != namespace {
			return
		}
		if !store.hasNewsForUs(namespace, op.Report.Heads) {
			return
		}
		addr, ok := l.resolvePeer(ctx, opts.Resolver, ev.DeliveredFrom)
		if !ok {
			addr = netaddr.EndpointAddr{ID: ev.DeliveredFrom}
		}
		go l.syncPeers(ctx, namespace, store, opts, []netaddr.EndpointAddr{addr})
	}
}

func (l *LiveSync) broadcastContentReady(ctx context.Context, hash blobs.Hash) {
	msg, err := postcard.Marshal(liveOp{Kind: liveOpContentReady, Hash: hash})
	if err != nil {
		return
	}
	_ = l.topic.Broadcast(ctx, msg)
}

func (l *LiveSync) queueDownload(ctx context.Context, opts liveSyncOptions, hash blobs.Hash, entryKey []byte, applyPolicy bool, peer key.EndpointID) {
	if l.downloads == nil || hash == blobs.EmptyHash || contentComplete(ctx, opts.BlobStore, hash) {
		return
	}
	// applyPolicy is false for callers that already filtered by policy (the
	// content-ready path). Otherwise apply it, including to an empty key, which
	// matches no include prefix and so is correctly excluded by a restrictive
	// policy.
	if applyPolicy && !opts.DownloadPolicy.allow(entryKey) {
		return
	}
	addr, ok := l.downloadAddr(ctx, opts, peer)
	if !ok {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending == nil {
		l.pending = make(map[blobs.Hash]*pendingDownload)
	}
	pending := l.pending[hash]
	if pending != nil {
		pending.add(addr)
		return
	}
	pending = newPendingDownload(addr)
	l.pending[hash] = pending
	select {
	case l.downloads <- liveDownload{Hash: hash, pending: pending}:
	default:
		delete(l.pending, hash)
	}
}

// untried returns the providers of req after the first tried. If there are
// none, it forgets req, so that the next announcement of the hash starts a new
// download instead of joining one that has ended.
func (l *LiveSync) untried(req liveDownload, tried int) []netaddr.EndpointAddr {
	l.mu.Lock()
	defer l.mu.Unlock()
	providers := req.pending.snapshot()[tried:]
	if len(providers) == 0 && l.pending[req.Hash] == req.pending {
		delete(l.pending, req.Hash)
	}
	return providers
}

func (l *LiveSync) forget(req liveDownload) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.pending[req.Hash] == req.pending {
		delete(l.pending, req.Hash)
	}
}

func (l *LiveSync) downloadAddr(ctx context.Context, opts liveSyncOptions, id key.EndpointID) (netaddr.EndpointAddr, bool) {
	if addr, ok := l.resolvePeer(ctx, opts.Resolver, id); ok {
		return addr, true
	}
	for _, addr := range opts.Bootstrap {
		if addr.ID.Equal(id) {
			return addr, true
		}
	}
	return netaddr.EndpointAddr{}, false
}

func (s *MemoryStore) downloadAllowed(namespace NamespaceID, hash blobs.Hash, policy DownloadPolicy) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.entries {
		if entry.Entry.Namespace() == namespace && entry.Entry.ContentHash() == hash && policy.allow(entry.Entry.Key()) {
			return true
		}
	}
	return false
}

func (l *LiveSync) runDownloader(ctx context.Context, store *MemoryStore, opts liveSyncOptions) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-l.downloads:
			l.download(ctx, store, opts, req)
		}
	}
}

// download fetches req's content, trying providers that announce it while
// earlier ones fail, and forgets req when it is done either way.
func (l *LiveSync) download(ctx context.Context, store *MemoryStore, opts liveSyncOptions, req liveDownload) {
	tried := 0
	for {
		if contentComplete(ctx, opts.BlobStore, req.Hash) {
			l.forget(req)
			store.contentReady(req.Hash)
			return
		}
		if opts.downloadBlob == nil {
			l.forget(req)
			return
		}
		providers := l.untried(req, tried)
		if len(providers) == 0 {
			return
		}
		tried += len(providers)
		if err := opts.downloadBlob(ctx, providers, req.Hash); err != nil {
			continue
		}
		l.forget(req)
		store.contentReady(req.Hash)
		l.broadcastContentReady(ctx, req.Hash)
		return
	}
}

type liveDownload struct {
	Hash    blobs.Hash
	pending *pendingDownload
}

type pendingDownload struct {
	mu        sync.Mutex
	providers []netaddr.EndpointAddr
	seen      map[key.EndpointID]struct{}
}

func newPendingDownload(addr netaddr.EndpointAddr) *pendingDownload {
	p := &pendingDownload{seen: make(map[key.EndpointID]struct{})}
	p.add(addr)
	return p
}

func (p *pendingDownload) add(addr netaddr.EndpointAddr) {
	if p == nil || addr.ID.IsZero() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.seen[addr.ID]; ok {
		return
	}
	p.seen[addr.ID] = struct{}{}
	p.providers = append(p.providers, addr)
}

func (p *pendingDownload) snapshot() []netaddr.EndpointAddr {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netaddr.EndpointAddr(nil), p.providers...)
}

// contentComplete reports whether the store holds hash in full.
//
// A store that cannot answer is treated as not holding the content: these
// call sites gate broadcasts and downloads, where re-fetching content we
// already have is cheap and announcing content we cannot read is not.
func contentComplete(ctx context.Context, store blobs.Store, hash blobs.Hash) bool {
	status, err := blobs.Status(ctx, store, hash)
	if err != nil {
		return false
	}
	return status.IsComplete()
}

func downloadBlob(ctx context.Context, ep *iroh.Endpoint, providers []netaddr.EndpointAddr, store blobs.Store, hash blobs.Hash) error {
	if ep == nil {
		return errors.New("docs: nil endpoint")
	}
	sink, ok := store.(blobs.Sink)
	if !ok {
		return fmt.Errorf("docs: download blob: %w", blobs.ErrStoreReadOnly)
	}
	d := blobs.NewDownloader(sink, blobs.BlobConnectorFunc(func(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (blobs.BlobConn, error) {
		conn, err := ep.Connect(ctx, addr, alpn)
		if err != nil {
			return nil, err
		}
		return blobConn{Conn: conn}, nil
	}), blobs.DownloaderOptions{Concurrency: len(providers)})
	defer d.Close()
	tag, err := d.Download(ctx, hash, providers)
	if err != nil {
		return err
	}
	// Live sync holds no durable name for downloaded content: the document
	// entry that referenced the hash is the record, and the blob store is the
	// caller's to collect. Release the tag and let the caller's policy decide.
	return tag.Close()
}

type blobConn struct {
	*iroh.Conn
}

func (c blobConn) OpenStreamSync(ctx context.Context) (blobs.BidiStream, error) {
	return c.Conn.OpenStreamSync(ctx)
}

func (l *LiveSync) syncPeers(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, peers []netaddr.EndpointAddr) {
	for _, peer := range peers {
		var outcome SyncOutcome
		var err error
		if opts.syncPeer != nil {
			outcome, err = opts.syncPeer(ctx, peer)
		} else {
			err = errors.New("docs: sync peer not configured")
		}
		if opts.OnSync != nil {
			opts.OnSync(SyncResult{Addr: peer, Outcome: outcome, Err: err})
		}
		if err == nil && outcome.NumRecv > 0 {
			l.broadcastSyncReport(ctx, namespace, store, opts)
		}
	}
}

func (l *LiveSync) broadcastSyncReport(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions) {
	limit := opts.maxGossipPayloadSize
	if limit <= 0 {
		limit = gossipproto.DefaultMaxPayloadSize()
	}
	heads := store.encodeAuthorHeadsLimited(namespace, limit, func(heads []byte) bool {
		msg, err := marshalSyncReport(namespace, heads)
		return err == nil && len(msg) <= limit
	})
	msg, err := marshalSyncReport(namespace, heads)
	if err != nil {
		return
	}
	_ = l.topic.BroadcastNeighbors(ctx, msg)
}

func marshalSyncReport(namespace NamespaceID, heads []byte) ([]byte, error) {
	return postcard.Marshal(liveOp{Kind: liveOpSyncReport, Report: liveSyncReport{
		Namespace: namespace,
		Heads:     heads,
	}})
}

func (l *LiveSync) resolvePeer(ctx context.Context, resolver iroh.AddressResolver, id key.EndpointID) (netaddr.EndpointAddr, bool) {
	if resolver == nil || id.IsZero() {
		return netaddr.EndpointAddr{}, false
	}
	for item, err := range resolver.Resolve(ctx, id) {
		if err != nil {
			continue
		}
		return item.Addr(), true
	}
	return netaddr.EndpointAddr{}, false
}

type liveOpKind uint64

const (
	liveOpPut liveOpKind = iota
	liveOpContentReady
	liveOpSyncReport
)

type liveOp struct {
	Kind   liveOpKind
	Entry  SignedEntry
	Hash   blobs.Hash
	Report liveSyncReport
}

type liveSyncReport struct {
	Namespace NamespaceID
	Heads     []byte
}

func (op liveOp) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(op.Kind))
	switch op.Kind {
	case liveOpPut:
		return e.Encode(op.Entry)
	case liveOpContentReady:
		e.RawBytes(op.Hash[:])
		return nil
	case liveOpSyncReport:
		return e.Encode(op.Report)
	default:
		return fmt.Errorf("docs: unknown live op %d", op.Kind)
	}
}

func (op *liveOp) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	op.Kind = liveOpKind(kind)
	switch op.Kind {
	case liveOpPut:
		return d.Decode(&op.Entry)
	case liveOpContentReady:
		b, err := d.RawBytes(len(op.Hash))
		if err != nil {
			return err
		}
		copy(op.Hash[:], b)
		return nil
	case liveOpSyncReport:
		return d.Decode(&op.Report)
	default:
		return fmt.Errorf("docs: unknown live op %d", op.Kind)
	}
}

func (r liveSyncReport) EncodePostcard(e *postcard.Encoder) error {
	if err := e.Encode(r.Namespace); err != nil {
		return err
	}
	e.BytesValue(r.Heads)
	return nil
}

func (r *liveSyncReport) DecodePostcard(d *postcard.Decoder) error {
	if err := d.Decode(&r.Namespace); err != nil {
		return err
	}
	heads, err := d.BytesValue()
	if err != nil {
		return err
	}
	r.Heads = heads
	return nil
}
