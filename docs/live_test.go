package docs

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestLiveOpPutRoundTrip(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))

	data, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got liveOp
	if err := postcard.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Kind != liveOpPut || !got.Entry.Equal(entry) {
		t.Fatalf("op = %#v, want put entry", got)
	}
}

func TestLiveSyncReceivedPut(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	from, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}

	store := NewMemoryStore()
	events, cancel := store.Subscribe()
	defer cancel()
	var l LiveSync
	l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{}, gossip.Event{
		Kind:          gossip.Received,
		Content:       msg,
		DeliveredFrom: from.Public().EndpointID(),
		Scope:         gossip.DeliveryNeighbors,
	})

	got, ok := store.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok || !got.Equal(entry) {
		t.Fatal("received put was not inserted")
	}
	event := readStoreEvent(t, events)
	if event.Kind != StoreEventInsertRemote || event.ContentStatus != ContentMissing {
		t.Fatalf("event = %#v, want remote missing insert", event)
	}
}

func TestLiveSyncReceivedSwarmPutMarksMissing(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	store := NewMemoryStore()
	events, cancel := store.Subscribe()
	defer cancel()
	var l LiveSync
	l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{}, gossip.Event{
		Kind:    gossip.Received,
		Content: msg,
		Scope:   gossip.DeliverySwarm,
		Round:   2,
	})

	event := readStoreEvent(t, events)
	if event.Kind != StoreEventInsertRemote || event.ContentStatus != ContentMissing {
		t.Fatalf("event = %#v, want remote missing insert", event)
	}
}

func TestLiveSyncDownloadPolicySkipsRemotePut(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	hash := blobs.NewHash([]byte("secret content"))
	entry := testSignedEntry(namespace, author, "private/k", NewRecord(hash, 14, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	from, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	addr := netaddr.NewEndpointAddr(from.Public().EndpointID())
	blobStore, err := blobs.NewMemStore()
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}

	l := LiveSync{downloads: make(chan liveDownload, 1)}
	l.handleReceived(context.Background(), namespace.ID(), NewMemoryStore(), liveSyncOptions{
		LiveSyncOptions: LiveSyncOptions{
			BlobStore:      blobStore,
			Resolver:       iroh.StaticLookupFromAddrs(addr),
			DownloadPolicy: DownloadPolicy{ExcludePrefixes: []string{"private/"}},
		},
	}, gossip.Event{
		Kind:          gossip.Received,
		Content:       msg,
		DeliveredFrom: from.Public().EndpointID(),
	})
	select {
	case req := <-l.downloads:
		t.Fatalf("queued download for excluded key: %+v", req)
	default:
	}
}

// TestLiveSyncDownloadPolicySkipsEmptyKeyPut is a regression test: an empty
// entry key must still be subject to the download policy. A previous guard
// skipped the policy check when the key was nil, letting an empty-key remote
// Put bypass a restrictive policy.
func TestLiveSyncDownloadPolicySkipsEmptyKeyPut(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	hash := blobs.NewHash([]byte("secret content"))
	entry := testSignedEntry(namespace, author, "", NewRecord(hash, 14, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	from, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	addr := netaddr.NewEndpointAddr(from.Public().EndpointID())
	blobStore, err := blobs.NewMemStore()
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}

	l := LiveSync{downloads: make(chan liveDownload, 1)}
	l.handleReceived(context.Background(), namespace.ID(), NewMemoryStore(), liveSyncOptions{
		LiveSyncOptions: LiveSyncOptions{
			BlobStore: blobStore,
			Resolver:  iroh.StaticLookupFromAddrs(addr),
			// An include-only policy: the empty key matches no prefix, so it
			// must be excluded.
			DownloadPolicy: DownloadPolicy{IncludePrefixes: []string{"public/"}},
		},
	}, gossip.Event{
		Kind:          gossip.Received,
		Content:       msg,
		DeliveredFrom: from.Public().EndpointID(),
	})
	select {
	case req := <-l.downloads:
		t.Fatalf("queued download for empty key excluded by policy: %+v", req)
	default:
	}
}

func TestLiveSyncDownloadPolicySkipsContentReady(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	hash := blobs.NewHash([]byte("secret content"))
	entry := testSignedEntry(namespace, author, "private/k", NewRecord(hash, 14, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpContentReady, Hash: hash})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	from, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	addr := netaddr.NewEndpointAddr(from.Public().EndpointID())
	blobStore, err := blobs.NewMemStore()
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	store := NewMemoryStore()
	store.PutWithOrigin(entry, InsertOrigin{Kind: InsertOriginRemote, ContentStatus: ContentMissing})

	l := LiveSync{downloads: make(chan liveDownload, 1)}
	l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{
		LiveSyncOptions: LiveSyncOptions{
			BlobStore:      blobStore,
			Resolver:       iroh.StaticLookupFromAddrs(addr),
			DownloadPolicy: DownloadPolicy{ExcludePrefixes: []string{"private/"}},
		},
	}, gossip.Event{
		Kind:          gossip.Received,
		Content:       msg,
		DeliveredFrom: from.Public().EndpointID(),
	})
	select {
	case req := <-l.downloads:
		t.Fatalf("queued download for excluded content-ready key: %+v", req)
	default:
	}
}

func TestLiveSyncQueuesMultipleContentProviders(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	hash := blobs.NewHash([]byte("shared content"))
	entry := testSignedEntry(namespace, author, "public/k", NewRecord(hash, 14, 1))
	store := NewMemoryStore()
	store.PutWithOrigin(entry, InsertOrigin{Kind: InsertOriginRemote, ContentStatus: ContentMissing})
	blobStore, err := blobs.NewMemStore()
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	firstKey := key.NewSecretKey(repeat32(0x01))
	secondKey := key.NewSecretKey(repeat32(0x02))
	first := netaddr.NewEndpointAddr(firstKey.Public().EndpointID())
	second := netaddr.NewEndpointAddr(secondKey.Public().EndpointID())
	l := LiveSync{downloads: make(chan liveDownload, 1)}
	opts := liveSyncOptions{
		LiveSyncOptions: LiveSyncOptions{
			BlobStore: blobStore,
			Resolver:  iroh.StaticLookupFromAddrs(first, second),
		},
	}

	l.queueDownload(context.Background(), opts, hash, entry.Entry.Key(), true, first.ID)
	l.queueDownload(context.Background(), opts, hash, nil, false, second.ID)

	select {
	case req := <-l.downloads:
		providers := req.pending.snapshot()
		if len(providers) != 2 {
			t.Fatalf("providers len = %d, want 2", len(providers))
		}
		if !providers[0].ID.Equal(first.ID) || !providers[1].ID.Equal(second.ID) {
			t.Fatalf("providers = %v, want %s then %s", providers, first.ID, second.ID)
		}
	default:
		t.Fatal("download was not queued")
	}
	select {
	case req := <-l.downloads:
		t.Fatalf("queued duplicate download: %+v", req)
	default:
	}
}

func TestLiveSyncDownloadsRemoteContent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	content := []byte("content fetched by live sync")
	contentHash := blobs.NewHash(content)
	entry := testSignedEntry(namespace, author, "k", NewRecord(contentHash, uint64(len(content)), 1))

	aStore := NewMemoryStore()
	aBlobs, err := blobs.NewMemStore(content)
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	a, aGossip, aRouter := newLiveSyncNode(t, ctx, aStore, aBlobs)
	defer aRouter.Shutdown(ctx)

	bStore := NewMemoryStore()
	bBlobs, err := blobs.NewMemStore()
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	b, bGossip, bRouter := newLiveSyncNode(t, ctx, bStore, bBlobs)
	defer bRouter.Shutdown(ctx)

	aAddr := netaddr.NewEndpointAddr(a.ID()).WithIP(a.LocalAddr())
	bEvents, cancelEvents := bStore.Subscribe()
	defer cancelEvents()

	aLive, err := StartLiveSync(ctx, a, aGossip, namespace.ID(), aStore, LiveSyncOptions{
		BlobStore: aBlobs,
	})
	if err != nil {
		t.Fatalf("start a live sync: %v", err)
	}
	defer aLive.Close()
	bLive, err := StartLiveSync(ctx, b, bGossip, namespace.ID(), bStore, LiveSyncOptions{
		Bootstrap: []netaddr.EndpointAddr{aAddr},
		Resolver:  iroh.StaticLookupFromAddrs(aAddr),
		BlobStore: bBlobs,
	})
	if err != nil {
		t.Fatalf("start b live sync: %v", err)
	}
	defer bLive.Close()
	if err := bLive.topic.Joined(ctx); err != nil {
		t.Fatalf("b joined: %v", err)
	}

	aStore.Put(entry)

	var ready bool
	for !ready {
		select {
		case ev := <-bEvents:
			switch ev.Kind {
			case StoreEventInsertRemote:
				// The status is whatever the blob store said when the entry
				// landed, and nothing orders the entry against its content:
				// the content can arrive first, over a download this test did
				// not ask for, leaving the insert already complete. Asserting
				// missing here made the test fail whenever b won that race.
				// What the test is really for is below — the content arrives
				// and is the content that was published.
			case StoreEventContentReady:
				if ev.Hash != contentHash {
					t.Fatalf("content ready hash = %s, want %s", ev.Hash, contentHash)
				}
				ready = true
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	got, err := blobs.ReadBlob(context.Background(), bBlobs, contentHash)
	if err != nil {
		t.Fatalf("downloaded blob missing from b store: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("downloaded blob = %q, want %q", got, content)
	}
}

func newLiveSyncNode(t *testing.T, ctx context.Context, store *MemoryStore, blobStore *blobs.MemStore) (*iroh.Endpoint, *gossip.Gossip, *iroh.Router) {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind endpoint: %v", err)
	}
	g := gossip.NewGossip(ep)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
		blobs.ALPN:  liveBlobHandler{store: blobStore},
		ALPN:        &Handler{Store: store, BlobStore: blobStore},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	return ep, g, router
}

type liveBlobHandler struct {
	store blobs.Store
}

func (h liveBlobHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	return blobs.ServeBlob(ctx, s, h.store)
}

func TestLiveSyncReportTriggersSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	namespace := NewNamespaceSecret(repeat32(0xb2))
	from, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	fromID := from.Public().EndpointID()
	addr := netaddr.NewEndpointAddr(fromID)
	msg, err := postcard.Marshal(liveOp{
		Kind: liveOpSyncReport,
		Report: liveSyncReport{
			Namespace: namespace.ID(),
			Heads:     []byte{1, 2, 3},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	called := make(chan netaddr.EndpointAddr, 1)
	var l LiveSync
	l.handleReceived(ctx, namespace.ID(), NewMemoryStore(), liveSyncOptions{
		LiveSyncOptions: LiveSyncOptions{Resolver: iroh.StaticLookupFromAddrs(addr)},
		syncPeer: func(ctx context.Context, peer netaddr.EndpointAddr) (SyncOutcome, error) {
			called <- peer
			return SyncOutcome{}, nil
		},
	}, gossip.Event{
		Kind:          gossip.Received,
		Content:       msg,
		DeliveredFrom: fromID,
	})

	select {
	case got := <-called:
		if !got.ID.Equal(fromID) {
			t.Fatalf("sync peer = %s, want %s", got.ID, fromID)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLiveSyncReportAuthorHeadsLimited(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	store := NewMemoryStore()
	for i := 0; i < 40; i++ {
		var seed [32]byte
		seed[0] = byte(i + 1)
		author := NewAuthor(seed)
		entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, uint64(i+1)))
		store.Put(entry)
	}

	all := store.encodeAuthorHeads(namespace.ID())
	allMsg, err := marshalSyncReport(namespace.ID(), all)
	if err != nil {
		t.Fatalf("marshal full report: %v", err)
	}
	limit := len(allMsg) - 200
	if limit <= 0 {
		t.Fatalf("test limit %d is not positive", limit)
	}
	heads := store.encodeAuthorHeadsLimited(namespace.ID(), limit, func(heads []byte) bool {
		msg, err := marshalSyncReport(namespace.ID(), heads)
		return err == nil && len(msg) <= limit
	})
	msg, err := marshalSyncReport(namespace.ID(), heads)
	if err != nil {
		t.Fatalf("marshal limited report: %v", err)
	}
	if len(msg) > limit {
		t.Fatalf("limited report size = %d, want <= %d", len(msg), limit)
	}

	var got []authorHead
	if err := postcard.Unmarshal(heads, &got); err != nil {
		t.Fatalf("unmarshal heads: %v", err)
	}
	if len(got) == 0 || len(got) >= 40 {
		t.Fatalf("limited heads len = %d, want between 1 and 39", len(got))
	}
	for i, head := range got {
		want := uint64(40 - i)
		if head.Timestamp != want {
			t.Fatalf("head %d timestamp = %d, want newest timestamp %d", i, head.Timestamp, want)
		}
	}
}

func TestLiveSyncReportFitsGossipPayloadBudget(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	store := NewMemoryStore()
	for i := 0; i < 120; i++ {
		var seed [32]byte
		seed[0] = byte(i + 1)
		seed[1] = byte(i / 255)
		author := NewAuthor(seed)
		store.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, uint64(i+1))))
	}

	limit := gossipproto.MaxPayloadSize(gossipproto.MinMaxMessageSize)
	heads := store.encodeAuthorHeadsLimited(namespace.ID(), limit, func(heads []byte) bool {
		msg, err := marshalSyncReport(namespace.ID(), heads)
		return err == nil && len(msg) <= limit
	})
	msg, err := marshalSyncReport(namespace.ID(), heads)
	if err != nil {
		t.Fatalf("marshal sync report: %v", err)
	}
	if len(msg) > limit {
		t.Fatalf("sync report size = %d, want <= %d", len(msg), limit)
	}
}

func TestLiveSyncConfinesBroadcastToNamespace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	shared := NewNamespaceSecret(repeat32(0xb2))
	other := NewNamespaceSecret(repeat32(0xb3))
	author := NewAuthor(repeat32(0xa1))
	sharedEntry := testSignedEntry(shared, author, "k", testRecord("one", 1, 1))
	otherEntry := testSignedEntry(other, author, "secret", testRecord("secret", 1, 1))

	blobStore, err := blobs.NewMemStore()
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	store := NewMemoryStore()
	a, aGossip, aRouter := newLiveSyncNode(t, ctx, store, blobStore)
	defer aRouter.Shutdown(ctx)
	_, bGossip, bRouter := newLiveSyncNode(t, ctx, NewMemoryStore(), blobStore)
	defer bRouter.Shutdown(ctx)

	aAddr := netaddr.NewEndpointAddr(a.ID()).WithIP(a.LocalAddr())
	live, err := StartLiveSync(ctx, a, aGossip, shared.ID(), store, LiveSyncOptions{})
	if err != nil {
		t.Fatalf("start live sync: %v", err)
	}
	defer live.Close()

	topic, err := bGossip.Subscribe(ctx, gossip.TopicID(shared.ID().Bytes()), []netaddr.EndpointAddr{aAddr})
	if err != nil {
		t.Fatalf("subscribe topic: %v", err)
	}
	defer topic.Close()
	if err := topic.Joined(ctx); err != nil {
		t.Fatalf("joined: %v", err)
	}

	received := make(chan liveOp)
	go func() {
		for ev, err := range topic.Events() {
			if err != nil || ev.Kind != gossip.Received {
				continue
			}
			var op liveOp
			if err := postcard.Unmarshal(ev.Content, &op); err != nil {
				continue
			}
			select {
			case received <- op:
			case <-ctx.Done():
				return
			}
		}
	}()

	// The other-namespace entry is published first, so a broadcaster that does
	// not confine itself sends it before the entry this topic is for.
	store.Put(otherEntry)
	store.Put(sharedEntry)

	for {
		select {
		case op := <-received:
			if op.Kind != liveOpPut {
				continue
			}
			if ns := op.Entry.Entry.Namespace(); ns != shared.ID() {
				t.Fatalf("topic peer received entry from namespace %s, want %s", ns, shared.ID())
			}
			return
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

// TestLiveSyncReceivedPutRejectsFutureTimestamp covers the gossip half of the
// remote insert path that TestProcessMessageRejectsFutureTimestamp covers for
// range reconciliation.
func TestLiveSyncReceivedPutRejectsFutureTimestamp(t *testing.T) {
	now := uint64(time.Now().UnixMicro())
	tests := []struct {
		name      string
		timestamp uint64
		want      int
	}{
		{"within bound", now + MaxTimestampFutureShift/2, 1},
		{"past bound", now + 2*MaxTimestampFutureShift, 0},
		{"max uint64", ^uint64(0), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := NewNamespaceSecret(repeat32(0xb2))
			author := NewAuthor(repeat32(0xa1))
			entry := testSignedEntry(namespace, author, "k", testRecord("k", 1, tt.timestamp))
			msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			store := NewMemoryStore()
			var l LiveSync
			l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{}, gossip.Event{
				Kind:    gossip.Received,
				Content: msg,
			})

			if got := store.Len(); got != tt.want {
				t.Fatalf("Len = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestLiveSyncDownloadsReconciledContent pins that live sync downloads the
// content of an entry that arrives by range reconciliation rather than by a
// gossip Put: b joins after a wrote the entry, so no gossip carries it.
func TestLiveSyncDownloadsReconciledContent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	content := []byte("content fetched after reconciliation")
	contentHash := blobs.NewHash(content)
	entry := testSignedEntry(namespace, author, "k", NewRecord(contentHash, uint64(len(content)), 1))

	aStore := NewMemoryStore()
	aBlobs, err := blobs.NewMemStore(content)
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	a, aGossip, aRouter := newLiveSyncNode(t, ctx, aStore, aBlobs)
	defer aRouter.Shutdown(ctx)
	aLive, err := StartLiveSync(ctx, a, aGossip, namespace.ID(), aStore, LiveSyncOptions{
		BlobStore: aBlobs,
	})
	if err != nil {
		t.Fatalf("start a live sync: %v", err)
	}
	defer aLive.Close()
	aStore.Put(entry)

	bStore := NewMemoryStore()
	bBlobs, err := blobs.NewMemStore()
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	b, bGossip, bRouter := newLiveSyncNode(t, ctx, bStore, bBlobs)
	defer bRouter.Shutdown(ctx)
	bEvents, cancelEvents := bStore.Subscribe()
	defer cancelEvents()

	aAddr := netaddr.NewEndpointAddr(a.ID()).WithIP(a.LocalAddr())
	bLive, err := StartLiveSync(ctx, b, bGossip, namespace.ID(), bStore, LiveSyncOptions{
		Bootstrap: []netaddr.EndpointAddr{aAddr},
		Resolver:  iroh.StaticLookupFromAddrs(aAddr),
		BlobStore: bBlobs,
	})
	if err != nil {
		t.Fatalf("start b live sync: %v", err)
	}
	defer bLive.Close()

	for {
		select {
		case ev, ok := <-bEvents:
			if !ok {
				t.Fatal("b store events closed")
			}
			if ev.Kind != StoreEventContentReady || ev.Hash != contentHash {
				continue
			}
			got, err := blobs.ReadBlob(ctx, bBlobs, contentHash)
			if err != nil {
				t.Fatalf("downloaded blob missing from b store: %v", err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("downloaded blob = %q, want %q", got, content)
			}
			return
		case <-ctx.Done():
			_, ok := bStore.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
			t.Fatalf("content never downloaded (entry synced: %v): %v", ok, ctx.Err())
		}
	}
}

func TestLiveSyncStoreEventQueuesDownload(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	other := NewNamespaceSecret(repeat32(0xb3))
	author := NewAuthor(repeat32(0xa1))
	hash := blobs.NewHash([]byte("content"))
	peer := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(0x01)).Public().EndpointID())
	tests := []struct {
		name   string
		ns     NamespaceSecret
		key    string
		kind   StoreEventKind
		from   key.EndpointID
		status ContentStatus
		want   bool
	}{
		{"remote complete", namespace, "k", StoreEventInsertRemote, peer.ID, ContentComplete, true},
		{"remote missing", namespace, "k", StoreEventInsertRemote, peer.ID, ContentMissing, false},
		{"remote incomplete", namespace, "k", StoreEventInsertRemote, peer.ID, ContentIncomplete, false},
		{"no peer", namespace, "k", StoreEventInsertRemote, key.EndpointID{}, ContentComplete, false},
		{"other namespace", other, "k", StoreEventInsertRemote, peer.ID, ContentComplete, false},
		{"policy excluded", namespace, "private/k", StoreEventInsertRemote, peer.ID, ContentComplete, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blobStore, err := blobs.NewMemStore()
			if err != nil {
				t.Fatalf("NewMemStore: %v", err)
			}
			l := LiveSync{downloads: make(chan liveDownload, 1)}
			opts := liveSyncOptions{LiveSyncOptions: LiveSyncOptions{
				BlobStore:      blobStore,
				Resolver:       iroh.StaticLookupFromAddrs(peer),
				DownloadPolicy: DownloadPolicy{ExcludePrefixes: []string{"private/"}},
			}}
			entry := testSignedEntry(tt.ns, author, tt.key, NewRecord(hash, 7, 1))
			l.handleStoreEvent(context.Background(), namespace.ID(), opts, StoreEvent{
				Kind:          tt.kind,
				Entry:         entry,
				From:          tt.from,
				ContentStatus: tt.status,
			})
			select {
			case req := <-l.downloads:
				if !tt.want {
					t.Fatalf("queued download %+v, want none", req)
				}
				if providers := req.pending.snapshot(); len(providers) != 1 || !providers[0].ID.Equal(peer.ID) {
					t.Fatalf("providers = %v, want [%s]", providers, peer.ID)
				}
			default:
				if tt.want {
					t.Fatal("download was not queued")
				}
			}
		})
	}
}
