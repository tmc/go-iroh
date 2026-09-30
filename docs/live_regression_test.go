package docs

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func newRegressionLive(t *testing.T, ctx context.Context, cancel context.CancelFunc, namespace NamespaceID) *LiveSync {
	t.Helper()
	n := irohtest.NewNet(t)
	topic, err := gossip.NewGossip(n.Peer().Endpoint).Subscribe(ctx, gossip.TopicID(namespace.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = topic.Close() })
	return &LiveSync{cancel: cancel, done: make(chan struct{}), topic: topic, downloads: make(chan liveDownload, liveDownloadQueueSize)}
}

func TestLiveSyncDownloadBurst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		namespace := NewNamespaceSecret(repeat32(0xb2))
		l := newRegressionLive(t, ctx, cancel, namespace.ID())
		provider := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(1)).Public().EndpointID())
		blobStore, err := blobs.NewMemStore()
		if err != nil {
			t.Fatal(err)
		}
		contents := make(map[blobs.Hash][]byte)
		for i := 0; i < 64; i++ {
			b := []byte(fmt.Sprintf("content %d", i))
			contents[blobs.NewHash(b)] = b
		}
		var fetched atomic.Int32
		opts := liveSyncOptions{LiveSyncOptions: LiveSyncOptions{BlobStore: blobStore, Bootstrap: []netaddr.EndpointAddr{provider}}, downloadBlob: func(ctx context.Context, providers []netaddr.EndpointAddr, hash blobs.Hash) error {
			_, err := blobStore.Add(contents[hash])
			if err == nil {
				fetched.Add(1)
			}
			return err
		}}
		for hash := range contents {
			l.queueDownload(ctx, opts, hash, []byte("k"), true, provider.ID)
		}
		go l.run(ctx, namespace.ID(), NewMemoryStore(), opts, make(chan StoreEvent))
		synctest.Wait()
		if got := fetched.Load(); got != int32(len(contents)) {
			t.Fatalf("downloaded %d of %d blobs", got, len(contents))
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLiveSyncRecoversStoreLag(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		namespace := NewNamespaceSecret(repeat32(0xb2))
		author := NewAuthor(repeat32(0xa1))
		store := NewMemoryStore()
		l := newRegressionLive(t, ctx, cancel, namespace.ID())
		provider := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(1)).Public().EndpointID())
		blobStore, err := blobs.NewMemStore()
		if err != nil {
			t.Fatal(err)
		}
		contents := make(map[blobs.Hash][]byte)
		for i := 0; i < 32; i++ {
			b := []byte(fmt.Sprintf("content %d", i))
			hash := blobs.NewHash(b)
			contents[hash] = b
			store.Put(testSignedEntry(namespace, author, fmt.Sprintf("k%03d", i), NewRecord(hash, uint64(len(b)), 1)))
		}
		var fetched atomic.Int32
		opts := liveSyncOptions{LiveSyncOptions: LiveSyncOptions{BlobStore: blobStore, Bootstrap: []netaddr.EndpointAddr{provider}}, downloadBlob: func(ctx context.Context, providers []netaddr.EndpointAddr, hash blobs.Hash) error {
			_, err := blobStore.Add(contents[hash])
			if err == nil {
				fetched.Add(1)
			}
			return err
		}}
		events := make(chan StoreEvent, 1)
		events <- StoreEvent{Kind: StoreEventLagged, Missed: 32}
		go l.run(ctx, namespace.ID(), store, opts, events)
		synctest.Wait()
		if got := fetched.Load(); got != int32(len(contents)) {
			t.Fatalf("recovered %d of %d downloads", got, len(contents))
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLiveSyncGossipProviderScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope gossip.DeliveryScope
		round uint16
		want  bool
	}{
		{"neighbors", gossip.DeliveryNeighbors, 0, true},
		{"origin", gossip.DeliverySwarm, 0, true},
		{"forwarded", gossip.DeliverySwarm, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			namespace := NewNamespaceSecret(repeat32(0xb2))
			entry := testSignedEntry(namespace, NewAuthor(repeat32(0xa1)), "k", testRecord("blob", 4, 1))
			msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
			if err != nil {
				t.Fatal(err)
			}
			addr := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(1)).Public().EndpointID())
			l := &LiveSync{downloads: make(chan liveDownload, 1)}
			store := NewMemoryStore()
			l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{LiveSyncOptions: LiveSyncOptions{Resolver: iroh.StaticLookupFromAddrs(addr)}}, gossip.Event{Content: msg, DeliveredFrom: addr.ID, Scope: tc.scope, Round: tc.round})
			if len(store.Entries()) != 1 {
				t.Fatal("metadata was not inserted")
			}
			if got := len(l.downloads) != 0; got != tc.want {
				t.Fatalf("queued download = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLiveSyncRejectsInvalidEmptyGossip(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	entry := testSignedEntry(namespace, NewAuthor(repeat32(0xa1)), "k", NewRecord(blobs.EmptyHash, 1, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	new(LiveSync).handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{}, gossip.Event{Content: msg})
	if len(store.Entries()) != 0 {
		t.Fatal("invalid empty record was inserted")
	}
}

func TestLiveSyncCoalescesOutgoingSync(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		addr := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(1)).Public().EndpointID())
		var calls atomic.Int32
		release := make(chan struct{})
		opts := liveSyncOptions{syncPeer: func(context.Context, netaddr.EndpointAddr) (SyncOutcome, error) {
			if calls.Add(1) == 1 {
				<-release
			}
			return SyncOutcome{}, nil
		}}
		l := new(LiveSync)
		store := NewMemoryStore()
		peers := []netaddr.EndpointAddr{addr}
		go l.syncPeers(ctx, NamespaceID{}, store, opts, peers)
		synctest.Wait()
		for i := 0; i < 20; i++ {
			l.syncPeers(ctx, NamespaceID{}, store, opts, peers)
		}
		if calls.Load() != 1 {
			t.Fatal("concurrent duplicate sync")
		}
		close(release)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("sync calls = %d, want one queued rerun", calls.Load())
		}
	})
}

func TestLiveSyncCloseWaitsForWorkers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		namespace := NewNamespaceSecret(repeat32(0xb2))
		l := newRegressionLive(t, ctx, cancel, namespace.ID())
		addr := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(1)).Public().EndpointID())
		release := make(chan struct{})
		var callback atomic.Bool
		opts := liveSyncOptions{LiveSyncOptions: LiveSyncOptions{Bootstrap: []netaddr.EndpointAddr{addr}, OnSync: func(SyncResult) { callback.Store(true) }}, syncPeer: func(ctx context.Context, addr netaddr.EndpointAddr) (SyncOutcome, error) {
			<-ctx.Done()
			<-release
			return SyncOutcome{}, ctx.Err()
		}}
		go l.run(ctx, namespace.ID(), NewMemoryStore(), opts, make(chan StoreEvent))
		synctest.Wait()
		closed := make(chan error, 1)
		go func() { closed <- l.Close() }()
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("Close returned with a worker running")
		default:
		}
		close(release)
		synctest.Wait()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if !callback.Load() {
			t.Fatal("Close did not wait for OnSync")
		}
	})
}

func TestLiveSyncLagReportAndContentReadyScope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	namespace := NewNamespaceSecret(repeat32(0xb2))
	store := NewMemoryStore()
	entry := testSignedEntry(namespace, NewAuthor(repeat32(0xa1)), "k", testRecord("missing content", 15, 1))
	store.Put(entry)
	blobStore, err := blobs.NewMemStore()
	if err != nil {
		t.Fatal(err)
	}
	a, aGossip, aRouter := newLiveSyncNode(t, ctx, store, blobStore)
	defer aRouter.Shutdown(ctx)
	_, bGossip, bRouter := newLiveSyncNode(t, ctx, NewMemoryStore(), blobStore)
	defer bRouter.Shutdown(ctx)
	topicID := gossip.TopicID(namespace.ID().Bytes())
	aTopic, err := aGossip.Subscribe(ctx, topicID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer aTopic.Close()
	bTopic, err := bGossip.Subscribe(ctx, topicID, []netaddr.EndpointAddr{netaddr.NewEndpointAddr(a.ID()).WithIP(a.LocalAddr())})
	if err != nil {
		t.Fatal(err)
	}
	defer bTopic.Close()
	if err := bTopic.Joined(ctx); err != nil {
		t.Fatal(err)
	}
	l := &LiveSync{topic: aTopic}
	l.recoverStore(ctx, namespace.ID(), store, liveSyncOptions{LiveSyncOptions: LiveSyncOptions{BlobStore: blobStore}})
	barrier := []byte("recovery complete")
	if err := aTopic.BroadcastNeighbors(ctx, barrier); err != nil {
		t.Fatal(err)
	}
	var report, put, ready, recovered bool
	for ev, err := range bTopic.Events() {
		if err != nil {
			t.Fatal(err)
		}
		if ev.Kind != gossip.Received {
			continue
		}
		if bytes.Equal(ev.Content, barrier) {
			if !report || !put {
				t.Fatal("lag recovery did not publish local metadata and sync heads")
			}
			recovered = true
			l.broadcastContentReady(ctx, entry.Entry.ContentHash())
			continue
		}
		var op liveOp
		if err := postcard.Unmarshal(ev.Content, &op); err != nil {
			t.Fatal(err)
		}
		switch op.Kind {
		case liveOpSyncReport:
			if op.Report.Namespace != namespace.ID() || !NewMemoryStore().hasNewsForUs(namespace.ID(), op.Report.Heads) {
				t.Fatal("lag recovery report did not advertise stored entries")
			}
			report = true
		case liveOpContentReady:
			if !recovered {
				t.Fatal("lag recovery claimed missing content was ready")
			}
			if ev.Scope != gossip.DeliveryNeighbors {
				t.Fatalf("ContentReady scope = %v, want neighbors", ev.Scope)
			}
			ready = true
		case liveOpPut:
			if !op.Entry.Equal(entry) {
				t.Fatal("lag recovery published different metadata")
			}
			put = true
		}
		if report && ready {
			return
		}
	}
	t.Fatal("topic ended before recovery report and content-ready announcement")
}

func TestLiveSyncRecoversIncomingProvider(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		namespace := NewNamespaceSecret(repeat32(0xb2))
		provider := key.NewSecretKey(repeat32(1)).Public().EndpointID()
		content := []byte("incoming provider content")
		hash := blobs.NewHash(content)
		entry := testSignedEntry(namespace, NewAuthor(repeat32(0xa1)), "k", NewRecord(hash, uint64(len(content)), 1))
		store := NewMemoryStore()
		store.PutWithOrigin(entry, InsertOrigin{Kind: InsertOriginRemote, From: provider, ContentStatus: ContentComplete})
		blobStore, err := blobs.NewMemStore()
		if err != nil {
			t.Fatal(err)
		}
		l := newRegressionLive(t, ctx, cancel, namespace.ID())
		var fetched atomic.Bool
		opts := liveSyncOptions{LiveSyncOptions: LiveSyncOptions{BlobStore: blobStore}, downloadBlob: func(ctx context.Context, providers []netaddr.EndpointAddr, got blobs.Hash) error {
			if got != hash || len(providers) != 1 || providers[0].ID != provider {
				t.Error("lost incoming provider identity")
			}
			_, err := blobStore.Add(content)
			fetched.Store(err == nil)
			return err
		}}
		events := make(chan StoreEvent, 1)
		events <- StoreEvent{Kind: StoreEventLagged, Missed: 1}
		go l.run(ctx, namespace.ID(), store, opts, events)
		synctest.Wait()
		if !fetched.Load() {
			t.Fatal("lost event did not recover incoming provider")
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLiveSyncFailedSaveDoesNotQueueContent(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	entry := testSignedEntry(namespace, NewAuthor(repeat32(0xa1)), "k", testRecord("content", 7, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryStore()
	store.persistPath = filepath.Join(t.TempDir(), "missing", "docs.store")
	addr := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(1)).Public().EndpointID())
	l := &LiveSync{downloads: make(chan liveDownload, 1)}
	l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{LiveSyncOptions: LiveSyncOptions{Bootstrap: []netaddr.EndpointAddr{addr}}}, gossip.Event{Content: msg, DeliveredFrom: addr.ID, Scope: gossip.DeliveryNeighbors})
	if store.PersistError() == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	if len(l.downloads) != 0 {
		t.Fatal("failed durable insertion queued content")
	}
	// No topic is installed: recovery must stop before publishing the failed snapshot.
	l.recoverStore(context.Background(), namespace.ID(), store, liveSyncOptions{})
}

func TestLiveSyncRerunUsesUpdatedAddress(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		first := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(1)).Public().EndpointID()).WithIP(netip.MustParseAddrPort("127.0.0.1:1001"))
		updated := netaddr.NewEndpointAddr(first.ID).WithIP(netip.MustParseAddrPort("127.0.0.1:1002"))
		release := make(chan struct{})
		called := make(chan netaddr.EndpointAddr, 2)
		opts := liveSyncOptions{syncPeer: func(_ context.Context, addr netaddr.EndpointAddr) (SyncOutcome, error) {
			called <- addr
			if len(called) == 1 {
				<-release
			}
			return SyncOutcome{}, nil
		}}
		l := new(LiveSync)
		store := NewMemoryStore()
		go l.syncPeers(ctx, NamespaceID{}, store, opts, []netaddr.EndpointAddr{first})
		synctest.Wait()
		l.syncPeers(ctx, NamespaceID{}, store, opts, []netaddr.EndpointAddr{updated})
		close(release)
		synctest.Wait()
		<-called
		got := <-called
		if !reflect.DeepEqual(got, updated) {
			t.Fatalf("rerun address = %v, want %v", got, updated)
		}
	})
}
