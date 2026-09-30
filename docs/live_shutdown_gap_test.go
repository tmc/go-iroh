//go:build gaptests

package docs

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// This characterizes the ownership boundary of the low-level API. LiveSync
// owns its outgoing workers, while Handler owns incoming sessions under the
// router's context. Disabling admission and closing LiveSync does not revoke
// an already admitted incoming session. A managed namespace API would need
// to share that session's cancellation with the namespace lifetime.
func TestLiveSyncCloseLeavesAdmittedIncomingSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	secret := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	store.Put(testSignedEntry(secret, author, "server", testRecord("data", 4, 1)))
	var active atomic.Bool
	active.Store(true)
	handler := Handler{
		Store: store,
		Allow: func(namespace NamespaceID, _ key.EndpointID) bool {
			return active.Load() && namespace == secret.ID()
		},
	}
	finished := make(chan error, 1)
	server := newSyncClient(t, ctx)
	g := gossip.NewGossip(server)
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
		ALPN: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
			err := handler.Accept(ctx, conn)
			finished <- err
			return err
		}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { router.Shutdown(context.Background()) })
	live, err := StartLiveSync(ctx, server, g, secret.ID(), store, LiveSyncOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { live.Close() })

	client := newSyncClient(t, ctx)
	conn, err := client.Connect(ctx, syncAddr(server), ALPN)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := stream.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeSyncFrame(stream, syncWireMessage{
		Kind: syncMessageInit, Namespace: secret.ID(),
		Message: NewMemoryStore().InitialMessageInNamespace(secret.ID()),
	}); err != nil {
		t.Fatal(err)
	}
	// The reply proves admission happened before the namespace was stopped;
	// the nonempty server store keeps reconciliation awaiting our response.
	if reply, err := readSyncFrame(stream); err != nil {
		t.Fatal(err)
	} else if reply.Kind != syncMessageSync || reply.Message.ValueCount() == 0 {
		t.Fatalf("initial reply = %+v, want sync containing server entry", reply)
	}

	active.Store(false)
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	if handler.Allow(secret.ID(), client.ID()) {
		t.Fatal("namespace still permits new incoming sessions")
	}
	entry := testSignedEntry(secret, author, "after-close", testRecord("later", 5, 2))
	if err := writeSyncFrame(stream, syncWireMessage{
		Kind: syncMessageSync,
		Message: Message{Parts: []MessagePart{{
			Kind: MessagePartRangeItem,
			RangeItem: RangeItem{
				HaveLocal: true,
				Values:    []RangeValue{{Entry: entry, Status: ContentMissing}},
			},
		}}},
	}); err != nil {
		t.Fatalf("already admitted session stopped with LiveSync: %v", err)
	}
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("already admitted session failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	got, ok := store.GetExact(secret.ID(), author.ID(), []byte("after-close"), false)
	if !ok || !got.Equal(entry) {
		t.Fatal("already admitted session did not insert its post-Close entry")
	}
}
