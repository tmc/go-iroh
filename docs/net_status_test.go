package docs

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

// blockingStore is a blob store whose lookups wait until their context ends.
type blockingStore struct{}

func (blockingStore) Open(ctx context.Context, hash blobs.Hash) (blobs.Blob, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestSyncContentStatusHonorsContext pins that the default content status
// lookup runs under the sync's context, so a blob store that stalls cannot
// hold a sync past its cancellation.
func TestSyncContentStatusHonorsContext(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	id := NewRecordIdentifier(namespace.ID(), author.ID(), []byte("k"))
	data := []byte("data")
	entry := NewSignedEntry(NewEntry(id, NewRecord(blobs.NewHash(data), uint64(len(data)), 1)), namespace, author)

	store := NewMemoryStore()
	store.Put(entry)
	h := &Handler{Store: store, BlobStore: blockingStore{}, Config: DefaultSyncConfig()}
	initial := NewMemoryStore().InitialMessageInNamespace(namespace.ID())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.run(ctx, new(bytes.Buffer), key.EndpointID{}, namespace.ID(), initial, true)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sync did not return after its context was canceled")
	}
}
