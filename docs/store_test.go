package docs

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

func TestMemoryStorePut(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()

	first := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	if got := store.Put(first); !got.Inserted() || got.Removed() != 0 {
		t.Fatalf("Put(first) = inserted %v removed %d, want true 0", got.Inserted(), got.Removed())
	}
	older := testSignedEntry(namespace, author, "k", testRecord("old", 1, 0))
	if got := store.Put(older); got.Inserted() || got.Removed() != 0 {
		t.Fatalf("Put(older) = inserted %v removed %d, want false 0", got.Inserted(), got.Removed())
	}
	newer := testSignedEntry(namespace, author, "k", testRecord("two", 1, 2))
	if got := store.Put(newer); !got.Inserted() || got.Removed() != 1 {
		t.Fatalf("Put(newer) = inserted %v removed %d, want true 1", got.Inserted(), got.Removed())
	}
	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
	got, ok := store.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok {
		t.Fatal("GetExact missing inserted entry")
	}
	if !got.Equal(newer) {
		t.Fatal("GetExact returned stale entry")
	}
}

func TestMemoryStorePrefixDeletion(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	other := NewAuthor(repeat32(0xc3))
	store := NewMemoryStore()

	store.Put(testSignedEntry(namespace, author, "dir/a", testRecord("a", 1, 1)))
	store.Put(testSignedEntry(namespace, author, "dir/b", testRecord("b", 1, 1)))
	store.Put(testSignedEntry(namespace, author, "other", testRecord("other", 1, 1)))
	store.Put(testSignedEntry(namespace, other, "dir/a", testRecord("other-author", 1, 1)))

	tombstone := testSignedEntry(namespace, author, "dir", EmptyRecord(2))
	if got := store.Put(tombstone); !got.Inserted() || got.Removed() != 2 {
		t.Fatalf("Put(tombstone) = inserted %v removed %d, want true 2", got.Inserted(), got.Removed())
	}
	if store.Len() != 3 {
		t.Fatalf("Len = %d, want 3", store.Len())
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("dir"), false); ok {
		t.Fatal("GetExact returned tombstone without includeEmpty")
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("dir"), true); !ok {
		t.Fatal("GetExact missing tombstone with includeEmpty")
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("dir/a"), true); ok {
		t.Fatal("GetExact returned removed child")
	}
	if _, ok := store.GetExact(namespace.ID(), other.ID(), []byte("dir/a"), false); !ok {
		t.Fatal("prefix delete removed another author's entry")
	}
}

func TestMemoryStoreParentBlocksChild(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()

	parent := testSignedEntry(namespace, author, "dir", EmptyRecord(2))
	if got := store.Put(parent); !got.Inserted() {
		t.Fatal("Put(parent) was not inserted")
	}
	child := testSignedEntry(namespace, author, "dir/a", testRecord("a", 1, 1))
	if got := store.Put(child); got.Inserted() {
		t.Fatal("older child inserted below newer parent")
	}
	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
}

func TestMemoryStoreWatchInsert(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	events, cancel := store.Subscribe()
	defer cancel()

	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	store.Put(entry)
	event := readStoreEvent(t, events)
	if event.Kind != StoreEventInsertLocal || event.Sequence != 1 || !event.Entry.Equal(entry) || event.Removed != 0 {
		t.Fatalf("event = %#v, want sequence 1 inserted entry", event)
	}
}

func TestMemoryStoreWatchSkipsStaleInsert(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	newer := testSignedEntry(namespace, author, "k", testRecord("new", 1, 2))
	older := testSignedEntry(namespace, author, "k", testRecord("old", 1, 1))
	store.Put(newer)

	events, cancel := store.Subscribe()
	defer cancel()
	store.Put(older)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	select {
	case event := <-events:
		t.Fatalf("event after stale insert = %#v, want none", event)
	case <-ctx.Done():
	}
}

func TestMemoryStoreSubscribeDoesNotReplay(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	store.Put(entry)

	events, cancel := store.Subscribe()
	defer cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	select {
	case event := <-events:
		t.Fatalf("late subscriber replayed %#v, want none", event)
	case <-ctx.Done():
	}
}

func TestMemoryStorePutWithOrigin(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	events, cancel := store.Subscribe()
	defer cancel()

	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	origin := InsertOrigin{
		Kind:          InsertOriginRemote,
		From:          sk.Public().EndpointID(),
		ContentStatus: ContentMissing,
	}
	store.PutWithOrigin(entry, origin)

	event := readStoreEvent(t, events)
	if event.Kind != StoreEventInsertRemote || !event.From.Equal(origin.From) || event.ContentStatus != ContentMissing {
		t.Fatalf("event = %#v, want remote origin", event)
	}
}

func TestMemoryStoreSubscribeLagged(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	events, cancel := store.Subscribe()
	defer cancel()

	for i := 0; i < storeBroadcastCapacity*4; i++ {
		store.Put(testSignedEntry(namespace, author, string(rune('a'+i)), testRecord("one", 1, uint64(i+1))))
	}

	for i := 0; i < storeBroadcastCapacity*4; i++ {
		event := readStoreEvent(t, events)
		if event.Kind == StoreEventLagged {
			if event.Missed == 0 {
				t.Fatal("lagged event missed 0")
			}
			return
		}
	}
	t.Fatal("subscriber did not receive lagged event")
}

func readStoreEvent(t *testing.T, events <-chan StoreEvent) StoreEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case event, ok := <-events:
		if !ok {
			t.Fatal("events channel closed")
		}
		return event
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return StoreEvent{}
}

func testSignedEntry(namespace NamespaceSecret, author Author, key string, record Record) SignedEntry {
	id := NewRecordIdentifier(namespace.ID(), author.ID(), []byte(key))
	return NewSignedEntry(NewEntry(id, record), namespace, author)
}

func testRecord(seed string, length, timestamp uint64) Record {
	return NewRecord(blobs.NewHash([]byte(seed)), length, timestamp)
}

// TestMemoryStorePrefixShadowing pins the documented surprise: a plain write to
// a key that is a prefix of an existing key from the same author deletes the
// longer entry, so the two cannot coexist. TestMemoryStorePrefixDeletion covers
// the deliberate tombstone use of the same rule; this covers the accident.
func TestMemoryStorePrefixShadowing(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()

	store.Put(testSignedEntry(namespace, author, "menu/tea", testRecord("tea", 1, 1)))
	got := store.Put(testSignedEntry(namespace, author, "menu", testRecord("menu", 1, 2)))
	if !got.Inserted() || got.Removed() != 1 {
		t.Fatalf("Put(menu) = inserted %v removed %d, want true 1", got.Inserted(), got.Removed())
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("menu/tea"), false); ok {
		t.Fatal("menu/tea survived a write to menu")
	}

	// A trailing separator does not avoid it: "menu/" is still a prefix.
	store.Put(testSignedEntry(namespace, author, "menu/tea", testRecord("tea", 1, 3)))
	if got := store.Put(testSignedEntry(namespace, author, "menu/", testRecord("menu", 1, 4))); got.Removed() != 1 {
		t.Fatalf("Put(menu/) removed %d, want 1", got.Removed())
	}

	// The write is dropped outright when the ancestor is the newer entry.
	if got := store.Put(testSignedEntry(namespace, author, "menu/coffee", testRecord("coffee", 1, 2))); got.Inserted() {
		t.Fatal("insert under a newer ancestor was accepted")
	}
}
