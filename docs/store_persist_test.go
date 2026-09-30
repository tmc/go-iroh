package docs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreSnapshotRoundTrip(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	entries := []SignedEntry{
		testSignedEntry(namespace, author, "b", testRecord("b", 1, 2)),
		testSignedEntry(namespace, author, "a", testRecord("a", 1, 1)),
		testSignedEntry(namespace, author, "dir", EmptyRecord(3)),
	}
	for _, entry := range entries {
		store.Put(entry)
	}

	var buf bytes.Buffer
	n, err := store.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("WriteTo bytes = %d, want %d", n, buf.Len())
	}
	var again bytes.Buffer
	if _, err := store.WriteTo(&again); err != nil {
		t.Fatalf("second WriteTo: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), again.Bytes()) {
		t.Fatal("WriteTo is not deterministic")
	}

	loaded := NewMemoryStore()
	rn, err := loaded.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if rn != int64(buf.Len()) {
		t.Fatalf("ReadFrom bytes = %d, want %d", rn, buf.Len())
	}
	got, want := loaded.Entries(), store.Entries()
	if len(got) != len(want) {
		t.Fatalf("len(loaded) = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if !got[i].Equal(want[i]) {
			t.Fatalf("entry %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestMemoryStoreSnapshotMergesByInsertRules(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	old := testSignedEntry(namespace, author, "k", testRecord("old", 1, 1))
	newer := testSignedEntry(namespace, author, "k", testRecord("new", 1, 2))

	src := NewMemoryStore()
	src.Put(old)
	var buf bytes.Buffer
	if _, err := src.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	dst := NewMemoryStore()
	dst.Put(newer)
	if _, err := dst.ReadFrom(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got, ok := dst.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok || !got.Equal(newer) {
		t.Fatal("ReadFrom replaced newer entry with stale snapshot entry")
	}
}

func TestMemoryStoreSnapshotReadDoesNotNotify(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	src := NewMemoryStore()
	src.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, 1)))

	var buf bytes.Buffer
	if _, err := src.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	dst := NewMemoryStore()
	events, cancel := dst.Subscribe()
	defer cancel()
	if _, err := dst.ReadFrom(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	select {
	case event := <-events:
		t.Fatalf("ReadFrom emitted event %#v", event)
	case <-ctx.Done():
	}
}

func TestMemoryStoreFileRoundTrip(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	store.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, 1)))

	path := filepath.Join(t.TempDir(), "docs.store")
	if err := store.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	loaded, err := LoadMemoryStoreFile(path)
	if err != nil {
		t.Fatalf("LoadMemoryStoreFile: %v", err)
	}
	got, ok := loaded.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok {
		t.Fatal("loaded entry missing")
	}
	if want := store.Entries()[0]; !got.Equal(want) {
		t.Fatalf("loaded entry = %#v, want %#v", got, want)
	}
}

func TestFileStorePersistsInsert(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	path := filepath.Join(t.TempDir(), "docs.store")

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	if outcome := store.Put(entry); !outcome.Inserted() {
		t.Fatal("Put did not insert")
	}
	if err := store.PersistError(); err != nil {
		t.Fatalf("PersistError: %v", err)
	}

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen NewFileStore: %v", err)
	}
	got, ok := reopened.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok {
		t.Fatal("reopened entry missing")
	}
	if !got.Equal(entry) {
		t.Fatalf("reopened entry = %#v, want %#v", got, entry)
	}
}

func TestMemoryStoreSnapshotErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "bad magic", data: []byte("not a store")},
		{name: "truncated count", data: storeSnapshotMagic},
		{name: "too many entries", data: append(append([]byte(nil), storeSnapshotMagic...), 0xc1, 0x84, 0x3d)},
		{name: "oversized entry", data: append(append([]byte(nil), storeSnapshotMagic...), 1, 0xff, 0xff, 0xff, 0xff, 0x0f)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewMemoryStore().ReadFrom(bytes.NewReader(tt.data)); err == nil {
				t.Fatal("ReadFrom succeeded")
			}
		})
	}
}

func TestMemoryStoreSnapshotWriteError(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	store.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, 1)))

	_, err := store.WriteTo(errorWriter{})
	if err == nil {
		t.Fatal("WriteTo succeeded")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestFileStoreConcurrentInserts(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	path := filepath.Join(t.TempDir(), "docs.store")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	const count = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			entry := testSignedEntry(namespace, author, fmt.Sprintf("key/%03d", i), testRecord("value", 5, uint64(i+1)))
			outcome := store.Put(entry)
			if !outcome.Inserted() || outcome.Err() != nil {
				t.Errorf("Put(%d): inserted=%v err=%v", i, outcome.Inserted(), outcome.Err())
			}
		}(i)
	}
	close(start)
	wg.Wait()
	loaded, err := LoadMemoryStoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Len(); got != count {
		t.Fatalf("persisted entries = %d, want %d", got, count)
	}
}

func TestFileStoreInsertPersistenceError(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	dir := filepath.Join(t.TempDir(), "store")
	path := filepath.Join(dir, "docs.store")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	events, cancel := store.Subscribe()
	defer cancel()
	entry := testSignedEntry(namespace, author, "key", testRecord("value", 5, 1))
	outcome := store.Put(entry)
	if !outcome.Inserted() || outcome.Err() == nil {
		t.Fatalf("Put: inserted=%v err=%v", outcome.Inserted(), outcome.Err())
	}
	select {
	case ev := <-events:
		t.Fatalf("failed save emitted event: %#v", ev)
	case <-time.After(10 * time.Millisecond):
	}
	if store.Len() != 1 {
		t.Fatal("failed save lost in-memory insertion")
	}
	if !errors.Is(store.PersistError(), outcome.Err()) {
		t.Fatal("PersistError does not match insertion error")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	outcome = store.Put(testSignedEntry(namespace, author, "other", testRecord("other", 5, 2)))
	if outcome.Err() != nil {
		t.Fatal(outcome.Err())
	}
	if err := store.PersistError(); err != nil {
		t.Fatalf("successful save retained error: %v", err)
	}
	loaded, err := LoadMemoryStoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Len() != 2 {
		t.Fatal("successful save did not include earlier memory insertion")
	}
}

func TestFileStoreProcessMessagePersistenceError(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	dir := filepath.Join(t.TempDir(), "store")
	store, err := NewFileStore(filepath.Join(dir, "docs.store"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	entry := testSignedEntry(namespace, author, "key", testRecord("value", 5, 1))
	message := Message{Parts: []MessagePart{{Kind: MessagePartRangeItem, RangeItem: RangeItem{Values: []RangeValue{{Entry: entry, Status: ContentComplete}}, HaveLocal: true}}}}
	called := false
	_, more, err := store.processMessage(inNamespace(namespace.ID()), DefaultSyncConfig(), message, nil, func(SignedEntry, ContentStatus) { called = true }, nil, namespace.ID().EndpointID())
	if err == nil || more {
		t.Fatalf("processMessage: more=%v err=%v", more, err)
	}
	if called {
		t.Fatal("failed save reported successful insertion callback")
	}
}

func TestFileStoreRetryAndRecovery(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	peer := NewAuthor(repeat32(0xa2)).ID().EndpointID()
	dir := filepath.Join(t.TempDir(), "store")
	path := filepath.Join(dir, "docs.store")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := store.Subscribe()
	defer cancel()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	entry := testSignedEntry(namespace, author, "key", testRecord("value", 5, 1))
	origin := InsertOrigin{Kind: InsertOriginRemote, From: peer, ContentStatus: ContentComplete}
	if outcome := store.PutWithOrigin(entry, origin); outcome.Err() == nil {
		t.Fatal("failed save returned nil error")
	}
	if outcome := store.PutWithOrigin(entry, origin); outcome.Inserted() || outcome.Err() == nil {
		t.Fatalf("duplicate failed save: inserted=%v err=%v", outcome.Inserted(), outcome.Err())
	}
	if _, more, err := store.processMessage(inNamespace(namespace.ID()), DefaultSyncConfig(), store.InitialMessageInNamespace(namespace.ID()), nil, nil, nil, peer); err == nil || more {
		t.Fatalf("matching fingerprint after failed save: more=%v err=%v", more, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveFile(path); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistError(); err != nil {
		t.Fatalf("repair retained error: %v", err)
	}
	select {
	case event := <-events:
		if event.Kind != StoreEventLagged {
			t.Fatalf("recovery event = %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("repair did not signal recovery")
	}
	loaded, err := LoadMemoryStoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Len() != 1 {
		t.Fatal("repair did not persist pending entry")
	}
	if _, _, err := store.processMessage(inNamespace(namespace.ID()), DefaultSyncConfig(), store.InitialMessageInNamespace(namespace.ID()), nil, nil, nil, peer); err != nil {
		t.Fatalf("matching fingerprints after repair: %v", err)
	}
}

func TestFileStoreDuplicateRetriesSave(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	dir := filepath.Join(t.TempDir(), "store")
	path := filepath.Join(dir, "docs.store")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	entry := testSignedEntry(namespace, author, "key", testRecord("value", 5, 1))
	if outcome := store.Put(entry); outcome.Err() == nil {
		t.Fatal("failed save returned nil error")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	outcome := store.Put(entry)
	if outcome.Inserted() || outcome.Err() != nil {
		t.Fatalf("duplicate repair: inserted=%v err=%v", outcome.Inserted(), outcome.Err())
	}
	loaded, err := LoadMemoryStoreFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Len() != 1 {
		t.Fatal("duplicate retry did not persist entry")
	}
}
