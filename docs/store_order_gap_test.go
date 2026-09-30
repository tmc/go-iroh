//go:build gaptests

package docs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// These tests propose a stronger boundary than the currently documented
// memory-first insertion contract: the persistence gate also owns mutation,
// and recovery must not announce an insertion waiting for its first save.
// Holding persistMu makes the unsaved interval deterministic; no storage
// failure or scheduler-dependent event order is needed.
func TestFileStoreGapMutationBeforeSaveGate(t *testing.T) {
	store, entry, finish := blockedFileStoreInsert(t)
	defer finish()
	if store.Len() != 0 {
		t.Fatal("insert became visible while another save owns the persistence gate")
	}
	if _, ok := store.GetExact(entry.Entry.Namespace(), entry.Entry.Author(), entry.Entry.Key(), false); ok {
		t.Fatal("GetExact exposed insertion before its persistence turn")
	}
}

func TestFileStoreGapRecoveryAnnouncesPendingInsert(t *testing.T) {
	store, entry, finish := blockedFileStoreInsert(t)
	defer finish()
	events := store.snapshotEvents(entry.Entry.Namespace())
	if len(events) != 0 {
		t.Fatalf("recovery announced %d pending insertion(s) while persistence was blocked", len(events))
	}
}

// blockedFileStoreInsert returns with the insertion either visible in memory
// or still waiting at the held persistence gate. The caller owns the gate until
// finish; Put cannot save or publish an insertion event before then.
func blockedFileStoreInsert(t *testing.T) (*MemoryStore, SignedEntry, func()) {
	t.Helper()
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store, err := NewFileStore(filepath.Join(t.TempDir(), "docs.store"))
	if err != nil {
		t.Fatal(err)
	}
	entry := testSignedEntry(namespace, author, "key", testRecord("value", 5, 1))
	store.persistMu.Lock()
	done := make(chan InsertOutcome, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		done <- store.Put(entry)
	}()
	<-started
	// The first observed mutation proves the gap. If mutations are gated, a
	// bounded wait ends with an empty store and the stronger contract passes.
	deadline := time.NewTimer(100 * time.Millisecond)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
wait:
	for {
		if store.Len() != 0 {
			break
		}
		select {
		case <-poll.C:
		case <-deadline.C:
			break wait
		}
	}
	return store, entry, func() {
		store.persistMu.Unlock()
		select {
		case outcome := <-done:
			if outcome.Err() != nil {
				t.Errorf("unblocked Put: %v", outcome.Err())
			}
		case <-time.After(5 * time.Second):
			t.Error("Put did not finish after releasing persistence gate")
		}
	}
}

// Recovery currently publishes its newly allocated sequence before the insert
// event allocated earlier in the same Put. This deterministic ordering test
// assumes Sequence is monotonic within a subscriber stream.
func TestFileStoreGapRecoverySequenceOrder(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	dir := filepath.Join(t.TempDir(), "store")
	store, err := NewFileStore(filepath.Join(dir, "docs.store"))
	if err != nil {
		t.Fatal(err)
	}
	events, cancel := store.Subscribe()
	defer cancel()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	first := testSignedEntry(namespace, author, "first", testRecord("first", 5, 1))
	if outcome := store.Put(first); outcome.Err() == nil {
		t.Fatal("failed save returned nil error")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	second := testSignedEntry(namespace, author, "second", testRecord("second", 6, 2))
	if outcome := store.Put(second); outcome.Err() != nil {
		t.Fatal(outcome.Err())
	}
	read := func() StoreEvent {
		t.Helper()
		select {
		case event := <-events:
			return event
		case <-time.After(time.Second):
			t.Fatal("missing recovery/insert event")
			return StoreEvent{}
		}
	}
	a, b := read(), read()
	if a.Sequence >= b.Sequence {
		t.Fatalf("subscriber sequences decreased: %d (%v) then %d (%v)", a.Sequence, a.Kind, b.Sequence, b.Kind)
	}
}
