package blobs

import (
	"context"
	"slices"
	"testing"
)

func TestFSStoreTagsPersist(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add([]byte("tagged"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.SetTag("keep", RawHash(hash)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}

	reopened, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen NewFSStore: %v", err)
	}
	value, ok, err := reopened.Tag("keep")
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if !ok || value != RawHash(hash) {
		t.Fatalf("Tag = %+v, %v, want %s", value, ok, hash)
	}
	tags, err := reopened.Tags()
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 1 || tags[0].Name != "keep" || tags[0].Value != RawHash(hash) {
		t.Fatalf("Tags = %+v", tags)
	}
}

func TestFSStoreGCSweepsUntaggedBlobs(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	keep, err := store.Add([]byte("keep"))
	if err != nil {
		t.Fatalf("Add keep: %v", err)
	}
	drop, err := store.Add([]byte("drop"))
	if err != nil {
		t.Fatalf("Add drop: %v", err)
	}
	if err := store.SetTag("keep", RawHash(keep)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	result, err := store.GC(context.Background())
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if result.Deleted != 1 {
		t.Fatalf("GC deleted %d blobs, want 1", result.Deleted)
	}
	if _, err := ReadBlob(context.Background(), store, keep); err != nil {
		t.Fatal("tagged blob was swept")
	}
	if _, err := ReadBlob(context.Background(), store, drop); err == nil {
		t.Fatal("untagged blob survived GC")
	}
}

func TestFSStoreGCWithEvents(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	keep, err := store.Add([]byte("keep"))
	if err != nil {
		t.Fatalf("Add keep: %v", err)
	}
	drop, err := store.Add([]byte("drop"))
	if err != nil {
		t.Fatalf("Add drop: %v", err)
	}
	if err := store.SetTag("keep", RawHash(keep)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	var events []GCEvent
	result, err := store.GCWithEvents(context.Background(), func(ev GCEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatalf("GCWithEvents: %v", err)
	}
	if result.Deleted != 1 {
		t.Fatalf("GCWithEvents deleted %d blobs, want 1", result.Deleted)
	}
	kinds := make([]GCEventKind, len(events))
	for i, ev := range events {
		kinds[i] = ev.Kind
	}
	want := []GCEventKind{GCEventMark, GCEventDelete, GCEventDone}
	if !slices.Equal(kinds, want) {
		t.Fatalf("event kinds = %v, want %v", kinds, want)
	}
	if events[0].Live != 1 {
		t.Fatalf("mark live = %d, want 1", events[0].Live)
	}
	if events[1].Hash != drop || events[1].Deleted != 1 {
		t.Fatalf("delete event = %+v, want drop hash and deleted=1", events[1])
	}
	if events[2].Deleted != 1 {
		t.Fatalf("done deleted = %d, want 1", events[2].Deleted)
	}
}

func TestFSStoreGCRechecksTagsBeforeDelete(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add([]byte("late tag"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	result, err := store.GCWithEvents(context.Background(), func(ev GCEvent) {
		if ev.Kind != GCEventMark {
			return
		}
		if err := store.SetTag("late", RawHash(hash)); err != nil {
			t.Fatalf("SetTag from GC callback: %v", err)
		}
	})
	if err != nil {
		t.Fatalf("GCWithEvents: %v", err)
	}
	if result.Deleted != 0 {
		t.Fatalf("GCWithEvents deleted %d blobs, want 0", result.Deleted)
	}
	if _, err := ReadBlob(context.Background(), store, hash); err != nil {
		t.Fatal("late-tagged blob was swept")
	}
}

func TestFSStoreTempTagProtectsBlob(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add([]byte("temporary"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	tag, err := store.NewTempTag(RawHash(hash))
	if err != nil {
		t.Fatalf("NewTempTag: %v", err)
	}
	if _, err := store.GC(context.Background()); err != nil {
		t.Fatalf("GC with temp tag: %v", err)
	}
	if _, err := ReadBlob(context.Background(), store, hash); err != nil {
		t.Fatal("temp-tagged blob was swept")
	}
	if err := tag.Close(); err != nil {
		t.Fatalf("Close temp tag: %v", err)
	}
	if _, err := store.GC(context.Background()); err != nil {
		t.Fatalf("GC after temp tag close: %v", err)
	}
	if _, err := ReadBlob(context.Background(), store, hash); err == nil {
		t.Fatal("blob survived after temp tag close")
	}
}

func TestFSStoreGCMarksHashSeqChildren(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	child, err := store.Add([]byte("child"))
	if err != nil {
		t.Fatalf("Add child: %v", err)
	}
	drop, err := store.Add([]byte("drop"))
	if err != nil {
		t.Fatalf("Add drop: %v", err)
	}
	seq := NewHashSequence([]Hash{child})
	root, err := store.Add(seq.Bytes())
	if err != nil {
		t.Fatalf("Add hash seq: %v", err)
	}
	if err := store.SetTag("collection", HashSeqHash(root)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	if _, err := store.GC(context.Background()); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := ReadBlob(context.Background(), store, root); err != nil {
		t.Fatal("hash seq root was swept")
	}
	if _, err := ReadBlob(context.Background(), store, child); err != nil {
		t.Fatal("hash seq child was swept")
	}
	if _, err := ReadBlob(context.Background(), store, drop); err == nil {
		t.Fatal("untagged blob survived GC")
	}
}

func TestFSStoreGCHashSeqAndRawSameHash(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	child, err := store.Add([]byte("child-of-dual-tagged-root"))
	if err != nil {
		t.Fatalf("Add child: %v", err)
	}
	seq := NewHashSequence([]Hash{child})
	root, err := store.Add(seq.Bytes())
	if err != nil {
		t.Fatalf("Add hash seq: %v", err)
	}
	// Tag the same root as both Raw and HashSeq; regardless of map iteration
	// order in gcRoots, HashSeq children must stay live (upstream iroh-blobs#317).
	for i := range 8 {
		name := "raw-" + string(rune('a'+i))
		if err := store.SetTag(name, RawHash(root)); err != nil {
			t.Fatalf("SetTag %s: %v", name, err)
		}
	}
	if err := store.SetTag("seq", HashSeqHash(root)); err != nil {
		t.Fatalf("SetTag seq: %v", err)
	}
	for range 16 {
		if _, err := store.GC(context.Background()); err != nil {
			t.Fatalf("GC: %v", err)
		}
		if _, err := ReadBlob(context.Background(), store, child); err != nil {
			t.Fatal("hash seq child was swept when root also had Raw tag")
		}
	}
}

func TestFSStoreGCRechecksLateHashSeqTagChildren(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	child, err := store.Add([]byte("late-seq-child"))
	if err != nil {
		t.Fatalf("Add child: %v", err)
	}
	seq := NewHashSequence([]Hash{child})
	root, err := store.Add(seq.Bytes())
	if err != nil {
		t.Fatalf("Add hash seq: %v", err)
	}
	// Tag the HashSeq only after the mark phase has already finished; both
	// root and child must survive the sweep (upstream iroh-blobs#240/#248).
	result, err := store.GCWithEvents(context.Background(), func(ev GCEvent) {
		if ev.Kind != GCEventMark {
			return
		}
		if err := store.SetTag("late-seq", HashSeqHash(root)); err != nil {
			t.Fatalf("SetTag late-seq: %v", err)
		}
	})
	if err != nil {
		t.Fatalf("GCWithEvents: %v", err)
	}
	if result.Deleted != 0 {
		t.Fatalf("GCWithEvents deleted %d blobs, want 0", result.Deleted)
	}
	if _, err := ReadBlob(context.Background(), store, root); err != nil {
		t.Fatal("late-tagged hash seq root was swept")
	}
	if _, err := ReadBlob(context.Background(), store, child); err != nil {
		t.Fatal("late-tagged hash seq child was swept")
	}
}

func TestParseHashInvalidNeverPanics(t *testing.T) {
	cases := []string{
		"",
		"0",
		"zz",
		"not-a-valid-hash",
		"0123456789abcdef",
		string(make([]byte, 64)),
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA====",
		"日本語テスト",
	}
	for _, tc := range cases {
		if _, err := ParseHash(tc); err == nil {
			t.Errorf("ParseHash(%q) unexpectedly succeeded", tc)
		}
	}
}
