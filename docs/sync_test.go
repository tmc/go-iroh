package docs

import (
	"testing"
	"time"
)

func TestProcessMessageStoresIncomingRangeItem(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("k", 1, 1))
	store := NewMemoryStore()
	var inserted []SignedEntry
	events, cancel := store.Subscribe()
	defer cancel()

	resp, ok := store.ProcessMessage(DefaultSyncConfig(), Message{Parts: []MessagePart{{
		Kind: MessagePartRangeItem,
		RangeItem: RangeItem{
			Range:     NewRange(entry.Entry.ID, entry.Entry.ID),
			Values:    []RangeValue{{Entry: entry, Status: ContentComplete}},
			HaveLocal: true,
		},
	}}}, nil, func(entry SignedEntry, status ContentStatus) {
		inserted = append(inserted, entry)
	}, nil)
	if ok {
		t.Fatalf("ProcessMessage returned response %#v, want none", resp)
	}
	if store.Len() != 1 || len(inserted) != 1 || !inserted[0].Equal(entry) {
		t.Fatalf("inserted len/store = %d/%d, want 1/1", len(inserted), store.Len())
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("k"), false); !ok {
		t.Fatal("inserted entry missing")
	}
	event := readStoreEvent(t, events)
	if event.Kind != StoreEventInsertRemote || event.ContentStatus != ContentComplete || !event.Entry.Equal(entry) {
		t.Fatalf("store event = %#v, want remote insert", event)
	}
}

func TestProcessMessageRejectsInvalidIncomingEntry(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("k", 1, 1))
	store := NewMemoryStore()

	resp, ok := store.ProcessMessage(DefaultSyncConfig(), Message{Parts: []MessagePart{{
		Kind: MessagePartRangeItem,
		RangeItem: RangeItem{
			Range:     NewRange(entry.Entry.ID, entry.Entry.ID),
			Values:    []RangeValue{{Entry: entry, Status: ContentComplete}},
			HaveLocal: true,
		},
	}}}, func(SignedEntry, ContentStatus) bool {
		return false
	}, func(SignedEntry, ContentStatus) {
		t.Fatal("onInsert called for rejected entry")
	}, nil)
	if ok {
		t.Fatalf("ProcessMessage returned response %#v, want none", resp)
	}
	if store.Len() != 0 {
		t.Fatalf("Len = %d, want 0", store.Len())
	}
}

func TestProcessMessageRangeItemReturnsLocalDiff(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	local := testSignedEntry(namespace, author, "k", testRecord("new", 1, 2))
	remote := testSignedEntry(namespace, author, "k", testRecord("old", 1, 1))
	store := NewMemoryStore()
	store.Put(local)

	resp, ok := store.ProcessMessage(DefaultSyncConfig(), Message{Parts: []MessagePart{{
		Kind: MessagePartRangeItem,
		RangeItem: RangeItem{
			Range:     NewRange(local.Entry.ID, local.Entry.ID),
			Values:    []RangeValue{{Entry: remote, Status: ContentComplete}},
			HaveLocal: false,
		},
	}}}, nil, nil, func(SignedEntry) ContentStatus { return ContentMissing })
	if !ok {
		t.Fatal("ProcessMessage returned no response")
	}
	if len(resp.Parts) != 1 || resp.Parts[0].Kind != MessagePartRangeItem {
		t.Fatalf("response parts = %#v", resp.Parts)
	}
	item := resp.Parts[0].RangeItem
	if !item.HaveLocal || len(item.Values) != 1 || !item.Values[0].Entry.Equal(local) || item.Values[0].Status != ContentMissing {
		t.Fatalf("response item = %#v", item)
	}
}

func TestProcessMessageFingerprintMatchTerminates(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("k", 1, 1))
	store := NewMemoryStore()
	store.Put(entry)
	msg := store.InitialMessage()

	resp, ok := store.ProcessMessage(DefaultSyncConfig(), msg, nil, nil, nil)
	if ok {
		t.Fatalf("ProcessMessage returned %#v, want none", resp)
	}
}

func TestProcessMessageFingerprintAnchorSendsItems(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("k", 1, 1))
	store := NewMemoryStore()
	store.Put(entry)
	r := NewRange(entry.Entry.ID, entry.Entry.ID)

	resp, ok := store.ProcessMessage(DefaultSyncConfig(), Message{Parts: []MessagePart{{
		Kind: MessagePartRangeFingerprint,
		RangeFingerprint: RangeFingerprint{
			Range:       r,
			Fingerprint: EmptyFingerprint(),
		},
	}}}, nil, nil, nil)
	if !ok {
		t.Fatal("ProcessMessage returned no response")
	}
	if len(resp.Parts) != 1 || resp.Parts[0].Kind != MessagePartRangeItem {
		t.Fatalf("response parts = %#v", resp.Parts)
	}
	item := resp.Parts[0].RangeItem
	if item.HaveLocal || len(item.Values) != 1 || !item.Values[0].Entry.Equal(entry) {
		t.Fatalf("response item = %#v", item)
	}
}

func TestProcessMessageFingerprintSplit(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	for _, key := range []string{"a", "b", "c", "d"} {
		store.Put(testSignedEntry(namespace, author, key, testRecord(key, 1, 1)))
	}
	first := store.Entries()[0].Entry.ID
	r := NewRange(first, first)

	resp, ok := store.ProcessMessage(DefaultSyncConfig(), Message{Parts: []MessagePart{{
		Kind: MessagePartRangeFingerprint,
		RangeFingerprint: RangeFingerprint{
			Range:       r,
			Fingerprint: Fingerprint{},
		},
	}}}, nil, nil, nil)
	if !ok {
		t.Fatal("ProcessMessage returned no response")
	}
	if len(resp.Parts) != 2 {
		t.Fatalf("response part count = %d, want 2", len(resp.Parts))
	}
	for _, part := range resp.Parts {
		if part.Kind != MessagePartRangeFingerprint {
			t.Fatalf("part = %#v, want range fingerprint", part)
		}
	}
}

func TestSplitRangeSkipsDuplicatePivots(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	for _, key := range []string{"a", "b"} {
		store.Put(testSignedEntry(namespace, author, key, testRecord(key, 1, 1)))
	}
	entries := store.Entries()
	r := NewRange(entries[0].Entry.ID, entries[1].Entry.ID)

	for _, r := range store.splitRange(allNamespaces, r, 5) {
		if r.IsAll() {
			t.Fatalf("splitRange generated all-range partition %#v", r)
		}
	}
}

// TestProcessMessageRejectsFutureTimestamp pins MaxTimestampFutureShift on the
// remote insert path: conflicts resolve by timestamp, so an entry dated past
// the bound would win every later write to its key.
func TestProcessMessageRejectsFutureTimestamp(t *testing.T) {
	now := uint64(time.Now().UnixMicro())
	tests := []struct {
		name      string
		timestamp uint64
		want      int
	}{
		{"now", now, 1},
		{"within bound", now + MaxTimestampFutureShift/2, 1},
		{"past bound", now + 2*MaxTimestampFutureShift, 0},
		{"max uint64", ^uint64(0), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace := NewNamespaceSecret(repeat32(0xb2))
			author := NewAuthor(repeat32(0xa1))
			entry := testSignedEntry(namespace, author, "k", testRecord("k", 1, tt.timestamp))
			store := NewMemoryStore()

			store.ProcessMessageInNamespace(namespace.ID(), DefaultSyncConfig(), Message{Parts: []MessagePart{{
				Kind: MessagePartRangeItem,
				RangeItem: RangeItem{
					Range:     NewRange(entry.Entry.ID, entry.Entry.ID),
					Values:    []RangeValue{{Entry: entry, Status: ContentComplete}},
					HaveLocal: true,
				},
			}}}, nil, nil, nil)

			if got := store.Len(); got != tt.want {
				t.Fatalf("Len = %d, want %d", got, tt.want)
			}
		})
	}
}
