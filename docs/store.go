package docs

import (
	"bytes"
	"slices"
	"sync"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

// InsertOutcome reports the result of a store insert.
type InsertOutcome struct {
	inserted bool
	removed  int
}

// Inserted reports whether the entry was inserted.
func (o InsertOutcome) Inserted() bool { return o.inserted }

// Removed reports how many older descendant entries were removed.
func (o InsertOutcome) Removed() int { return o.removed }

// MemoryStore is an in-memory document entry store.
type MemoryStore struct {
	mu          sync.RWMutex
	entries     map[string]SignedEntry
	events      *storeWatcher
	seq         uint64
	persistPath string
	persistErr  error
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]SignedEntry)}
}

// Len returns the number of entries in s.
func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// GetExact returns the entry for namespace, author, and key.
func (s *MemoryStore) GetExact(namespace NamespaceID, author AuthorID, key []byte, includeEmpty bool) (SignedEntry, bool) {
	id := NewRecordIdentifier(namespace, author, key)

	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[string(id.bytes())]
	if !ok || (!includeEmpty && entry.Entry.Record.IsEmpty()) {
		return SignedEntry{}, false
	}
	return entry, true
}

// Subscribe returns a subscription to successful store insert events. Events
// sent before Subscribe are not replayed.
func (s *MemoryStore) Subscribe() (<-chan StoreEvent, func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.events == nil {
		s.events = newStoreWatcher()
	}
	return s.events.Subscribe()
}

// Entries returns the store entries in document order.
func (s *MemoryStore) Entries() []SignedEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.entriesLocked()
}

// GetRange returns entries whose identifiers are in r.
func (s *MemoryStore) GetRange(r Range) []SignedEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getRangeLocked(r)
}

func (s *MemoryStore) getRangeLocked(r Range) []SignedEntry {
	var entries []SignedEntry
	for _, entry := range s.entries {
		if r.Contains(entry.Entry.ID) {
			entries = append(entries, entry)
		}
	}
	sortEntries(entries)
	return entries
}

// Fingerprint returns the fingerprint of entries in r.
func (s *MemoryStore) Fingerprint(r Range) Fingerprint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.fingerprintLocked(r)
}

// InitialMessage returns the Rust range reconciliation initial message.
func (s *MemoryStore) InitialMessage() Message {
	s.mu.RLock()
	entries := s.entriesLocked()
	var first RecordIdentifier
	if len(entries) != 0 {
		first = entries[0].Entry.ID
	}
	r := NewRange(first, first)
	fingerprint := s.fingerprintLocked(r)
	s.mu.RUnlock()

	return Message{Parts: []MessagePart{{
		Kind: MessagePartRangeFingerprint,
		RangeFingerprint: RangeFingerprint{
			Range:       r,
			Fingerprint: fingerprint,
		},
	}}}
}

// ProcessMessage processes message and returns a response, if reconciliation
// should continue. The validate callback must verify incoming entries that
// should be trusted.
func (s *MemoryStore) ProcessMessage(config SyncConfig, message Message, validate func(SignedEntry, ContentStatus) bool, onInsert func(SignedEntry, ContentStatus), contentStatus func(SignedEntry) ContentStatus) (Message, bool) {
	config = config.withDefaults()
	if validate == nil {
		validate = func(SignedEntry, ContentStatus) bool { return true }
	}
	if contentStatus == nil {
		contentStatus = func(SignedEntry) ContentStatus { return ContentComplete }
	}

	var out []MessagePart
	var items []RangeItem
	var fingerprints []RangeFingerprint
	for _, part := range message.Parts {
		switch part.Kind {
		case MessagePartRangeItem:
			items = append(items, part.RangeItem)
		case MessagePartRangeFingerprint:
			fingerprints = append(fingerprints, part.RangeFingerprint)
		}
	}

	for _, item := range items {
		var diff []RangeValue
		if !item.HaveLocal {
			for _, entry := range s.GetRange(item.Range) {
				if !peerHasNewerValue(item.Values, entry) {
					diff = append(diff, RangeValue{Entry: entry, Status: contentStatus(entry)})
				}
			}
		}
		for _, value := range item.Values {
			if !validate(value.Entry, value.Status) {
				continue
			}
			origin := InsertOrigin{Kind: InsertOriginRemote, ContentStatus: value.Status}
			if outcome := s.PutWithOrigin(value.Entry, origin); outcome.Inserted() && onInsert != nil {
				onInsert(value.Entry, value.Status)
			}
		}
		if len(diff) != 0 {
			out = append(out, MessagePart{
				Kind: MessagePartRangeItem,
				RangeItem: RangeItem{
					Range:     item.Range,
					Values:    diff,
					HaveLocal: true,
				},
			})
		}
	}

	for _, remote := range fingerprints {
		local := s.Fingerprint(remote.Range)
		if local == remote.Fingerprint {
			continue
		}
		entries := s.GetRange(remote.Range)
		if len(entries) <= 1 || remote.Fingerprint == EmptyFingerprint() {
			out = append(out, MessagePart{
				Kind: MessagePartRangeItem,
				RangeItem: RangeItem{
					Range:     remote.Range,
					Values:    rangeValues(entries, contentStatus),
					HaveLocal: false,
				},
			})
			continue
		}
		for _, r := range s.splitRange(remote.Range, config.SplitFactor) {
			if config.splitHook != nil {
				config.splitHook(r)
			}
			chunk := s.GetRange(r)
			if len(chunk) > config.MaxSetSize {
				out = append(out, MessagePart{
					Kind: MessagePartRangeFingerprint,
					RangeFingerprint: RangeFingerprint{
						Range:       r,
						Fingerprint: s.Fingerprint(r),
					},
				})
			} else {
				out = append(out, MessagePart{
					Kind: MessagePartRangeItem,
					RangeItem: RangeItem{
						Range:     r,
						Values:    rangeValues(chunk, contentStatus),
						HaveLocal: false,
					},
				})
			}
		}
	}
	if len(out) == 0 {
		return Message{}, false
	}
	return Message{Parts: out}, true
}

func (s *MemoryStore) fingerprintLocked(r Range) Fingerprint {
	fp := EmptyFingerprint()
	for _, entry := range s.getRangeLocked(r) {
		fp.Xor(Fingerprint(entry.Fingerprint()))
	}
	return fp
}

func (s *MemoryStore) entriesLocked() []SignedEntry {
	entries := make([]SignedEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	sortEntries(entries)
	return entries
}

// Put inserts entry if it is newer than all matching parent entries.
//
// Keys form a prefix hierarchy per author, so an entry shadows its
// descendants: writing "menu" for an author removes that author's "menu/tea"
// and every other key under "menu", and a document cannot hold both. The insert
// is dropped instead when an ancestor key is already present with a newer or
// equal record. "Newer" is the record timestamp, with the content hash breaking
// ties. Entries from different authors never shadow each other.
//
// This is the iroh-docs model, deliberate and how a subtree is deleted, but it
// is silent: [InsertOutcome.Removed] reports how many entries a write deleted,
// and nothing reports it to a later reader. A caller that wants "menu" and
// "menu/tea" to coexist must keep the author's keys prefix-free, so that no key
// is a prefix of another. Note that a trailing separator does not help: "menu/"
// is still a prefix of "menu/tea".
func (s *MemoryStore) Put(entry SignedEntry) InsertOutcome {
	return s.PutWithOrigin(entry, InsertOrigin{Kind: InsertOriginLocal})
}

func (s *MemoryStore) put(entry SignedEntry) InsertOutcome {
	outcome, _, _ := s.putEntry(entry, InsertOrigin{}, false)
	return outcome
}

// PutWithOrigin inserts entry with origin metadata for subscribers. It shadows
// descendant keys exactly as [MemoryStore.Put] does.
func (s *MemoryStore) PutWithOrigin(entry SignedEntry, origin InsertOrigin) InsertOutcome {
	outcome, event, events := s.putEntry(entry, origin, true)
	if outcome.Inserted() && s.persistPath != "" {
		s.setPersistError(s.SaveFile(s.persistPath))
	}
	if outcome.Inserted() && events != nil {
		events.Send(event)
	}
	return outcome
}

// PersistError returns the last error from an automatic file-store save.
func (s *MemoryStore) PersistError() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.persistErr
}

func (s *MemoryStore) setPersistError(err error) {
	s.mu.Lock()
	s.persistErr = err
	s.mu.Unlock()
}

func (s *MemoryStore) contentReady(hash blobs.Hash) {
	s.mu.Lock()
	s.seq++
	event := StoreEvent{
		Kind:     StoreEventContentReady,
		Sequence: s.seq,
		Hash:     hash,
	}
	events := s.events
	s.mu.Unlock()
	if events != nil {
		events.Send(event)
	}
}

func (s *MemoryStore) putEntry(entry SignedEntry, origin InsertOrigin, notify bool) (InsertOutcome, StoreEvent, *storeWatcher) {
	s.mu.Lock()

	if s.entries == nil {
		s.entries = make(map[string]SignedEntry)
	}
	id := entry.Entry.ID
	key := id.bytes()
	for _, existing := range s.entries {
		if hasEntryPrefix(id, existing.Entry.ID) && entry.Entry.Record.Compare(existing.Entry.Record) <= 0 {
			s.mu.Unlock()
			return InsertOutcome{}, StoreEvent{}, nil
		}
	}
	removed := 0
	for k, existing := range s.entries {
		if hasEntryPrefix(existing.Entry.ID, id) && entry.Entry.Record.Compare(existing.Entry.Record) >= 0 {
			delete(s.entries, k)
			removed++
		}
	}
	s.entries[string(key)] = entry
	outcome := InsertOutcome{inserted: true, removed: removed}
	var event StoreEvent
	var events *storeWatcher
	if notify {
		s.seq++
		event = StoreEvent{
			Kind:          storeEventKind(origin.Kind),
			Sequence:      s.seq,
			Entry:         entry,
			Removed:       removed,
			From:          origin.From,
			ContentStatus: origin.ContentStatus,
		}
		events = s.events
	}
	s.mu.Unlock()

	return outcome, event, events
}

// InsertOriginKind tags the origin of a store insert.
type InsertOriginKind uint8

const (
	// InsertOriginLocal means the entry was inserted locally.
	InsertOriginLocal InsertOriginKind = iota
	// InsertOriginRemote means the entry came from a peer.
	InsertOriginRemote
)

// InsertOrigin describes where an inserted entry came from.
type InsertOrigin struct {
	Kind          InsertOriginKind
	From          key.EndpointID
	ContentStatus ContentStatus
}

func hasEntryPrefix(id, prefix RecordIdentifier) bool {
	return id.namespace == prefix.namespace && id.author == prefix.author && bytes.HasPrefix(id.key, prefix.key)
}

func sortEntries(entries []SignedEntry) {
	slices.SortFunc(entries, func(a, b SignedEntry) int {
		return a.Compare(b)
	})
}

func peerHasNewerValue(values []RangeValue, entry SignedEntry) bool {
	for _, value := range values {
		if value.Entry.Entry.ID.Compare(entry.Entry.ID) == 0 && value.Entry.Entry.Record.Compare(entry.Entry.Record) >= 0 {
			return true
		}
	}
	return false
}

func rangeValues(entries []SignedEntry, contentStatus func(SignedEntry) ContentStatus) []RangeValue {
	values := make([]RangeValue, 0, len(entries))
	for _, entry := range entries {
		values = append(values, RangeValue{Entry: entry, Status: contentStatus(entry)})
	}
	return values
}

func (s *MemoryStore) splitRange(r Range, splitFactor int) []Range {
	if splitFactor < 2 {
		splitFactor = 2
	}
	entries := s.GetRange(r)
	n := len(entries)
	if n == 0 {
		return nil
	}
	start := 0
	for ; start < len(entries); start++ {
		if entries[start].Entry.ID.Compare(r.Start) >= 0 {
			break
		}
	}
	if start == len(entries) {
		start = 0
	}
	pivot := func(i int) RecordIdentifier {
		i %= splitFactor
		offset := (n * (i + 1)) / splitFactor
		offset = (start + offset) % n
		return entries[offset].Entry.ID
	}

	var ranges []Range
	if r.IsAll() {
		for i := 0; i < splitFactor; i++ {
			x, y := pivot(i), pivot(i+1)
			if x.Compare(y) != 0 {
				ranges = append(ranges, NewRange(x, y))
			}
		}
		return ranges
	}
	ranges = append(ranges, NewRange(r.Start, pivot(0)))
	for i := 0; i < splitFactor-2; i++ {
		x, y := pivot(i), pivot(i+1)
		if x.Compare(y) != 0 {
			ranges = append(ranges, NewRange(x, y))
		}
	}
	ranges = append(ranges, NewRange(pivot(splitFactor-2), r.End))
	return nonEmptyRanges(ranges)
}

func nonEmptyRanges(ranges []Range) []Range {
	out := ranges[:0]
	for _, r := range ranges {
		if r.Start.Compare(r.End) != 0 {
			out = append(out, r)
		}
	}
	return out
}
