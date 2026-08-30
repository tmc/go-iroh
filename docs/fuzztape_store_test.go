package docs

import (
	"bytes"
	"slices"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/internal/fuzztape"
)

// The store machine checks MemoryStore against a plain map holding the same
// entries. The map applies the prefix rules of the document store — an entry
// is rejected if an ancestor of its key is at least as new, and inserting an
// entry removes the descendants it supersedes — and every operation compares
// what the store reports against what the map says.

// storeMachine is a MemoryStore and its reference model. The model is keyed
// by the encoded record identifier, the same identity the store uses.
type storeMachine struct {
	t     *fuzztape.T
	store *MemoryStore
	model map[string]Entry

	namespaces []NamespaceSecret
	authors    []Author
}

// storeMachineKeys are the entry keys the machine uses. They are short and
// overlapping so that the prefix rules are exercised: "" is an ancestor of
// every key, and "a" is an ancestor of "ab".
var storeMachineKeys = [][]byte{nil, []byte("a"), []byte("ab"), []byte("b"), []byte("ba")}

// storeMachineHashes are the content hashes the machine uses. None of them is
// blobs.EmptyHash, which would make the record a tombstone.
var storeMachineHashes = []blobs.Hash{{1}, {2}, {3}}

// storeMachineTimestamps are deliberately few, so that entries collide on
// timestamp and the tie-break on content hash is exercised.
var storeMachineTimestamps = []uint64{1, 2, 3}

func newStoreMachine(t *fuzztape.T) *storeMachine {
	m := &storeMachine{
		t:     t,
		store: NewMemoryStore(),
		model: make(map[string]Entry),
	}
	for i := range 2 {
		var seed [32]byte
		seed[0] = byte(i + 1)
		m.namespaces = append(m.namespaces, NewNamespaceSecret(seed))
		seed[1] = 0xff
		m.authors = append(m.authors, NewAuthor(seed))
	}
	return m
}

// pickID draws one of the identifiers the machine works with, and returns the
// namespace secret and author needed to sign an entry for it.
func (m *storeMachine) pickID(t *fuzztape.T) (RecordIdentifier, NamespaceSecret, Author) {
	ns := m.namespaces[t.IntN(len(m.namespaces))]
	author := m.authors[t.IntN(len(m.authors))]
	key := storeMachineKeys[t.IntN(len(storeMachineKeys))]
	return NewRecordIdentifier(ns.ID(), author.ID(), key), ns, author
}

// modelPut applies the store's insert rules to the model, and reports the
// outcome the store is expected to return.
func (m *storeMachine) modelPut(e Entry) (inserted bool, removed int) {
	for _, existing := range m.model {
		if isKeyPrefix(existing.ID, e.ID) && e.Record.Compare(existing.Record) <= 0 {
			return false, 0
		}
	}
	for k, existing := range m.model {
		if isKeyPrefix(e.ID, existing.ID) && e.Record.Compare(existing.Record) >= 0 {
			delete(m.model, k)
			removed++
		}
	}
	m.model[string(e.ID.bytes())] = e
	return true, removed
}

// isKeyPrefix reports whether ancestor's key is a prefix of id's key within
// the same namespace and author.
func isKeyPrefix(ancestor, id RecordIdentifier) bool {
	return ancestor.namespace == id.namespace && ancestor.author == id.author &&
		bytes.HasPrefix(id.key, ancestor.key)
}

// modelEntries returns the model entries in document order.
func (m *storeMachine) modelEntries() []Entry {
	entries := make([]Entry, 0, len(m.model))
	for _, e := range m.model {
		entries = append(entries, e)
	}
	slices.SortFunc(entries, func(a, b Entry) int { return a.Compare(b) })
	return entries
}

// put inserts entry into both the store and the model, and compares the
// outcomes.
func (m *storeMachine) put(entry SignedEntry) {
	got := m.store.Put(entry)
	wantInserted, wantRemoved := m.modelPut(entry.Entry)
	if got.Inserted() != wantInserted || got.Removed() != wantRemoved {
		m.t.Fatalf("Put(%s) = inserted %v, removed %d; want inserted %v, removed %d",
			entryString(entry.Entry), got.Inserted(), got.Removed(), wantInserted, wantRemoved)
	}
}

func entryString(e Entry) string {
	return string(e.Key()) + "@" + string(rune('0'+e.Record.Timestamp))
}

// FuzzStoreMachine explores operation sequences over MemoryStore under
// go test -fuzz.
func FuzzStoreMachine(f *testing.F) {
	storeMachineSpec().Fuzz(f)
}

func TestStoreMachine(t *testing.T) {
	storeMachineSpec().Run(t, 200)
}

func storeMachineSpec() fuzztape.Machine[*storeMachine] {
	return fuzztape.Machine[*storeMachine]{
		Name:   "FuzzStoreMachine",
		MaxOps: 48,
		Init:   newStoreMachine,
		Ops: []fuzztape.Op[*storeMachine]{
			{
				Name:   "put",
				Weight: 6,
				Apply: func(t *fuzztape.T, m *storeMachine) {
					id, ns, author := m.pickID(t)
					record := NewRecord(
						storeMachineHashes[t.IntN(len(storeMachineHashes))],
						uint64(1+t.IntN(4)), // a non-empty record has a non-zero length
						storeMachineTimestamps[t.IntN(len(storeMachineTimestamps))],
					)
					m.put(NewSignedEntry(NewEntry(id, record), ns, author))
				},
			},
			{
				Name:   "delete",
				Weight: 2,
				Apply: func(t *fuzztape.T, m *storeMachine) {
					id, ns, author := m.pickID(t)
					record := EmptyRecord(storeMachineTimestamps[t.IntN(len(storeMachineTimestamps))])
					m.put(NewSignedEntry(NewEntry(id, record), ns, author))
				},
			},
			{
				Name:   "getExact",
				Weight: 3,
				Apply: func(t *fuzztape.T, m *storeMachine) {
					id, _, _ := m.pickID(t)
					includeEmpty := t.Bool()
					got, ok := m.store.GetExact(id.Namespace(), id.Author(), id.Key(), includeEmpty)
					want, wantOK := m.model[string(id.bytes())]
					if wantOK && !includeEmpty && want.Record.IsEmpty() {
						wantOK = false
					}
					if ok != wantOK {
						m.t.Fatalf("GetExact(%q, includeEmpty %v) ok = %v, want %v",
							id.Key(), includeEmpty, ok, wantOK)
					}
					if ok && got.Entry.Compare(want) != 0 {
						m.t.Fatalf("GetExact(%q) = %s, want %s",
							id.Key(), entryString(got.Entry), entryString(want))
					}
				},
			},
			{
				Name:   "getRange",
				Weight: 2,
				Apply: func(t *fuzztape.T, m *storeMachine) {
					start, _, _ := m.pickID(t)
					end, _, _ := m.pickID(t)
					r := NewRange(start, end)
					got := m.store.GetRange(r)
					var want []Entry
					for _, e := range m.modelEntries() {
						if r.Contains(e.ID) {
							want = append(want, e)
						}
					}
					if len(got) != len(want) {
						m.t.Fatalf("GetRange returned %d entries, want %d", len(got), len(want))
					}
					for i := range got {
						if got[i].Entry.Compare(want[i]) != 0 {
							m.t.Fatalf("GetRange entry %d = %s, want %s",
								i, entryString(got[i].Entry), entryString(want[i]))
						}
					}
				},
			},
			{
				Name: "reload",
				Apply: func(t *fuzztape.T, m *storeMachine) {
					// A snapshot round trip must preserve the store exactly:
					// the entries are written in document order and reinserted
					// under the same prefix rules.
					var buf bytes.Buffer
					if _, err := m.store.WriteTo(&buf); err != nil {
						m.t.Fatalf("WriteTo: %v", err)
					}
					reloaded := NewMemoryStore()
					if _, err := reloaded.ReadFrom(&buf); err != nil {
						m.t.Fatalf("ReadFrom: %v", err)
					}
					m.store = reloaded
				},
			},
		},
		Check: func(t *fuzztape.T, m *storeMachine) {
			want := m.modelEntries()
			got := m.store.Entries()
			if m.store.Len() != len(want) {
				t.Fatalf("Len = %d, want %d", m.store.Len(), len(want))
			}
			if len(got) != len(want) {
				t.Fatalf("Entries returned %d entries, want %d", len(got), len(want))
			}
			for i := range got {
				if got[i].Entry.Compare(want[i]) != 0 {
					t.Fatalf("entry %d = %s, want %s", i, entryString(got[i].Entry), entryString(want[i]))
				}
				if got[i].Entry.Record != want[i].Record {
					t.Fatalf("entry %d record = %+v, want %+v", i, got[i].Entry.Record, want[i].Record)
				}
				if err := got[i].Verify(); err != nil {
					t.Fatalf("entry %d does not verify: %v", i, err)
				}
			}
		},
	}
}
