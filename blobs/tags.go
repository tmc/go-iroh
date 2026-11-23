package blobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// TagInfo describes one named blob tag.
type TagInfo struct {
	Name  string
	Value HashAndFormat
}

// GCResult reports the result of a filesystem store garbage-collection sweep.
type GCResult struct {
	Deleted int
}

// GCEventKind identifies a garbage-collection progress event.
type GCEventKind string

const (
	// GCEventMark reports the number of hashes found reachable from tags.
	GCEventMark GCEventKind = "mark"
	// GCEventDelete reports one deleted blob.
	GCEventDelete GCEventKind = "delete"
	// GCEventDone reports the final sweep result.
	GCEventDone GCEventKind = "done"
)

// GCEvent reports progress from [FSStore.GCWithEvents].
type GCEvent struct {
	Kind    GCEventKind
	Hash    Hash
	Live    int
	Deleted int
}

// SetTag sets name to value.
func (s *FSStore) SetTag(name string, value HashAndFormat) error {
	if s == nil {
		return errors.New("blobs: nil fs store")
	}
	if name == "" {
		return errors.New("blobs: empty tag name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStoreClosed
	}
	if s.tags == nil {
		s.tags = make(map[string]HashAndFormat)
	}
	s.tags[name] = value
	if err := s.saveTagsLocked(); err != nil {
		return err
	}
	return nil
}

// Tag returns the value for name.
func (s *FSStore) Tag(name string) (HashAndFormat, bool, error) {
	if s == nil {
		return HashAndFormat{}, false, errors.New("blobs: nil fs store")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return HashAndFormat{}, false, ErrStoreClosed
	}
	value, ok := s.tags[name]
	return value, ok, nil
}

// DeleteTag deletes name.
func (s *FSStore) DeleteTag(name string) (bool, error) {
	if s == nil {
		return false, errors.New("blobs: nil fs store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrStoreClosed
	}
	if _, ok := s.tags[name]; !ok {
		return false, nil
	}
	delete(s.tags, name)
	if err := s.saveTagsLocked(); err != nil {
		return false, err
	}
	return true, nil
}

// Tags returns all persistent tags sorted by name.
func (s *FSStore) Tags() ([]TagInfo, error) {
	if s == nil {
		return nil, errors.New("blobs: nil fs store")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	out := make([]TagInfo, 0, len(s.tags))
	for name, value := range s.tags {
		out = append(out, TagInfo{Name: name, Value: value})
	}
	slices.SortFunc(out, func(a, b TagInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return out, nil
}

// TempTag is a process-local tag that protects a blob from collection until it
// is closed.
//
// A TempTag whose store never collects blobs, such as [MemStore], protects
// nothing and Close is a no-op. Value reports what the tag protects.
type TempTag struct {
	once  sync.Once
	store tempTagStore
	id    uint64
	value HashAndFormat
}

// tempTagStore is the part of a store a TempTag needs to release itself.
type tempTagStore interface {
	releaseTempTag(id uint64)
}

// Value returns the hash and format t protects.
func (t *TempTag) Value() HashAndFormat {
	if t == nil {
		return HashAndFormat{}
	}
	return t.value
}

// Hash returns the hash t protects.
func (t *TempTag) Hash() Hash { return t.Value().Hash }

// NewTempTag creates a process-local tag for value.
//
// A blob is collectible between the moment it is stored and the moment a tag
// names it, so NewTempTag cannot protect a blob a caller has only just added.
// Use [BlobWriter.Commit], which installs the blob and its tag together.
func (s *FSStore) NewTempTag(value HashAndFormat) (*TempTag, error) {
	if s == nil {
		return nil, errors.New("blobs: nil fs store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStoreClosed
	}
	return s.newTempTagLocked(value), nil
}

// newTempTagLocked creates a temp tag for value. s.mu must be held for writing.
func (s *FSStore) newTempTagLocked(value HashAndFormat) *TempTag {
	if s.temp == nil {
		s.temp = make(map[uint64]HashAndFormat)
	}
	s.nextTag++
	id := s.nextTag
	s.temp[id] = value
	return &TempTag{store: s, id: id, value: value}
}

func (s *FSStore) releaseTempTag(id uint64) {
	s.mu.Lock()
	delete(s.temp, id)
	s.mu.Unlock()
}

// Close removes t from its store.
func (t *TempTag) Close() error {
	if t == nil || t.store == nil {
		return nil
	}
	t.once.Do(func() { t.store.releaseTempTag(t.id) })
	return nil
}

// GC deletes blobs that are not reachable from a persistent or temp tag.
func (s *FSStore) GC(ctx context.Context) (GCResult, error) {
	return s.GCWithEvents(ctx, nil)
}

// GCWithEvents deletes blobs that are not reachable from a persistent or temp
// tag and calls onEvent with mark, delete, and done progress events.
func (s *FSStore) GCWithEvents(ctx context.Context, onEvent func(GCEvent)) (GCResult, error) {
	if s == nil {
		return GCResult{}, errors.New("blobs: nil fs store")
	}
	if err := ctxErr(ctx); err != nil {
		return GCResult{}, err
	}
	if s.isClosed() {
		return GCResult{}, ErrStoreClosed
	}
	live := make(map[Hash]struct{})
	roots := s.gcRoots()
	for _, value := range roots {
		s.markLive(live, value)
	}
	emitGCEvent(onEvent, GCEvent{Kind: GCEventMark, Live: len(live)})

	entries, err := os.ReadDir(s.dataDir)
	if err != nil {
		return GCResult{}, fmt.Errorf("blobs: read data dir: %w", err)
	}
	var deleted int
	for _, entry := range entries {
		if err := ctxErr(ctx); err != nil {
			return GCResult{}, err
		}
		if entry.IsDir() {
			continue
		}
		hash, err := ParseHash(entry.Name())
		if err != nil {
			continue
		}
		if _, ok := live[hash]; ok {
			continue
		}
		if !s.gcClaimDelete(hash) {
			continue
		}
		if err := os.Remove(filepath.Join(s.dataDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return GCResult{}, fmt.Errorf("blobs: remove data: %w", err)
		}
		if err := os.Remove(filepath.Join(s.baoDir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return GCResult{}, fmt.Errorf("blobs: remove outboard: %w", err)
		}
		deleted++
		emitGCEvent(onEvent, GCEvent{Kind: GCEventDelete, Hash: hash, Deleted: deleted})
	}
	if err := s.gcRemoveOrphanOutboards(ctx, live); err != nil {
		return GCResult{}, err
	}
	result := GCResult{Deleted: deleted}
	emitGCEvent(onEvent, GCEvent{Kind: GCEventDone, Deleted: deleted})
	return result, nil
}

func (s *FSStore) gcRemoveOrphanOutboards(ctx context.Context, live map[Hash]struct{}) error {
	entries, err := os.ReadDir(s.baoDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("blobs: read outboard dir: %w", err)
	}
	for _, entry := range entries {
		if err := ctxErr(ctx); err != nil {
			return err
		}
		if entry.IsDir() {
			continue
		}
		hash, err := ParseHash(entry.Name())
		if err != nil {
			continue
		}
		if _, ok := live[hash]; ok {
			continue
		}
		s.mu.Lock()
		remove := !s.closed && !s.protectsHashLocked(hash) && !fileExists(s.dataPath(hash))
		if remove {
			err = os.Remove(filepath.Join(s.baoDir, entry.Name()))
		}
		s.mu.Unlock()
		if remove && err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("blobs: remove orphan outboard: %w", err)
		}
	}
	return nil
}

func (s *FSStore) gcRoots() []HashAndFormat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	roots := make([]HashAndFormat, 0, len(s.tags)+len(s.temp))
	for _, value := range s.tags {
		roots = append(roots, value)
	}
	for _, value := range s.temp {
		roots = append(roots, value)
	}
	return roots
}

func (s *FSStore) gcClaimDelete(hash Hash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	return !s.protectsHashLocked(hash)
}

func (s *FSStore) protectsHashLocked(hash Hash) bool {
	for _, value := range s.tags {
		if value.Hash == hash {
			return true
		}
	}
	for _, value := range s.temp {
		if value.Hash == hash {
			return true
		}
	}
	return false
}

func emitGCEvent(onEvent func(GCEvent), ev GCEvent) {
	if onEvent != nil {
		onEvent(ev)
	}
}

func (s *FSStore) markLive(live map[Hash]struct{}, value HashAndFormat) {
	if value.Hash == EmptyHash {
		return
	}
	if _, ok := live[value.Hash]; ok {
		return
	}
	live[value.Hash] = struct{}{}
	if value.Format.IsRaw() {
		return
	}
	data, err := os.ReadFile(s.dataPath(value.Hash))
	if err != nil {
		return
	}
	seq, err := ParseHashSequence(data)
	if err != nil {
		return
	}
	for _, hash := range seq.Hashes() {
		live[hash] = struct{}{}
	}
}
