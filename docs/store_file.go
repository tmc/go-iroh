package docs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// NewFileStore opens a store that persists inserts to path. Check
// [InsertOutcome.Err] for save failures; failed saves leave inserts in memory.
// Concurrent saves on this store are serialized through snapshot and rename.
func NewFileStore(path string) (*MemoryStore, error) {
	if path == "" {
		return nil, errors.New("docs: empty store file path")
	}
	var store *MemoryStore
	if _, err := os.Stat(path); err == nil {
		loaded, err := LoadMemoryStoreFile(path)
		if err != nil {
			return nil, err
		}
		store = loaded
	} else if errors.Is(err, os.ErrNotExist) {
		store = NewMemoryStore()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("docs: create store dir: %w", err)
		}
		if err := store.SaveFile(path); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("docs: stat store file: %w", err)
	}
	store.persistPath = path
	return store, nil
}

// SaveFile writes s to path atomically. Saving the configured file-store path
// updates PersistError and signals subscriber recovery after a failed save.
func (s *MemoryStore) SaveFile(path string) error {
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	err := s.saveFile(path)
	if path == s.persistPath {
		s.setPersistError(err)
	}
	return err
}

func (s *MemoryStore) saveFile(path string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("docs: create store temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := s.WriteTo(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("docs: write store file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("docs: sync store file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("docs: close store file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("docs: rename store file: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// LoadMemoryStoreFile loads a store snapshot from path.
func LoadMemoryStoreFile(path string) (*MemoryStore, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("docs: open store file: %w", err)
	}
	defer f.Close()

	store := NewMemoryStore()
	if _, err := store.ReadFrom(f); err != nil {
		return nil, err
	}
	return store, nil
}
