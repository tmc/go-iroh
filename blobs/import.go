package blobs

import (
	"errors"
	"fmt"
	"io"
	"os"

	"lukechampine.com/blake3/bao"
)

// ImportMode controls how [FSStore.ImportFile] stores file data.
type ImportMode uint8

const (
	// ImportCopy always copies bytes into the store.
	ImportCopy ImportMode = iota
	// ImportTryReference tries to reference the source with a hardlink, then
	// falls back to [ImportCopy]. Reflink support can be added behind this mode.
	ImportTryReference
)

// ImportFile imports path as a complete raw blob.
func (s *FSStore) ImportFile(path string, mode ImportMode) (Hash, error) {
	if s == nil {
		return Hash{}, errors.New("blobs: nil fs store")
	}
	if s.isClosed() {
		return Hash{}, ErrStoreClosed
	}
	if path == "" {
		return Hash{}, errors.New("blobs: empty import path")
	}
	switch mode {
	case ImportCopy:
		return s.importFileCopy(path)
	case ImportTryReference:
		hash, err := s.importFileLink(path)
		if err == nil {
			return hash, nil
		}
		return s.importFileCopy(path)
	default:
		return Hash{}, fmt.Errorf("blobs: unknown import mode %d", mode)
	}
}

func (s *FSStore) importFileCopy(path string) (Hash, error) {
	src, err := os.Open(path)
	if err != nil {
		return Hash{}, fmt.Errorf("blobs: open import file: %w", err)
	}
	defer src.Close()

	dataTmp, err := os.CreateTemp(s.dataDir, importTempPrefix+"*")
	if err != nil {
		return Hash{}, fmt.Errorf("blobs: create import data: %w", err)
	}
	defer removeTemp(dataTmp.Name())
	if _, err := io.Copy(dataTmp, src); err != nil {
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: copy import data: %w", err)
	}
	if _, err := dataTmp.Seek(0, io.SeekStart); err != nil {
		dataTmp.Close()
		return Hash{}, fmt.Errorf("blobs: rewind import data: %w", err)
	}
	hash, _, err := s.finishImport(dataTmp, true, false)
	return hash, err
}

func (s *FSStore) importFileLink(path string) (Hash, error) {
	dataTmp, err := os.CreateTemp(s.dataDir, importTempPrefix+"*")
	if err != nil {
		return Hash{}, fmt.Errorf("blobs: create import data: %w", err)
	}
	dataTmpName := dataTmp.Name()
	if err := dataTmp.Close(); err != nil {
		removeTemp(dataTmpName)
		return Hash{}, err
	}
	if err := os.Remove(dataTmpName); err != nil {
		return Hash{}, err
	}
	if err := os.Link(path, dataTmpName); err != nil {
		return Hash{}, err
	}
	dataTmp, err = os.OpenFile(dataTmpName, os.O_RDONLY, 0)
	if err != nil {
		removeTemp(dataTmpName)
		return Hash{}, fmt.Errorf("blobs: open linked import data: %w", err)
	}
	defer removeTemp(dataTmpName)
	hash, _, err := s.finishImport(dataTmp, false, false)
	return hash, err
}

// finishImport encodes the outboard for dataTmp and installs both files under
// the content's root hash.
//
// When protect is set, finishImport returns a [TempTag] naming the blob, created
// under the same lock that installs it. Holding s.mu across both is what makes
// the blob unreachable by [FSStore.GC] before it is protected: GC claims a
// deletion under the same lock, so it either runs entirely before the install,
// finding nothing, or entirely after, finding the tag.
func (s *FSStore) finishImport(dataTmp *os.File, syncData, protect bool) (Hash, *TempTag, error) {
	info, err := dataTmp.Stat()
	if err != nil {
		dataTmp.Close()
		return Hash{}, nil, fmt.Errorf("blobs: stat import data: %w", err)
	}
	outTmp, err := os.CreateTemp(s.baoDir, importOutboardTempPrefix+"*")
	if err != nil {
		dataTmp.Close()
		return Hash{}, nil, fmt.Errorf("blobs: create import outboard: %w", err)
	}
	defer removeTemp(outTmp.Name())

	root, err := bao.Encode(outTmp, dataTmp, info.Size(), 4, true)
	if err != nil {
		outTmp.Close()
		dataTmp.Close()
		return Hash{}, nil, fmt.Errorf("blobs: encode import outboard: %w", err)
	}
	hash := Hash(root)
	if syncData {
		if err := dataTmp.Sync(); err != nil {
			outTmp.Close()
			dataTmp.Close()
			return Hash{}, nil, fmt.Errorf("blobs: sync import data: %w", err)
		}
	}
	if err := outTmp.Sync(); err != nil {
		outTmp.Close()
		dataTmp.Close()
		return Hash{}, nil, fmt.Errorf("blobs: sync import outboard: %w", err)
	}
	if err := dataTmp.Close(); err != nil {
		outTmp.Close()
		return Hash{}, nil, fmt.Errorf("blobs: close import data: %w", err)
	}
	if err := outTmp.Close(); err != nil {
		return Hash{}, nil, fmt.Errorf("blobs: close import outboard: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Hash{}, nil, ErrStoreClosed
	}
	if !fileExists(s.dataPath(hash)) || !fileExists(s.outboardPath(hash)) {
		if err := os.Rename(dataTmp.Name(), s.dataPath(hash)); err != nil {
			return Hash{}, nil, fmt.Errorf("blobs: install import data: %w", err)
		}
		if err := os.Rename(outTmp.Name(), s.outboardPath(hash)); err != nil {
			_ = os.Remove(s.dataPath(hash))
			return Hash{}, nil, fmt.Errorf("blobs: install import outboard: %w", err)
		}
	}
	// Tag last, after every path that can fail. Creating it earlier would leave
	// an entry in s.temp that nothing could release: the caller gets no handle
	// on an error, and TempTag.Close takes s.mu, so it cannot be closed from
	// here either. Atomicity is unaffected, since holding s.mu across the
	// installs and the tag is the whole of the argument.
	var tag *TempTag
	if protect {
		tag = s.newTempTagLocked(RawHash(hash))
	}
	return hash, tag, nil
}

// importTempPrefix and importOutboardTempPrefix name in-flight import and write
// temporaries. They must not parse as a [Hash]: [FSStore.GC] walks the data
// directory and skips names that [ParseHash] rejects, which is what keeps
// uncommitted content alive.
const (
	importTempPrefix         = ".import-data-"
	importOutboardTempPrefix = ".import-outboard-"
)

func removeTemp(name string) {
	_ = os.Remove(name)
}

func fileExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
