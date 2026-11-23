package blobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lukechampine.com/blake3/bao"
)

func TestFSStorePersistsBlob(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte("persistent blob"), 2000)

	store, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	reopened, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen NewFSStore: %v", err)
	}
	status, err := reopened.BlobStatus(context.Background(), hash)
	if err != nil {
		t.Fatalf("BlobStatus: %v", err)
	}
	if !status.IsComplete() || status.Size != int64(len(data)) {
		t.Fatalf("BlobStatus = %+v, want complete size %d", status, len(data))
	}
	got, err := ReadBlob(context.Background(), reopened, hash)
	if err != nil {
		t.Fatalf("ReadBlob: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("ReadBlob data mismatch")
	}

	entry, err := reopened.Open(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	r, err := entry.DataReader(context.Background())
	if err != nil {
		t.Fatalf("DataReader: %v", err)
	}
	buf := make([]byte, len(data))
	if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt data: %v", err)
	}
	if !bytes.Equal(buf, data) {
		t.Fatal("DataReader data mismatch")
	}
	outboard, err := entry.Outboard(context.Background())
	if err != nil {
		t.Fatalf("Outboard: %v", err)
	}
	out := make([]byte, outboard.Size())
	if _, err := outboard.ReadAt(out, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt outboard: %v", err)
	}
	if !bao.VerifyBuf(data, out, 4, hash.Bytes()) {
		t.Fatal("outboard does not verify data")
	}
}

func TestFSStoreServesBlob(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := []byte("serve persistent blob")
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, store)
	}()
	got, err := GetBlobBytes(context.Background(), client, hash)
	if err != nil {
		t.Fatalf("GetBlobBytes: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("transfer = %q, want %q", got, data)
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestFSStoreImportFileCopy(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := bytes.Repeat([]byte("import file copy"), 4096)
	path := writeTempBlobFile(t, data)

	hash, err := store.ImportFile(path, ImportCopy)
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if want := NewHash(data); hash != want {
		t.Fatalf("ImportFile hash = %s, want %s", hash, want)
	}
	got, err := ReadBlob(context.Background(), store, hash)
	if err != nil {
		t.Fatalf("ReadBlob: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("ReadBlob data mismatch")
	}
}

func TestFSStoreImportFileTryReference(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := bytes.Repeat([]byte("import file reference"), 4096)
	path := writeTempBlobFile(t, data)

	hash, err := store.ImportFile(path, ImportTryReference)
	if err != nil {
		t.Fatalf("ImportFile: %v", err)
	}
	if want := NewHash(data); hash != want {
		t.Fatalf("ImportFile hash = %s, want %s", hash, want)
	}
	got, err := ReadBlob(context.Background(), store, hash)
	if err != nil {
		t.Fatalf("ReadBlob: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("ReadBlob data mismatch")
	}
}

func TestFSStoreHonorsCanceledContext(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add([]byte("x"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Open(ctx, hash); err == nil {
		t.Fatal("Get canceled context error = nil")
	}
}

func writeTempBlobFile(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "blob.data")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestGCKeepsUncommittedBlob pins the invariant that FSStore.NewBlob relies on:
// an in-flight blob has no hash yet, so no tag can protect it, and GC must skip
// it because its temporary name does not parse as a Hash.
func TestGCKeepsUncommittedBlob(t *testing.T) {
	ctx := context.Background()
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	w, err := store.NewBlob(ctx)
	if err != nil {
		t.Fatalf("NewBlob: %v", err)
	}
	defer w.Close()
	data := []byte("still being written")
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if _, err := store.GC(ctx); err != nil {
		t.Fatalf("GC: %v", err)
	}

	tag, err := w.Commit()
	if err != nil {
		t.Fatalf("Commit after GC: %v", err)
	}
	defer tag.Close()
	got, err := ReadBlob(ctx, store, tag.Hash())
	if err != nil {
		t.Fatalf("ReadBlob: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("blob = %q, want %q", got, data)
	}
}

// TestCloseAfterCommitIsNoop pins the database/sql.Tx contract documented on
// BlobWriter: defer w.Close() is correct whether or not Commit is reached.
func TestCloseAfterCommitIsNoop(t *testing.T) {
	ctx := context.Background()
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	w, err := store.NewBlob(ctx)
	if err != nil {
		t.Fatalf("NewBlob: %v", err)
	}
	data := []byte("committed")
	if _, err := w.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	tag, err := w.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	defer tag.Close()
	if err := w.Close(); err != nil {
		t.Fatalf("Close after Commit = %v, want nil", err)
	}
	if _, err := ReadBlob(ctx, store, tag.Hash()); err != nil {
		t.Fatalf("blob gone after Close: %v", err)
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("leftover temp file in %s: %s", dir, e.Name())
		}
	}
}

func TestFSStoreTempFileCleanupOnCancelAndFailure(t *testing.T) {
	ctx := context.Background()
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	// 1. Cancelled NewBlob (Close without Commit) leaves no temp files.
	w, err := store.NewBlob(ctx)
	if err != nil {
		t.Fatalf("NewBlob: %v", err)
	}
	if _, err := w.Write([]byte("cancelled import")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertNoTempFiles(t, store.dataDir)
	assertNoTempFiles(t, store.baoDir)

	// 2. Failed Commit removes its temp files even if Close is not called.
	data := []byte("failing commit")
	hash := NewHash(data)
	if err := os.MkdirAll(store.outboardPath(hash), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	w2, err := store.NewBlob(ctx)
	if err != nil {
		t.Fatalf("NewBlob: %v", err)
	}
	if _, err := w2.Write(data); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := w2.Commit(); err == nil {
		t.Fatal("Commit succeeded, want error")
	}
	assertNoTempFiles(t, store.dataDir)
	assertNoTempFiles(t, store.baoDir)

	// 3. Failed ImportFile (nonexistent source) leaves no temp files.
	if _, err := store.ImportFile(filepath.Join(t.TempDir(), "missing"), ImportCopy); err == nil {
		t.Fatal("ImportFile(missing) succeeded, want error")
	}
	assertNoTempFiles(t, store.dataDir)
	assertNoTempFiles(t, store.baoDir)
}

func TestFSStoreOpenCleansLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := []byte("survives reopen")
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.SetTag("keep", RawHash(hash)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}

	// Simulate crash leftovers in data, outboard, and root directories.
	leftovers := []string{
		filepath.Join(store.dataDir, importTempPrefix+"crash1"),
		filepath.Join(store.dataDir, ".somehash.tmp-crash2"),
		filepath.Join(store.baoDir, importOutboardTempPrefix+"crash3"),
		filepath.Join(store.baoDir, ".somehash.tmp-crash4"),
		filepath.Join(store.dir, ".tags.json.tmp-crash5"),
	}
	for _, p := range leftovers {
		if err := os.WriteFile(p, []byte("junk"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s): %v", p, err)
		}
	}

	reopened, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen NewFSStore: %v", err)
	}
	for _, p := range leftovers {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("leftover %s still exists after reopen (err=%v)", p, err)
		}
	}
	got, err := ReadBlob(context.Background(), reopened, hash)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("ReadBlob after reopen = %q, %v; want %q", got, err, data)
	}
	if _, ok, err := reopened.Tag("keep"); err != nil || !ok {
		t.Fatalf("Tag(keep) after reopen = %v, %v; want present", ok, err)
	}
}

func TestFSStoreRequestsAfterCloseDoNotPanic(t *testing.T) {
	ctx := context.Background()
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := vectorData(2*BlockSize + 17)
	complete, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	unknown := NewHash([]byte("unknown"))
	opened, err := store.Open(ctx, complete)
	if err != nil {
		t.Fatalf("Open before Close: %v", err)
	}
	tag, err := store.NewTempTag(RawHash(complete))
	if err != nil {
		t.Fatalf("NewTempTag: %v", err)
	}
	w, err := store.NewBlob(ctx)
	if err != nil {
		t.Fatalf("NewBlob before Close: %v", err)
	}
	if _, err := w.Write([]byte("in-flight")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	// Closing a previously acquired TempTag after store.Close must not panic.
	if err := tag.Close(); err != nil {
		t.Fatalf("TempTag.Close after store.Close: %v", err)
	}
	// Committing an in-flight writer after store.Close must fail cleanly and leave no temp file.
	if _, err := w.Commit(); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Commit after Close = %v, want %v", err, ErrStoreClosed)
	}
	assertNoTempFiles(t, store.dataDir)
	assertNoTempFiles(t, store.baoDir)

	if _, err := store.Add([]byte("x")); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Add after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := store.NewBlob(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("NewBlob after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := store.ImportFile(writeTempBlobFile(t, []byte("x")), ImportCopy); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("ImportFile after Close = %v, want %v", err, ErrStoreClosed)
	}
	if err := store.SetTag("t", RawHash(complete)); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("SetTag after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, _, err := store.Tag("t"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Tag after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := store.DeleteTag("t"); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("DeleteTag after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := store.Tags(); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("Tags after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := store.NewTempTag(RawHash(complete)); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("NewTempTag after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := store.GC(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("GC after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := opened.DataReader(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("opened.DataReader after Close = %v, want %v", err, ErrStoreClosed)
	}
	if _, err := opened.Outboard(ctx); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("opened.Outboard after Close = %v, want %v", err, ErrStoreClosed)
	}

	for _, hash := range []Hash{complete, unknown, EmptyHash} {
		if _, err := store.Open(ctx, hash); !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("Open(%s) after Close = %v, want %v", hash, err, ErrStoreClosed)
		}
		if _, err := store.BlobStatus(ctx, hash); !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("BlobStatus(%s) after Close = %v, want %v", hash, err, ErrStoreClosed)
		}

		// ServeBlob Get and Observe requests after Close return ErrStoreClosed cleanly.
		client, server := newTestBidiStreamPair()
		errc := make(chan error, 1)
		go func() { errc <- ServeBlob(ctx, server, store) }()
		_, _ = client.Write(EncodeGetRequestBytes(GetBlob(hash)))
		_ = client.CloseWrite()
		_, _ = io.ReadAll(client)
		if err := <-errc; !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("ServeBlob(Get %s) after Close = %v, want %v", hash, err, ErrStoreClosed)
		}

		client, server = newTestBidiStreamPair()
		errc = make(chan error, 1)
		go func() { errc <- ServeBlob(ctx, server, store) }()
		_, _ = client.Write(EncodeObserveRequestBytes(ObserveBlob(hash)))
		_ = client.CloseWrite()
		_, _ = io.ReadAll(client)
		if err := <-errc; !errors.Is(err, ErrStoreClosed) {
			t.Fatalf("ServeBlob(Observe %s) after Close = %v, want %v", hash, err, ErrStoreClosed)
		}
	}
}

func TestFSStoreGCRemovesOrphanedOutboard(t *testing.T) {
	ctx := context.Background()
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	orphanHash := NewHash([]byte("orphan"))
	orphanPath := store.outboardPath(orphanHash)
	if err := os.WriteFile(orphanPath, []byte("stale outboard"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := store.GC(ctx); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, err := os.Stat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan outboard %s still exists after GC (err=%v)", orphanPath, err)
	}
}
