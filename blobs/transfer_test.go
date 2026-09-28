package blobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

func TestSingleLeafTransfer(t *testing.T) {
	data := []byte("hello single leaf")
	hash := NewHash(data)
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeSingleLeaf(context.Background(), server, mustStore(t, data))
	}()
	got, err := GetSingleLeaf(context.Background(), client, hash)
	if err != nil {
		t.Fatalf("GetSingleLeaf: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("GetSingleLeaf = %q, want %q", got, data)
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeSingleLeaf: %v", err)
	}
}

func TestBlobTransfer(t *testing.T) {
	data := vectorData(BlockSize + 1)
	hash := NewHash(data)
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, mustStore(t, data))
	}()
	got, err := GetBlobBytes(context.Background(), client, hash)
	if err != nil {
		t.Fatalf("GetBlobBytes: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("GetBlobBytes returned %d bytes, want %d", len(got), len(data))
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestDownloadBlobStreamsToWriter(t *testing.T) {
	data := vectorData(2*BlockSize + 123)
	hash := NewHash(data)
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, mustStore(t, data))
	}()

	var got bytes.Buffer
	if err := DownloadBlob(context.Background(), client, hash, &got); err != nil {
		t.Fatalf("DownloadBlob: %v", err)
	}
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("DownloadBlob wrote %d bytes, want %d", got.Len(), len(data))
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestDownloadBlobValidationError(t *testing.T) {
	hash := NewHash([]byte("expected"))
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		_, _ = io.ReadAll(server)
		_, encoded, encErr := EncodeBlob([]byte("other"))
		if encErr != nil {
			errc <- encErr
			return
		}
		_, err := server.Write(encoded)
		if closeErr := server.Close(); err == nil {
			err = closeErr
		}
		errc <- err
	}()

	err := DownloadBlob(context.Background(), client, hash, io.Discard)
	if !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("DownloadBlob validation error = %v, want %v", err, ErrInvalidBlob)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server write: %v", err)
	}
}

func TestBlobRangeTransfer(t *testing.T) {
	data := vectorData(3*BlockSize + 321)
	hash := NewHash(data)
	tests := []struct {
		name   string
		ranges ChunkRanges
		want   []byte
	}{
		{name: "prefix", ranges: RangeChunks(0, 2), want: data[:2*ChunkSize]},
		{name: "suffix resume", ranges: openRangeForTest(2), want: data[2*ChunkSize:]},
		{name: "last partial chunk", ranges: RangeChunks(48, 50), want: data[48*ChunkSize:]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := newTestBidiStreamPair()
			errc := make(chan error, 1)
			go func() {
				errc <- ServeBlob(context.Background(), server, mustStore(t, data))
			}()
			got, err := GetBlobRangeBytes(context.Background(), client, hash, tt.ranges, uint64(len(data)))
			if err != nil {
				t.Fatalf("GetBlobRangeBytes: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("GetBlobRangeBytes returned %d bytes, want %d", len(got), len(tt.want))
			}
			if err := <-errc; err != nil {
				t.Fatalf("ServeBlob: %v", err)
			}
		})
	}
}

func TestDownloadBlobRangeResume(t *testing.T) {
	data := vectorData(3*BlockSize + 123)
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	const resumeAt = BlockSize + 2*ChunkSize
	var got bytes.Buffer
	downloadRange := func(offset, length uint64) {
		t.Helper()
		client, server := newTestBidiStreamPair()
		errc := make(chan error, 1)
		go func() {
			errc <- ServeBlob(context.Background(), server, store)
		}()
		if err := DownloadBlobRange(context.Background(), client, hash, offset, length, &got); err != nil {
			t.Fatalf("DownloadBlobRange(%d, %d): %v", offset, length, err)
		}
		if err := <-errc; err != nil {
			t.Fatalf("ServeBlob: %v", err)
		}
	}

	downloadRange(0, resumeAt)
	downloadRange(resumeAt, uint64(len(data)-resumeAt))
	if !bytes.Equal(got.Bytes(), data) {
		t.Fatalf("resumed download wrote %d bytes, want %d", got.Len(), len(data))
	}
	if NewHash(got.Bytes()) != hash {
		t.Fatal("resumed download hash mismatch")
	}
}

func TestDownloadBlobParallel(t *testing.T) {
	data := vectorData(6*BlockSize + 333)
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	const rangeSize = 2 * BlockSize
	out := newTestWriterAt(len(data))
	errc := make(chan error, 8)
	open := func(ctx context.Context) (BidiStream, error) {
		client, server := newTestBidiStreamPair()
		go func() {
			errc <- ServeBlob(ctx, server, store)
		}()
		return client, nil
	}
	err = DownloadBlobParallel(context.Background(), open, hash, out, ParallelDownloadOptions{
		Size:        uint64(len(data)),
		RangeSize:   rangeSize,
		Parallelism: 3,
		Retries:     1,
	})
	if err != nil {
		t.Fatalf("DownloadBlobParallel: %v", err)
	}
	for range 4 {
		if err := <-errc; err != nil {
			t.Fatalf("ServeBlob: %v", err)
		}
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("parallel download wrote %d bytes, want %d", len(out.Bytes()), len(data))
	}
	if NewHash(out.Bytes()) != hash {
		t.Fatal("parallel download hash mismatch")
	}
}

func TestDownloadBlobParallelRetriesRange(t *testing.T) {
	data := vectorData(2*BlockSize + 1)
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	out := newTestWriterAt(len(data))
	errc := make(chan error, 2)
	var calls atomic.Int32
	open := func(ctx context.Context) (BidiStream, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("temporary open failure")
		}
		client, server := newTestBidiStreamPair()
		go func() {
			errc <- ServeBlob(ctx, server, store)
		}()
		return client, nil
	}
	err = DownloadBlobParallel(context.Background(), open, hash, out, ParallelDownloadOptions{
		Size:        uint64(len(data)),
		RangeSize:   4 * BlockSize,
		Parallelism: 1,
		Retries:     1,
	})
	if err != nil {
		t.Fatalf("DownloadBlobParallel: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("retry download data mismatch")
	}
}

func TestBlobRangeTransferRejectsDisjointRanges(t *testing.T) {
	data := vectorData(BlockSize)
	hash := NewHash(data)
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, mustStore(t, data))
	}()
	ranges := ChunkRanges{ranges: []ChunkRange{{Start: 0, End: 1}, {Start: 3, End: 4}}}
	if _, err := client.Write(EncodeGetRequestBytes(GetBlobRanges(hash, ranges))); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrUnsupportedRequest) {
		t.Fatalf("ServeBlob disjoint range error = %v, want %v", err, ErrUnsupportedRequest)
	}
}

func TestObserveTransfer(t *testing.T) {
	data := vectorData(3*ChunkSize + 17)
	hash := NewHash(data)
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, mustStore(t, data))
	}()

	var got []Bitfield
	for bitfield, err := range Observe(context.Background(), client, hash) {
		if err != nil {
			t.Fatalf("Observe: %v", err)
		}
		got = append(got, bitfield)
	}
	if len(got) != 1 {
		t.Fatalf("Observe yielded %d updates, want 1", len(got))
	}
	if got[0].Size() != uint64(len(data)) || !got[0].IsComplete() {
		t.Fatalf("Observe = size %d complete %v", got[0].Size(), got[0].IsComplete())
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func openRangeForTest(start uint64) ChunkRanges {
	return ChunkRanges{open: &start}
}

func TestGetManyBlobTransfer(t *testing.T) {
	data := [][]byte{
		[]byte("first blob"),
		vectorData(BlockSize + 1),
		[]byte("third blob"),
	}
	var hashes []Hash
	blobs := make(map[Hash][]byte)
	for _, b := range data {
		hash := NewHash(b)
		hashes = append(hashes, hash)
		blobs[hash] = append([]byte(nil), b...)
	}

	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, mustStore(t, blobValues(blobs)...))
	}()
	got, err := GetManyBlobBytes(context.Background(), client, hashes)
	if err != nil {
		t.Fatalf("GetManyBlobBytes: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("GetManyBlobBytes returned %d blobs, want %d", len(got), len(data))
	}
	for i := range data {
		if !bytes.Equal(got[i], data[i]) {
			t.Fatalf("blob %d length = %d, want %d", i, len(got[i]), len(data[i]))
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestGetHashSequenceBytes(t *testing.T) {
	data := [][]byte{
		[]byte("first child"),
		vectorData(BlockSize + 1),
		[]byte("third child"),
	}
	var hashes []Hash
	blobs := make(map[Hash][]byte)
	for _, b := range data {
		hash := NewHash(b)
		hashes = append(hashes, hash)
		blobs[hash] = append([]byte(nil), b...)
	}
	seq := NewHashSequence(hashes)
	root := NewHash(seq.Bytes())
	blobs[root] = seq.Bytes()

	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, mustStore(t, blobValues(blobs)...))
	}()
	gotSeq, got, err := GetHashSequenceBytes(context.Background(), client, root)
	if err != nil {
		t.Fatalf("GetHashSequenceBytes: %v", err)
	}
	if gotSeq.Len() != len(hashes) {
		t.Fatalf("hash seq len = %d, want %d", gotSeq.Len(), len(hashes))
	}
	for i, want := range hashes {
		h, ok := gotSeq.At(i)
		if !ok || h != want {
			t.Fatalf("hash %d = %s, %v, want %s, true", i, h, ok, want)
		}
	}
	if len(got) != len(data) {
		t.Fatalf("GetHashSequenceBytes returned %d blobs, want %d", len(got), len(data))
	}
	for i := range data {
		if !bytes.Equal(got[i], data[i]) {
			t.Fatalf("blob %d length = %d, want %d", i, len(got[i]), len(data[i]))
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestServeSingleLeafErrors(t *testing.T) {
	hash := NewHash([]byte("missing"))
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeSingleLeaf(context.Background(), server, mustStore(t))
	}()
	if _, err := client.Write(EncodeGetRequestBytes(GetBlob(hash))); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("ServeSingleLeaf missing error = %v, want %v", err, ErrBlobNotFound)
	}

	client, server = newTestBidiStreamPair()
	errc = make(chan error, 1)
	go func() {
		errc <- ServeSingleLeaf(context.Background(), server, mustStore(t))
	}()
	if _, err := client.Write(EncodeGetRequestBytes(GetAll(hash))); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrUnsupportedRequest) {
		t.Fatalf("ServeSingleLeaf unsupported error = %v, want %v", err, ErrUnsupportedRequest)
	}
}

func TestGetSingleLeafValidation(t *testing.T) {
	hash := NewHash([]byte("expected"))
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		_, _ = io.ReadAll(server)
		_, err := server.Write([]byte{1, 2, 3})
		if closeErr := server.Close(); err == nil {
			err = closeErr
		}
		errc <- err
	}()
	_, err := GetSingleLeaf(context.Background(), client, hash)
	if !errors.Is(err, ErrInvalidSingleLeaf) {
		t.Fatalf("GetSingleLeaf validation error = %v, want %v", err, ErrInvalidSingleLeaf)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server write: %v", err)
	}
}

type testBidiStream struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newTestBidiStreamPair() (*testBidiStream, *testBidiStream) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return &testBidiStream{r: br, w: aw}, &testBidiStream{r: ar, w: bw}
}

func (s *testBidiStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *testBidiStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *testBidiStream) Close() error                { return s.w.Close() }
func (s *testBidiStream) CloseWrite() error           { return s.w.Close() }

type testWriterAt struct {
	mu sync.Mutex
	b  []byte
}

func newTestWriterAt(n int) *testWriterAt {
	return &testWriterAt{b: make([]byte, n)}
}

func (w *testWriterAt) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if off < 0 || int(off)+len(p) > len(w.b) {
		return 0, io.ErrShortWrite
	}
	return copy(w.b[off:], p), nil
}

func (w *testWriterAt) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.b...)
}

// mustStore returns an in-memory store holding data.
func mustStore(t *testing.T, data ...[]byte) *MemStore {
	t.Helper()
	m, err := NewMemStore(data...)
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	return m
}

func blobValues(m map[Hash][]byte) [][]byte {
	out := make([][]byte, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestDownloadTrailingBytesBounded(t *testing.T) {
	data := vectorData(3*BlockSize + 321)
	hash, encoded, err := EncodeBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	_, rangeEncoded, err := EncodeBlobRange(data, ChunkSize, ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	seq := NewHashSequence([]Hash{hash})
	rootHash, rootEncoded, err := EncodeBlob(seq.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		resp []byte
		call func(context.Context, BidiStream) error
	}{
		{
			name: "DownloadBlob",
			resp: encoded,
			call: func(ctx context.Context, s BidiStream) error {
				return DownloadBlob(ctx, s, hash, io.Discard)
			},
		},
		{
			name: "DownloadBlobRange",
			resp: rangeEncoded,
			call: func(ctx context.Context, s BidiStream) error {
				return DownloadBlobRange(ctx, s, hash, ChunkSize, ChunkSize, io.Discard)
			},
		},
		{
			name: "GetManyBlobBytes",
			resp: encoded,
			call: func(ctx context.Context, s BidiStream) error {
				_, err := GetManyBlobBytes(ctx, s, []Hash{hash})
				return err
			},
		},
		{
			name: "GetHashSequenceBytes",
			resp: append(append([]byte(nil), rootEncoded...), encoded...),
			call: func(ctx context.Context, s BidiStream) error {
				_, _, err := GetHashSequenceBytes(ctx, s, rootHash)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &trailingStream{resp: tt.resp, limit: 32 << 20}
			if err := tt.call(context.Background(), s); !errors.Is(err, ErrInvalidBlob) {
				t.Fatalf("%s trailing error = %v, want %v", tt.name, err, ErrInvalidBlob)
			}
			if s.trailing > 4096 {
				t.Fatalf("%s read %d trailing bytes, want at most 4096", tt.name, s.trailing)
			}
		})
	}
}

// trailingStream is a hostile provider: it serves a valid response and then
// keeps sending, up to limit bytes, counting what the client reads past resp.
type trailingStream struct {
	resp     []byte
	limit    int
	trailing int
}

func (s *trailingStream) Read(p []byte) (int, error) {
	if len(s.resp) > 0 {
		n := copy(p, s.resp)
		s.resp = s.resp[n:]
		return n, nil
	}
	if s.trailing >= s.limit {
		return 0, io.EOF
	}
	n := min(len(p), s.limit-s.trailing)
	clear(p[:n])
	s.trailing += n
	return n, nil
}

func (s *trailingStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *trailingStream) Close() error                { return nil }

func TestServeRequestTooLarge(t *testing.T) {
	data := []byte("hello")
	valid := EncodeGetRequestBytes(GetBlob(NewHash(data)))
	tests := []struct {
		name   string
		serve  func(context.Context, BidiStream, Store) error
		prefix []byte
	}{
		{"ServeBlob/zeros", ServeBlob, nil},
		{"ServeBlob/valid then zeros", ServeBlob, valid},
		{"ServeSingleLeaf/zeros", ServeSingleLeaf, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A request that never ends, cut off far past any sane bound so an
			// unbounded read fails the test instead of the machine.
			s := &trailingStream{resp: tt.prefix, limit: 64 << 20}
			err := tt.serve(context.Background(), s, mustStore(t, data))
			if !errors.Is(err, ErrRequestTooLarge) {
				t.Fatalf("serve error = %v, want %v", err, ErrRequestTooLarge)
			}
			if s.trailing > MaxRequestSize+64<<10 {
				t.Fatalf("server read %d bytes, want at most about %d", s.trailing, MaxRequestSize)
			}
		})
	}
}
