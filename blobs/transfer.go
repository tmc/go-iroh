package blobs

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"sync"
)

// BidiStream is the stream shape used by the blob transfer helpers.
//
// If a stream implements CloseWrite, the helpers use it to close the send side.
// Otherwise Close must close the send side while still allowing reads from the
// peer. This matches iroh.Stream. A net.Conn, whose Close closes both
// directions and which does not implement CloseWrite, is not a suitable
// BidiStream for these helpers.
//
// If a stream implements CancelRead(code uint64), as iroh.Stream does, the
// helpers call it to abandon a response when their context ends. Otherwise a
// helper still returns when its context ends, but leaves a goroutine blocked
// in Read until the stream fails; the helper stops writing to the caller's
// writer before it returns.
type BidiStream interface {
	io.Reader
	io.Writer
	Close() error
}

// AcceptBlobStream accepts the next bidirectional stream from a blob client.
type AcceptBlobStream func(context.Context) (BidiStream, error)

var (
	// ErrBlobNotFound is returned when a requested blob is not in a store.
	ErrBlobNotFound = errors.New("blobs: blob not found")
	// ErrStoreReadOnly is returned when a store cannot accept new blobs.
	ErrStoreReadOnly = errors.New("blobs: store cannot add content")
	// ErrUnsupportedRequest is returned when a request is outside the
	// raw-blob transfer subset.
	ErrUnsupportedRequest = errors.New("blobs: unsupported request")
	// ErrRequestTooLarge is returned when a request is longer than
	// [MaxRequestSize].
	ErrRequestTooLarge = errors.New("blobs: request too large")
)

// MaxRequestSize is the largest request a server reads, as in iroh-blobs.
const MaxRequestSize = 1 << 20

// ServeBlob serves one full-range raw blob request on s.
//
// The client must send a full [RequestGet] request, then close its send side.
// ServeBlob writes the full-range BAO response, or the hash-sequence root and
// children for [GetAll], and closes its send side. A request longer than
// [MaxRequestSize] fails with [ErrRequestTooLarge].
func ServeBlob(ctx context.Context, s BidiStream, store Store) error {
	return serveBlob(ctx, s, store, false, true)
}

// ServeBlobStreams serves blob requests from streams accepted by accept.
//
// ServeBlobStreams accepts streams until accept returns an error or ctx is
// canceled, and then waits for the streams it is serving. Each accepted stream
// is served concurrently with [ServeBlob]; an error serving one stream ends
// only that stream. ServeBlobStreams returns nil when ctx is done or when the
// accept error matches [net.ErrClosed], as the close errors of an iroh
// connection do, and returns any other accept error.
func ServeBlobStreams(ctx context.Context, accept AcceptBlobStream, store Store) error {
	if accept == nil {
		return errors.New("blobs: nil stream accepter")
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancel(ctxOrBackground(ctx))
	defer cancel()
	for {
		s, err := accept(ctx)
		if err != nil {
			// accept fails when the connection closes, which is how
			// serving normally ends.
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("blobs: accept stream: %w", err)
		}
		wg.Go(func() { _ = ServeBlob(ctx, s, store) })
	}
}

// ServeSingleLeaf serves one single-leaf raw blob request on s.
//
// The client must send a full [RequestGet] / [GetBlob] request, then close its
// send side. ServeSingleLeaf writes the single-leaf BAO response and closes its
// send side. Blobs larger than [MaxSingleLeafSize] are rejected.
func ServeSingleLeaf(ctx context.Context, s BidiStream, store Store) error {
	return serveBlob(ctx, s, store, true, false)
}

func serveBlob(ctx context.Context, s BidiStream, store Store, singleLeaf, hashSeq bool) error {
	if store == nil {
		return errors.New("blobs: nil blob store")
	}
	requestBytes, err := readAllContext(ctx, s, MaxRequestSize+1)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("blobs: read request: %w", err)
	}
	if len(requestBytes) > MaxRequestSize {
		_ = s.Close()
		return ErrRequestTooLarge
	}
	req, err := DecodeRequestBytes(requestBytes)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("blobs: decode request: %w", err)
	}
	switch req.Type {
	case RequestGet:
		if req.Get == nil {
			_ = s.Close()
			return ErrUnsupportedRequest
		}
		if !hashSeq && !req.Get.Ranges.IsBlob() {
			_ = s.Close()
			return ErrUnsupportedRequest
		}
		if err := writeGet(ctx, s, store, *req.Get, singleLeaf); err != nil {
			_ = s.Close()
			return err
		}
	case RequestGetMany:
		if req.GetMany == nil {
			_ = s.Close()
			return ErrUnsupportedRequest
		}
		for i, hash := range req.GetMany.Hashes {
			ranges := req.GetMany.Ranges.At(uint64(i))
			if ranges.IsEmpty() {
				continue
			}
			if !ranges.IsAll() {
				_ = s.Close()
				return ErrUnsupportedRequest
			}
			if err := writeBlob(ctx, s, store, hash, singleLeaf); err != nil {
				_ = s.Close()
				return err
			}
		}
	case RequestObserve:
		if req.Observe == nil {
			_ = s.Close()
			return ErrUnsupportedRequest
		}
		if err := writeObserve(ctx, s, store, *req.Observe); err != nil {
			_ = s.Close()
			return err
		}
	default:
		_ = s.Close()
		return ErrUnsupportedRequest
	}
	return closeWrite(s)
}

func writeObserve(ctx context.Context, s io.Writer, store Store, req ObserveRequest) error {
	blob, err := store.Open(ctx, req.Hash)
	if err != nil {
		return err
	}
	size, verified := blob.Size()
	if !blob.IsComplete() || !verified {
		return ErrBlobNotFound
	}
	b := CompleteBitfield(size)
	if !req.Ranges.IsAll() {
		b = NewBitfield(size, req.Ranges.ChunkRanges())
	}
	return writeObserveItem(s, b)
}

func writeGet(ctx context.Context, s io.Writer, store Store, req GetRequest, singleLeaf bool) error {
	if req.Ranges.IsBlob() {
		return writeBlob(ctx, s, store, req.Hash, singleLeaf)
	}
	if !req.Ranges.IsAll() {
		return writeBlobRange(ctx, s, store, req.Hash, req.Ranges.At(0))
	}
	root, err := ReadBlob(ctx, store, req.Hash)
	if err != nil {
		return err
	}
	seq, err := ParseHashSequence(root)
	if err != nil {
		return fmt.Errorf("blobs: parse hash sequence: %w", err)
	}
	if err := writeBlobBytes(s, req.Hash, root, encoderFor(singleLeaf)); err != nil {
		return err
	}
	for _, hash := range seq.hashes {
		if err := writeBlob(ctx, s, store, hash, singleLeaf); err != nil {
			return err
		}
	}
	return nil
}

func encoderFor(singleLeaf bool) func([]byte) (Hash, []byte, error) {
	if singleLeaf {
		return EncodeSingleLeaf
	}
	return EncodeBlob
}

// writeBlob streams the full-range BAO response for hash.
//
// A full-range response is byte-identical to a range response covering the
// whole blob, so this shares the one streaming path with writeBlobRange and
// never holds the blob in memory.
func writeBlob(ctx context.Context, s io.Writer, store Store, hash Hash, singleLeaf bool) error {
	blob, err := store.Open(ctx, hash)
	if err != nil {
		return err
	}
	size, verified := blob.Size()
	if !blob.IsComplete() || !verified {
		return ErrBlobNotFound
	}
	if singleLeaf && size > MaxSingleLeafSize {
		return fmt.Errorf("%w: %d > %d", ErrSingleLeafTooLarge, size, MaxSingleLeafSize)
	}
	return extractRange(ctx, s, blob, 0, size)
}

func writeBlobRange(ctx context.Context, s io.Writer, store Store, hash Hash, ranges ChunkRanges) error {
	blob, err := store.Open(ctx, hash)
	if err != nil {
		return err
	}
	size, verified := blob.Size()
	if !blob.IsComplete() || !verified {
		return ErrBlobNotFound
	}
	offset, length, ok := singleByteRange(ranges, size)
	if !ok {
		return ErrUnsupportedRequest
	}
	return extractRange(ctx, s, blob, offset, length)
}

// extractRange streams [offset, offset+length) of blob to s as a BAO slice.
func extractRange(ctx context.Context, s io.Writer, blob Blob, offset, length uint64) error {
	size, _ := blob.Size()
	if size > maxInt64 {
		return ErrUnsupportedRequest
	}
	data, err := blob.DataReader(ctx)
	if err != nil {
		return fmt.Errorf("blobs: open data: %w", err)
	}
	defer data.Close()
	outboard, err := blob.Outboard(ctx)
	if err != nil {
		return fmt.Errorf("blobs: open outboard: %w", err)
	}
	defer outboard.Close()
	if outboard.Size() < 0 || uint64(outboard.Size()) > maxInt64 {
		return ErrUnsupportedRequest
	}
	dataSection := io.NewSectionReader(data, 0, int64(size))
	outboardSection := io.NewSectionReader(outboard, 0, outboard.Size())
	return ExtractBlobRange(s, dataSection, outboardSection, offset, length)
}

func checkedAdd(a, b uint64) (uint64, bool) {
	c := a + b
	return c, c >= a
}

const maxInt64 = uint64(1<<63 - 1)

func writeBlobBytes(s io.Writer, hash Hash, data []byte, encode func([]byte) (Hash, []byte, error)) error {
	got, encoded, err := encode(data)
	if err != nil {
		return err
	}
	if got != hash {
		return fmt.Errorf("blobs: stored blob hash mismatch")
	}
	if _, err := s.Write(encoded); err != nil {
		return fmt.Errorf("blobs: write response: %w", err)
	}
	return nil
}

// Observe requests bitfield updates for hash from s.
//
// Observe sends [ObserveBlob], closes its send side, and yields provider
// bitfield updates until the response stream ends.
func Observe(ctx context.Context, s BidiStream, hash Hash) iter.Seq2[Bitfield, error] {
	return func(yield func(Bitfield, error) bool) {
		if ctx == nil {
			ctx = context.Background()
		}
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				abort(s)
			case <-done:
			}
		}()
		defer close(done)

		if _, err := s.Write(EncodeObserveRequestBytes(ObserveBlob(hash))); err != nil {
			_ = s.Close()
			yield(Bitfield{}, fmt.Errorf("blobs: write observe request: %w", err))
			return
		}
		if err := closeWrite(s); err != nil {
			yield(Bitfield{}, fmt.Errorf("blobs: close observe request: %w", err))
			return
		}
		type item struct {
			bitfield Bitfield
			err      error
		}
		items := make(chan item)
		go func() {
			r := bufio.NewReader(s)
			for {
				bitfield, err := readObserveItem(r)
				select {
				case items <- item{bitfield, err}:
				case <-done:
					return
				}
				if err != nil {
					return
				}
			}
		}()
		for {
			var it item
			select {
			case it = <-items:
			case <-ctx.Done():
				yield(Bitfield{}, ctx.Err())
				return
			}
			if it.err == nil {
				if !yield(it.bitfield, nil) {
					abort(s)
					return
				}
				continue
			}
			if errors.Is(it.err, io.EOF) {
				return
			}
			if ctx.Err() != nil {
				yield(Bitfield{}, ctx.Err())
				return
			}
			yield(Bitfield{}, fmt.Errorf("blobs: read observe response: %w", it.err))
			return
		}
	}
}

// GetBlobBytes requests and validates one full-range raw blob from s.
//
// GetBlobBytes sends [GetBlob], closes its send side, reads the response, and
// verifies the returned BAO body against hash.
func GetBlobBytes(ctx context.Context, s BidiStream, hash Hash) ([]byte, error) {
	var out bytes.Buffer
	if err := DownloadBlob(ctx, s, hash, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DownloadBlob requests and validates one full-range raw blob from s.
//
// DownloadBlob sends [GetBlob], closes its send side, and streams the verified
// BAO response into w. It returns an error if the response hash does not match
// hash or if the peer sends trailing bytes after the blob.
func DownloadBlob(ctx context.Context, s BidiStream, hash Hash, w io.Writer) error {
	if w == nil {
		return errors.New("blobs: nil blob writer")
	}
	if _, err := s.Write(EncodeGetRequestBytes(GetBlob(hash))); err != nil {
		_ = s.Close()
		return fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return fmt.Errorf("blobs: close request: %w", err)
	}
	dw := &detachableWriter{w: w}
	errc := make(chan error, 1)
	go func() {
		if err := DecodeBlobToWriter(hash, s, dw); err != nil {
			errc <- fmt.Errorf("blobs: decode response: %w", err)
			return
		}
		if err := readTrailingByte(s); err != nil {
			errc <- err
			return
		}
		errc <- nil
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		abort(s)
		dw.detach()
		return ctx.Err()
	}
}

// GetBlobRangeBytes requests and validates a contiguous chunk range from s.
//
// size is the verified full blob size. The returned bytes are the selected
// range, clamped to size.
func GetBlobRangeBytes(ctx context.Context, s BidiStream, hash Hash, ranges ChunkRanges, size uint64) ([]byte, error) {
	offset, length, ok := singleByteRange(ranges, size)
	if !ok {
		return nil, ErrUnsupportedRequest
	}
	var out bytes.Buffer
	if err := DownloadBlobRange(ctx, s, hash, offset, length, &out); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DownloadBlobRange requests and validates [offset, offset+length) from hash.
//
// The request is encoded as iroh-blobs chunk ranges, so offset must start on a
// [ChunkSize] boundary. The final range may end inside the blob's last chunk.
func DownloadBlobRange(ctx context.Context, s BidiStream, hash Hash, offset, length uint64, w io.Writer) error {
	if w == nil {
		return errors.New("blobs: nil blob writer")
	}
	if length == 0 {
		return nil
	}
	if offset%ChunkSize != 0 {
		return fmt.Errorf("%w: range offset %d is not chunk-aligned", ErrUnsupportedRequest, offset)
	}
	end, ok := checkedAdd(offset, length)
	if !ok {
		return fmt.Errorf("%w: range [%d,%d) overflows", ErrUnsupportedRequest, offset, length)
	}
	startChunk := offset / ChunkSize
	endChunk := (end-1)/ChunkSize + 1
	req := GetBlobRanges(hash, RangeChunks(startChunk, endChunk))
	if _, err := s.Write(EncodeGetRequestBytes(req)); err != nil {
		_ = s.Close()
		return fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return fmt.Errorf("blobs: close request: %w", err)
	}
	dw := &detachableWriter{w: w}
	errc := make(chan error, 1)
	go func() {
		if err := DecodeBlobRangeToWriter(hash, s, offset, length, dw); err != nil {
			errc <- fmt.Errorf("blobs: decode response: %w", err)
			return
		}
		if err := readTrailingByte(s); err != nil {
			errc <- err
			return
		}
		errc <- nil
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		abort(s)
		dw.detach()
		return ctx.Err()
	}
}

// RangeOpener opens one bidirectional stream to a blob provider.
type RangeOpener func(context.Context) (BidiStream, error)

// ParallelDownloadOptions configures [DownloadBlobParallel].
type ParallelDownloadOptions struct {
	Size        uint64
	RangeSize   uint64
	Parallelism int
	Retries     int
}

// DownloadBlobParallel downloads hash as verified ranges in parallel.
//
// Each range is verified against hash before it is written to w. RangeSize must
// be a positive multiple of [ChunkSize]. Retries is the number of retries after
// the first attempt for each range.
func DownloadBlobParallel(ctx context.Context, open RangeOpener, hash Hash, w io.WriterAt, opts ParallelDownloadOptions) error {
	if open == nil {
		return errors.New("blobs: nil range opener")
	}
	if w == nil {
		return errors.New("blobs: nil blob writer")
	}
	if opts.Size == 0 {
		return nil
	}
	if opts.Size > maxInt64 {
		return ErrUnsupportedRequest
	}
	if opts.RangeSize == 0 {
		opts.RangeSize = 4 << 20
	}
	if opts.RangeSize%ChunkSize != 0 {
		return fmt.Errorf("%w: range size %d is not chunk-aligned", ErrUnsupportedRequest, opts.RangeSize)
	}
	if opts.Parallelism <= 0 {
		opts.Parallelism = 4
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}
	ranges, err := downloadRanges(opts.Size, opts.RangeSize)
	if err != nil {
		return err
	}
	if opts.Parallelism > len(ranges) {
		opts.Parallelism = len(ranges)
	}

	ctx, cancel := context.WithCancel(ctxOrBackground(ctx))
	defer cancel()
	jobs := make(chan downloadRange, len(ranges))
	for _, r := range ranges {
		jobs <- r
	}
	close(jobs)

	errc := make(chan error, 1)
	var wg sync.WaitGroup
	for range opts.Parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				if err := downloadRangeWithRetry(ctx, open, hash, w, r, opts.Retries); err != nil {
					select {
					case errc <- err:
						cancel()
					default:
					}
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		select {
		case err := <-errc:
			return err
		default:
			return nil
		}
	case err := <-errc:
		<-done
		return err
	case <-ctx.Done():
		<-done
		return ctx.Err()
	}
}

type downloadRange struct {
	offset uint64
	length uint64
}

func downloadRanges(size, rangeSize uint64) ([]downloadRange, error) {
	var ranges []downloadRange
	for offset := uint64(0); offset < size; {
		length := rangeSize
		if size-offset < length {
			length = size - offset
		}
		ranges = append(ranges, downloadRange{offset: offset, length: length})
		next, ok := checkedAdd(offset, length)
		if !ok {
			return nil, fmt.Errorf("%w: range offset overflow", ErrUnsupportedRequest)
		}
		offset = next
	}
	return ranges, nil
}

func downloadRangeWithRetry(ctx context.Context, open RangeOpener, hash Hash, w io.WriterAt, r downloadRange, retries int) error {
	var last error
	for attempt := 0; attempt <= retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := downloadRangeOnce(ctx, open, hash, w, r)
		if err == nil {
			return nil
		}
		last = err
	}
	return fmt.Errorf("blobs: download range [%d,%d): %w", r.offset, r.offset+r.length, last)
}

func downloadRangeOnce(ctx context.Context, open RangeOpener, hash Hash, w io.WriterAt, r downloadRange) error {
	s, err := open(ctx)
	if err != nil {
		return fmt.Errorf("open range stream: %w", err)
	}
	var buf bytes.Buffer
	err = DownloadBlobRange(ctx, s, hash, r.offset, r.length, &buf)
	_ = s.Close()
	if err != nil {
		return err
	}
	if uint64(buf.Len()) != r.length {
		return fmt.Errorf("%w: range [%d,%d) decoded %d bytes", ErrInvalidBlob, r.offset, r.offset+r.length, buf.Len())
	}
	n, err := w.WriteAt(buf.Bytes(), int64(r.offset))
	if err != nil {
		return fmt.Errorf("write verified range: %w", err)
	}
	if n != buf.Len() {
		return io.ErrShortWrite
	}
	return nil
}

// GetManyBlobBytes requests and validates full-range raw blobs from s.
func GetManyBlobBytes(ctx context.Context, s BidiStream, hashes []Hash) ([][]byte, error) {
	hashes = append([]Hash(nil), hashes...)
	if _, err := s.Write(EncodeGetManyRequestBytes(NewGetManyRequest(hashes, ChunkRangesSeqAll()))); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return nil, fmt.Errorf("blobs: close request: %w", err)
	}

	type result struct {
		data [][]byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data := make([][]byte, 0, len(hashes))
		for _, hash := range hashes {
			b, err := DecodeBlobReader(hash, s)
			if err != nil {
				done <- result{err: fmt.Errorf("blobs: decode response: %w", err)}
				return
			}
			data = append(data, b)
		}
		if err := readTrailingByte(s); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{data: data}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case res := <-done:
		return res.data, res.err
	case <-ctx.Done():
		abort(s)
		return nil, ctx.Err()
	}
}

// GetHashSequenceBytes requests a hash sequence and all of its child blobs from s.
func GetHashSequenceBytes(ctx context.Context, s BidiStream, root Hash) (HashSequence, [][]byte, error) {
	if _, err := s.Write(EncodeGetRequestBytes(GetAll(root))); err != nil {
		_ = s.Close()
		return HashSequence{}, nil, fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return HashSequence{}, nil, fmt.Errorf("blobs: close request: %w", err)
	}

	type result struct {
		seq  HashSequence
		data [][]byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		rootBytes, err := DecodeBlobReader(root, s)
		if err != nil {
			done <- result{err: fmt.Errorf("blobs: decode response: %w", err)}
			return
		}
		seq, err := ParseHashSequence(rootBytes)
		if err != nil {
			done <- result{err: fmt.Errorf("blobs: parse hash sequence: %w", err)}
			return
		}
		data := make([][]byte, 0, seq.Len())
		for _, hash := range seq.hashes {
			b, err := DecodeBlobReader(hash, s)
			if err != nil {
				done <- result{err: fmt.Errorf("blobs: decode response: %w", err)}
				return
			}
			data = append(data, b)
		}
		if err := readTrailingByte(s); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{seq: seq, data: data}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case res := <-done:
		return res.seq, res.data, res.err
	case <-ctx.Done():
		abort(s)
		return HashSequence{}, nil, ctx.Err()
	}
}

// GetSingleLeaf requests and validates one single-leaf raw blob from s.
//
// GetSingleLeaf sends [GetBlob], closes its send side, reads the response, and
// verifies the returned single-leaf BAO body against hash.
func GetSingleLeaf(ctx context.Context, s BidiStream, hash Hash) ([]byte, error) {
	return getBlob(ctx, s, hash, DecodeSingleLeaf)
}

func getBlob(ctx context.Context, s BidiStream, hash Hash, decode func(Hash, []byte) ([]byte, error)) ([]byte, error) {
	if _, err := s.Write(EncodeGetRequestBytes(GetBlob(hash))); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return nil, fmt.Errorf("blobs: close request: %w", err)
	}
	// One byte past the largest valid response is enough for decode to
	// reject an oversized one.
	encoded, err := readAllContext(ctx, s, 8+MaxSingleLeafSize+1)
	if err != nil {
		return nil, fmt.Errorf("blobs: read response: %w", err)
	}
	data, err := decode(hash, encoded)
	if err != nil {
		return nil, fmt.Errorf("blobs: decode response: %w", err)
	}
	return data, nil
}

// abort ends both directions of s, so that a Read waiting on a peer that
// never answers returns. Close alone may end only the send side.
func abort(s BidiStream) {
	if c, ok := s.(interface{ CancelRead(uint64) }); ok {
		c.CancelRead(0)
	}
	_ = s.Close()
}

// detachableWriter passes writes to w until detach is called, after which it
// rejects them. A helper that returns without waiting for its reader
// goroutine detaches the caller's writer first, so the goroutine never
// writes to it after the helper has returned.
type detachableWriter struct {
	mu       sync.Mutex
	w        io.Writer
	detached bool
}

func (w *detachableWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.detached {
		return 0, errDetached
	}
	return w.w.Write(p)
}

// detach waits for any Write in progress and rejects later ones.
func (w *detachableWriter) detach() {
	w.mu.Lock()
	w.detached = true
	w.mu.Unlock()
}

var errDetached = errors.New("blobs: download abandoned")

func closeWrite(s BidiStream) error {
	if c, ok := s.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return s.Close()
}

// readTrailingByte reports whether r holds anything beyond a verified blob.
// It reads a single byte instead of draining r, so a peer that keeps sending
// after the blob cannot make the caller buffer its output.
func readTrailingByte(r io.Reader) error {
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			return fmt.Errorf("%w: trailing bytes", ErrInvalidBlob)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("blobs: read response: %w", err)
		}
	}
}

// readAllContext reads s until EOF, until it has read limit bytes, or until
// ctx is done.
func readAllContext(ctx context.Context, s BidiStream, limit int64) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(s, limit))
		done <- result{b: b, err: err}
	}()
	select {
	case res := <-done:
		return res.b, res.err
	case <-ctx.Done():
		abort(s)
		return nil, ctx.Err()
	}
}

func singleByteRange(ranges ChunkRanges, size uint64) (offset, length uint64, ok bool) {
	ranges = ranges.normalize()
	if ranges.IsEmpty() {
		return 0, 0, true
	}
	if ranges.IsAll() {
		return 0, size, true
	}
	if start, open := ranges.OpenStart(); open {
		if start > maxChunkIndex() {
			return 0, 0, false
		}
		offset = start * ChunkSize
		if offset > size {
			return 0, 0, false
		}
		return offset, size - offset, true
	}
	rs := ranges.Ranges()
	if len(rs) != 1 {
		return 0, 0, false
	}
	if rs[0].Start > maxChunkIndex() || rs[0].End > maxChunkIndex() {
		return 0, 0, false
	}
	offset = rs[0].Start * ChunkSize
	end := rs[0].End * ChunkSize
	if offset > size {
		return 0, 0, false
	}
	if end > size {
		end = size
	}
	if end < offset {
		return 0, 0, false
	}
	return offset, end - offset, true
}

func maxChunkIndex() uint64 {
	return ^uint64(0) / ChunkSize
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
