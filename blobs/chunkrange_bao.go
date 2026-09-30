package blobs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"

	"lukechampine.com/blake3/guts"
)

const blockChunks = BlockSize / ChunkSize

type chunkSelection [][2]uint64

func selectChunks(ranges ChunkRanges, chunks uint64) chunkSelection {
	ranges = ranges.normalize()
	var in chunkSelection
	lastOnly := ranges.open != nil && *ranges.open == math.MaxUint64
	for _, r := range ranges.ranges {
		in = append(in, [2]uint64{r.Start, r.End})
	}
	if ranges.open != nil && !lastOnly {
		in = append(in, [2]uint64{*ranges.open, math.MaxUint64})
	}
	if chunks == 0 {
		return nil
	}
	last := chunks - 1
	var out chunkSelection
	for _, r := range in {
		if r[0] >= r[1] {
			continue
		}
		if r[1] > last {
			out = append(out, [2]uint64{min(r[0], last), chunks})
			break
		}
		if r[0] < chunks {
			out = append(out, [2]uint64{r[0], min(r[1], chunks)})
		}
	}
	if lastOnly && out.count(last, chunks) == 0 {
		out = append(out, [2]uint64{last, chunks})
	}
	return out
}

func (s chunkSelection) count(lo, hi uint64) uint64 {
	var n uint64
	for _, r := range s.intersecting(lo, hi) {
		if a, b := max(r[0], lo), min(r[1], hi); a < b {
			n += b - a
		}
	}
	return n
}

// intersecting returns the contiguous part of s that can overlap [lo, hi).
// Selections are normalized and sorted, so the bounds can be found by search.
func (s chunkSelection) intersecting(lo, hi uint64) chunkSelection {
	if lo >= hi || len(s) == 0 {
		return nil
	}
	first := sort.Search(len(s), func(i int) bool { return s[i][1] > lo })
	last := first + sort.Search(len(s)-first, func(i int) bool { return s[first+i][0] >= hi })
	return s[first:last]
}

func leftChunks(n uint64) uint64 {
	return uint64(1) << (bits.Len64(n-1) - 1)
}

func readAtFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if err != nil && !(errors.Is(err, io.EOF) && n == len(p)) {
		return err
	}
	if n != len(p) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func writeChunkBytes(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

func chunkCV(data []byte, counter uint64, root bool) [8]uint32 {
	node := guts.CompressChunk(data, &guts.IV, counter, 0)
	if root {
		node.Flags |= guts.FlagRoot
	}
	return guts.ChainingValue(node)
}

func parentCV(left, right [8]uint32, root bool) [8]uint32 {
	flags := uint32(0)
	if root {
		flags = guts.FlagRoot
	}
	return guts.ChainingValue(guts.ParentNode(left, right, &guts.IV, flags))
}

func hashChunkTree(data []byte, first, n uint64, root bool) [8]uint32 {
	return hashChunkSubtree(data, first, 0, n, root)
}

func hashChunkSubtree(data []byte, first, local, n uint64, root bool) [8]uint32 {
	if n == 1 {
		lo := min(local*ChunkSize, uint64(len(data)))
		hi := min(lo+ChunkSize, uint64(len(data)))
		return chunkCV(data[lo:hi], first+local, root)
	}
	left := leftChunks(n)
	return parentCV(hashChunkSubtree(data, first, local, left, false), hashChunkSubtree(data, first, local+left, n-left, false), root)
}

func readChunkCV(r io.Reader) ([8]uint32, error) {
	var p [32]byte
	var cv [8]uint32
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return cv, err
	}
	for i := range cv {
		cv[i] = binary.LittleEndian.Uint32(p[i*4:])
	}
	return cv, nil
}

type chunkRangeEncoder struct {
	w        io.Writer
	data     io.ReaderAt
	outboard io.ReaderAt
	size     uint64
	sel      chunkSelection
}

func (e *chunkRangeEncoder) subtree(sel chunkSelection, start, n uint64, root bool, off int64, want [8]uint32) error {
	selected := sel.count(start, start+n)
	if selected == 0 {
		return nil
	}
	if n <= blockChunks {
		lo := start * ChunkSize
		length := min(n*ChunkSize, e.size-lo)
		buf := make([]byte, length)
		if err := readAtFull(e.data, buf, int64(lo)); err != nil {
			return fmt.Errorf("blobs: read chunk block at %d: %w", start, err)
		}
		if selected == n {
			if got := hashChunkTree(buf, start, n, root); got != want {
				return fmt.Errorf("%w: block at chunk %d does not match its hash", ErrInvalidBlob, start)
			}
			return writeChunkBytes(e.w, buf)
		}
		var proof bytes.Buffer
		got, err := encodePartialBlock(&proof, sel, start, n, buf, root)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%w: block at chunk %d does not match its hash", ErrInvalidBlob, start)
		}
		return writeChunkBytes(e.w, proof.Bytes())
	}
	var pair [64]byte
	if err := readAtFull(e.outboard, pair[:], off); err != nil {
		return fmt.Errorf("blobs: read outboard: %w", err)
	}
	leftCV := bytesToCV(pair[:32])
	rightCV := bytesToCV(pair[32:])
	if parentCV(leftCV, rightCV, root) != want {
		return fmt.Errorf("%w: outboard at chunk %d does not match its hash", ErrInvalidBlob, start)
	}
	if err := writeChunkBytes(e.w, pair[:]); err != nil {
		return err
	}
	left := leftChunks(n)
	leftParents := int64((left+blockChunks-1)/blockChunks - 1)
	if err := e.subtree(sel.intersecting(start, start+left), start, left, false, off+64, leftCV); err != nil {
		return err
	}
	return e.subtree(sel.intersecting(start+left, start+n), start+left, n-left, false, off+64+64*leftParents, rightCV)
}

func encodePartialBlock(w io.Writer, sel chunkSelection, start, n uint64, data []byte, root bool) ([8]uint32, error) {
	selected := sel.count(start, start+n)
	if selected == 0 {
		return hashChunkTree(data, start, n, root), nil
	}
	if n == 1 {
		cv := chunkCV(data, start, root)
		if selected != 0 {
			if err := writeChunkBytes(w, data); err != nil {
				return cv, err
			}
		}
		return cv, nil
	}
	left := leftChunks(n)
	leftLen := min(left*ChunkSize, uint64(len(data)))
	if selected == n {
		cv := hashChunkTree(data, start, n, root)
		return cv, writeChunkBytes(w, data)
	}
	var pair bytes.Buffer
	if _, err := pair.Write(make([]byte, 64)); err != nil {
		return [8]uint32{}, err
	}
	leftCV, err := encodePartialBlock(&pair, sel.intersecting(start, start+left), start, left, data[:leftLen], false)
	if err != nil {
		return [8]uint32{}, err
	}
	rightCV, err := encodePartialBlock(&pair, sel.intersecting(start+left, start+n), start+left, n-left, data[leftLen:], false)
	if err != nil {
		return [8]uint32{}, err
	}
	copy(pair.Bytes()[:32], cvBytes(leftCV))
	copy(pair.Bytes()[32:64], cvBytes(rightCV))
	if err := writeChunkBytes(w, pair.Bytes()); err != nil {
		return [8]uint32{}, err
	}
	return parentCV(leftCV, rightCV, root), nil
}

func cvBytes(cv [8]uint32) []byte {
	p := make([]byte, 32)
	for i, word := range cv {
		binary.LittleEndian.PutUint32(p[i*4:], word)
	}
	return p
}

// EncodeBlobChunks writes an iroh-blobs BAO response for the selected chunk
// ranges. The response includes the verified blob size followed by only the
// selected chunks and their proof. data and outboard must describe hash.
func EncodeBlobChunks(w io.Writer, hash Hash, size uint64, data, outboard io.ReaderAt, ranges ChunkRanges) error {
	if w == nil || data == nil || outboard == nil {
		return errors.New("blobs: nil chunk range input")
	}
	if size > maxInt64 {
		return ErrUnsupportedRequest
	}
	var sizeBuf [8]byte
	binary.LittleEndian.PutUint64(sizeBuf[:], size)
	if err := writeChunkBytes(w, sizeBuf[:]); err != nil {
		return err
	}
	chunks := (size + ChunkSize - 1) / ChunkSize
	if chunks == 0 {
		if hash != NewHash(nil) {
			return fmt.Errorf("%w: empty blob hash mismatch", ErrInvalidBlob)
		}
		return nil
	}
	sel := selectChunks(ranges, chunks)
	if len(sel) == 0 {
		return ErrUnsupportedRequest
	}
	e := chunkRangeEncoder{w: w, data: data, outboard: outboard, size: size, sel: sel}
	return e.subtree(sel, 0, chunks, true, 8, hashToCV(hash))
}

func hashToCV(h Hash) [8]uint32 { return bytesToCV(h[:]) }

func bytesToCV(p []byte) (cv [8]uint32) {
	for i := range cv {
		cv[i] = binary.LittleEndian.Uint32(p[i*4:])
	}
	return cv
}

type chunkRangeDecoder struct {
	r    io.Reader
	w    io.Writer
	sel  chunkSelection
	size uint64
}

func (d *chunkRangeDecoder) subtree(sel chunkSelection, start, n uint64, root bool, want [8]uint32) (bool, error) {
	selected := sel.count(start, start+n)
	if selected == 0 {
		return true, nil
	}
	if n <= blockChunks {
		return d.block(sel, start, n, root, want)
	}
	leftCV, err := readChunkCV(d.r)
	if err != nil {
		return false, err
	}
	rightCV, err := readChunkCV(d.r)
	if err != nil {
		return false, err
	}
	if parentCV(leftCV, rightCV, root) != want {
		return false, fmt.Errorf("hash mismatch at chunk subtree [%d,%d)", start, start+n)
	}
	left := leftChunks(n)
	ok, err := d.subtree(sel.intersecting(start, start+left), start, left, false, leftCV)
	if err != nil || !ok {
		return ok, err
	}
	return d.subtree(sel.intersecting(start+left, start+n), start+left, n-left, false, rightCV)
}

func (d *chunkRangeDecoder) block(sel chunkSelection, start, n uint64, root bool, want [8]uint32) (bool, error) {
	selected := sel.count(start, start+n)
	if selected == 0 {
		return true, nil
	}
	if selected == n {
		length := uint64(0)
		for i := start; i < start+n; i++ {
			length += min(ChunkSize, d.sizeForChunk(i))
		}
		buf := make([]byte, length)
		if _, err := io.ReadFull(d.r, buf); err != nil {
			return false, err
		}
		if hashChunkTree(buf, start, n, root) != want {
			return false, fmt.Errorf("hash mismatch in selected block [%d,%d)", start, start+n)
		}
		if err := writeChunkBytes(d.w, buf); err != nil {
			return false, err
		}
		return true, nil
	}
	if n == 1 {
		length := d.sizeForChunk(start)
		buf := make([]byte, length)
		if _, err := io.ReadFull(d.r, buf); err != nil {
			return false, err
		}
		if chunkCV(buf, start, root) != want {
			return false, fmt.Errorf("hash mismatch at chunk %d", start)
		}
		if err := writeChunkBytes(d.w, buf); err != nil {
			return false, err
		}
		return true, nil
	}
	leftCV, err := readChunkCV(d.r)
	if err != nil {
		return false, err
	}
	rightCV, err := readChunkCV(d.r)
	if err != nil {
		return false, err
	}
	if parentCV(leftCV, rightCV, root) != want {
		return false, fmt.Errorf("hash mismatch in block subtree [%d,%d)", start, start+n)
	}
	left := leftChunks(n)
	ok, err := d.block(sel.intersecting(start, start+left), start, left, false, leftCV)
	if err != nil || !ok {
		return ok, err
	}
	return d.block(sel.intersecting(start+left, start+n), start+left, n-left, false, rightCV)
}

func (d *chunkRangeDecoder) sizeForChunk(chunk uint64) uint64 {
	start := chunk * ChunkSize
	if start >= d.size {
		return 0
	}
	return min(ChunkSize, d.size-start)
}

// DecodeBlobChunksToWriter validates a chunk-range BAO response and streams
// the selected chunks to w. It returns the verified full blob size.
func DecodeBlobChunksToWriter(expected Hash, r io.Reader, ranges ChunkRanges, w io.Writer) (uint64, error) {
	return decodeBlobChunksToWriter(expected, r, ranges, w, nil)
}

func decodeBlobChunksToWriter(expected Hash, r io.Reader, ranges ChunkRanges, w io.Writer, checkSize func(uint64) error) (uint64, error) {
	if r == nil || w == nil {
		return 0, errors.New("blobs: nil chunk range reader or writer")
	}
	var sizeBuf [8]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return 0, fmt.Errorf("%w: truncated size prefix", ErrInvalidBlob)
	}
	size := binary.LittleEndian.Uint64(sizeBuf[:])
	if size > maxInt64 {
		return 0, ErrUnsupportedRequest
	}
	if checkSize != nil {
		if err := checkSize(size); err != nil {
			return 0, err
		}
	}
	chunks := (size + ChunkSize - 1) / ChunkSize
	if chunks == 0 {
		if expected != NewHash(nil) {
			return 0, fmt.Errorf("%w: hash mismatch", ErrInvalidBlob)
		}
		return 0, nil
	}
	sel := selectChunks(ranges, chunks)
	if len(sel) == 0 {
		return 0, fmt.Errorf("%w: empty selection does not prove blob size", ErrInvalidBlob)
	}
	d := chunkRangeDecoder{r: r, w: w, sel: sel, size: size}
	ok, err := d.subtree(sel, 0, chunks, true, hashToCV(expected))
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidBlob, err)
	}
	if !ok {
		return 0, fmt.Errorf("%w: hash mismatch", ErrInvalidBlob)
	}
	return size, nil
}

// DecodeBlobChunks validates a chunk-range BAO response and returns the
// selected bytes and verified full blob size.
func DecodeBlobChunks(expected Hash, encoded []byte, ranges ChunkRanges) ([]byte, uint64, error) {
	r := bytes.NewReader(encoded)
	var out bytes.Buffer
	size, err := DecodeBlobChunksToWriter(expected, r, ranges, &out)
	if err != nil {
		return nil, 0, err
	}
	if r.Len() != 0 {
		return nil, 0, fmt.Errorf("%w: trailing %d bytes", ErrInvalidBlob, r.Len())
	}
	return out.Bytes(), size, nil
}
