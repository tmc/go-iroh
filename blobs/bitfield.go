package blobs

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/tmc/go-iroh/endpointticket"
)

const maxObserveItemSize = 1024 * 1024

// Bitfield reports which chunks of a blob a provider has.
type Bitfield struct {
	size   uint64
	ranges ChunkRanges
}

// EmptyBitfield returns a bitfield with no chunks.
func EmptyBitfield() Bitfield {
	return Bitfield{}
}

// CompleteBitfield returns a bitfield containing every chunk of a blob.
func CompleteBitfield(size uint64) Bitfield {
	return Bitfield{size: size, ranges: RangeAll()}
}

// NewBitfield returns a bitfield for size and ranges.
func NewBitfield(size uint64, ranges ChunkRanges) Bitfield {
	if size == 0 {
		return Bitfield{size: size, ranges: ranges.normalize()}
	}
	end := chunkCount(size)
	complete := RangeChunks(0, end)
	if chunkRangesSubset(complete, ranges) {
		return CompleteBitfield(size)
	}
	if containsChunk(ranges, end-1) {
		r := ranges.normalize()
		r.open = &end
		return Bitfield{size: size, ranges: r.normalize()}
	}
	return Bitfield{size: size, ranges: ranges.normalize()}
}

// Size returns the observed blob size.
func (b Bitfield) Size() uint64 {
	return b.size
}

// Ranges returns the observed chunk ranges.
func (b Bitfield) Ranges() ChunkRanges {
	return cloneChunkRanges(b.ranges)
}

// IsComplete reports whether b contains every chunk of the blob.
func (b Bitfield) IsComplete() bool {
	if b.size == 0 {
		return b.ranges.IsAll()
	}
	return chunkRangesSubset(RangeChunks(0, chunkCount(b.size)), b.ranges)
}

// TotalBytes returns the number of bytes covered by b's chunk ranges,
// clipped to b.Size(). Ranges starting at or past b.Size() contribute zero
// bytes without underflowing or overflowing.
func (b Bitfield) TotalBytes() uint64 {
	if b.size == 0 {
		return 0
	}
	ranges := b.ranges.normalize()
	var total uint64
	for _, r := range ranges.ranges {
		start := chunkBytesSaturating(r.Start)
		end := min(chunkBytesSaturating(r.End), b.size)
		if end > start {
			total += end - start
		}
	}
	if ranges.open != nil {
		start := chunkBytesSaturating(*ranges.open)
		if b.size > start {
			total += b.size - start
		}
	}
	return total
}

func chunkBytesSaturating(chunk uint64) uint64 {
	if chunk > maxChunkIndex() {
		return math.MaxUint64
	}
	return chunk * ChunkSize
}

func (b Bitfield) encodeObserveItem(dst []byte) []byte {
	dst = appendVarint(dst, b.size)
	return encodeChunkRangesBoundaries(dst, b.ranges)
}

func decodeObserveItem(p *parser) (Bitfield, error) {
	size, err := p.varint()
	if err != nil {
		return Bitfield{}, wrapDecodeErr(err)
	}
	ranges, err := decodeChunkRangesBoundaries(p)
	if err != nil {
		return Bitfield{}, err
	}
	return NewBitfield(size, ranges), nil
}

func writeObserveItem(w io.Writer, b Bitfield) error {
	item := b.encodeObserveItem(nil)
	if len(item) > maxObserveItemSize {
		return fmt.Errorf("blobs: observe item too large")
	}
	frame := appendVarint(nil, uint64(len(item)))
	frame = append(frame, item...)
	if _, err := w.Write(frame); err != nil {
		return fmt.Errorf("blobs: write observe item: %w", err)
	}
	return nil
}

func readObserveItem(r *bufio.Reader) (Bitfield, error) {
	n, err := readVarintReader(r)
	if err != nil {
		return Bitfield{}, err
	}
	if n > maxObserveItemSize {
		return Bitfield{}, fmt.Errorf("blobs: observe item too large")
	}
	item := make([]byte, n)
	if _, err := io.ReadFull(r, item); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return Bitfield{}, fmt.Errorf("blobs: read observe item: %w", err)
	}
	var bitfield Bitfield
	err = decodeToEnd(item, func(p *parser) error {
		var err error
		bitfield, err = decodeObserveItem(p)
		return err
	})
	if err != nil {
		return Bitfield{}, err
	}
	return bitfield, nil
}

func readVarintReader(r io.ByteReader) (uint64, error) {
	var x uint64
	var s uint
	for i := 0; ; i++ {
		c, err := r.ReadByte()
		if err != nil {
			if i > 0 && errors.Is(err, io.EOF) {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if c < 0x80 {
			if i > 9 || i == 9 && c > 1 {
				return 0, endpointticket.ErrVarintOverflow
			}
			return x | uint64(c)<<s, nil
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
}

func encodeChunkRangesBoundaries(dst []byte, ranges ChunkRanges) []byte {
	bounds := chunkRangeBoundaries(ranges)
	dst = appendVarint(dst, uint64(len(bounds)))
	for _, n := range bounds {
		dst = appendVarint(dst, n)
	}
	return dst
}

func decodeChunkRangesBoundaries(p *parser) (ChunkRanges, error) {
	n, err := p.varint()
	if err != nil {
		return ChunkRanges{}, wrapDecodeErr(err)
	}
	if n > uint64(len(p.b)-p.off) {
		return ChunkRanges{}, wrapDecodeErr(endpointticket.ErrTruncated)
	}
	bounds := make([]uint64, 0, n)
	for range n {
		bound, err := p.varint()
		if err != nil {
			return ChunkRanges{}, wrapDecodeErr(err)
		}
		bounds = append(bounds, bound)
	}
	if !slicesSorted(bounds) {
		return ChunkRanges{}, verifyErr("chunk range boundaries are not sorted", nil)
	}
	var ranges ChunkRanges
	for len(bounds) >= 2 {
		ranges.ranges = append(ranges.ranges, ChunkRange{Start: bounds[0], End: bounds[1]})
		bounds = bounds[2:]
	}
	if len(bounds) == 1 {
		open := bounds[0]
		ranges.open = &open
	}
	return ranges.normalize(), nil
}

func chunkRangeBoundaries(ranges ChunkRanges) []uint64 {
	ranges = ranges.normalize()
	bounds := make([]uint64, 0, len(ranges.ranges)*2+1)
	for _, r := range ranges.ranges {
		bounds = append(bounds, r.Start, r.End)
	}
	if ranges.open != nil {
		bounds = append(bounds, *ranges.open)
	}
	return bounds
}

func chunkCount(size uint64) uint64 {
	if size == 0 {
		return 0
	}
	return (size-1)/ChunkSize + 1
}

func containsChunk(ranges ChunkRanges, chunk uint64) bool {
	ranges = ranges.normalize()
	for _, r := range ranges.ranges {
		if r.Start <= chunk && chunk < r.End {
			return true
		}
	}
	if ranges.open != nil && *ranges.open <= chunk {
		return true
	}
	return false
}

func chunkRangesSubset(need, have ChunkRanges) bool {
	need = need.normalize()
	have = have.normalize()
	for _, r := range need.ranges {
		if !chunkRangeCovered(r, have) {
			return false
		}
	}
	if need.open != nil {
		if have.open == nil || *have.open > *need.open {
			return false
		}
	}
	return true
}

func chunkRangeCovered(r ChunkRange, ranges ChunkRanges) bool {
	if r.Start >= r.End {
		return true
	}
	for _, have := range ranges.ranges {
		if have.Start <= r.Start && r.End <= have.End {
			return true
		}
	}
	return ranges.open != nil && *ranges.open <= r.Start
}

func cloneChunkRanges(r ChunkRanges) ChunkRanges {
	out := ChunkRanges{ranges: append([]ChunkRange(nil), r.ranges...)}
	if r.open != nil {
		open := *r.open
		out.open = &open
	}
	return out
}

func slicesSorted(v []uint64) bool {
	prev := uint64(0)
	for i, n := range v {
		if i > 0 && n < prev {
			return false
		}
		prev = n
	}
	return true
}
