package blobs

import (
	"cmp"
	"math"
	"slices"

	"github.com/tmc/go-iroh/endpointticket"
)

// ChunkRange is a half-open range of 1024-byte BLAKE3 chunks.
type ChunkRange struct {
	Start uint64
	End   uint64
}

// ChunkRanges selects chunks from a single blob.
type ChunkRanges struct {
	ranges []ChunkRange
	open   *uint64
}

// RangeEmpty returns a chunk range set selecting no chunks.
func RangeEmpty() ChunkRanges { return ChunkRanges{} }

// RangeAll returns a chunk range set selecting every chunk.
func RangeAll() ChunkRanges {
	var zero uint64
	return ChunkRanges{open: &zero}
}

// RangeLastChunk returns a chunk range set selecting the verified-size proof.
func RangeLastChunk() ChunkRanges {
	last := uint64(math.MaxUint64)
	return ChunkRanges{open: &last}
}

// RangeChunks returns a chunk range set selecting [start, end).
func RangeChunks(start, end uint64) ChunkRanges {
	if start >= end {
		return RangeEmpty()
	}
	return ChunkRanges{ranges: []ChunkRange{{Start: start, End: end}}}
}

// RangeChunksMany returns a chunk range set containing ranges. Overlapping or
// adjacent ranges are merged, and empty ranges are discarded.
func RangeChunksMany(ranges ...ChunkRange) ChunkRanges {
	return ChunkRanges{ranges: slices.Clone(ranges)}.normalize()
}

// RangeChunksFrom returns the open-ended chunk range [start, infinity).
func RangeChunksFrom(start uint64) ChunkRanges {
	return ChunkRanges{open: &start}
}

// IsEmpty reports whether r selects no chunks.
func (r ChunkRanges) IsEmpty() bool {
	return len(r.ranges) == 0 && r.open == nil
}

// IsAll reports whether r selects every chunk.
func (r ChunkRanges) IsAll() bool {
	return len(r.ranges) == 0 && r.open != nil && *r.open == 0
}

// Ranges returns the finite selected chunk ranges.
func (r ChunkRanges) Ranges() []ChunkRange { return slices.Clone(r.ranges) }

// OpenStart returns the start of the open-ended selected chunk range, if any.
func (r ChunkRanges) OpenStart() (uint64, bool) {
	if r.open == nil {
		return 0, false
	}
	return *r.open, true
}

func (r ChunkRanges) normalize() ChunkRanges {
	if r.IsEmpty() {
		return RangeEmpty()
	}
	ranges := slices.Clone(r.ranges)
	slices.SortFunc(ranges, func(a, b ChunkRange) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(a.End, b.End))
	})
	out := ranges[:0]
	for _, cr := range ranges {
		if cr.Start >= cr.End {
			continue
		}
		if len(out) == 0 || cr.Start > out[len(out)-1].End {
			out = append(out, cr)
			continue
		}
		if cr.End > out[len(out)-1].End {
			out[len(out)-1].End = cr.End
		}
	}
	if r.open != nil {
		start := *r.open
		for len(out) > 0 && out[len(out)-1].End >= start {
			if out[len(out)-1].Start < start {
				start = out[len(out)-1].Start
			}
			out = out[:len(out)-1]
		}
		open := start
		return ChunkRanges{ranges: slices.Clip(out), open: &open}
	}
	return ChunkRanges{ranges: slices.Clip(out)}
}

// RangeSpec is the compact wire form of chunk ranges.
type RangeSpec struct {
	spans []uint64
}

// RangeSpecEmpty returns the wire range spec for an empty chunk selection.
func RangeSpecEmpty() RangeSpec { return RangeSpec{} }

// RangeSpecAll returns the wire range spec for all chunks.
func RangeSpecAll() RangeSpec { return RangeSpec{spans: []uint64{0}} }

// RangeSpecLastChunk returns the wire range spec for the verified-size proof.
func RangeSpecLastChunk() RangeSpec { return RangeSpec{spans: []uint64{math.MaxUint64}} }

// RangeSpecFromRanges converts ranges to the Rust iroh-blobs wire range spec.
func RangeSpecFromRanges(r ChunkRanges) RangeSpec {
	r = r.normalize()
	var boundaries []uint64
	for _, cr := range r.ranges {
		boundaries = append(boundaries, cr.Start, cr.End)
	}
	if r.open != nil {
		boundaries = append(boundaries, *r.open)
	}
	if len(boundaries) == 0 {
		return RangeSpecEmpty()
	}
	spans := make([]uint64, 0, len(boundaries))
	prev := boundaries[0]
	spans = append(spans, prev)
	for _, boundary := range boundaries[1:] {
		spans = append(spans, boundary-prev)
		prev = boundary
	}
	return RangeSpec{spans: spans}
}

// Spans returns the alternating deselected/selected span widths.
func (s RangeSpec) Spans() []uint64 { return slices.Clone(s.spans) }

// IsEmpty reports whether s selects no chunks.
func (s RangeSpec) IsEmpty() bool { return len(s.spans) == 0 }

// IsAll reports whether s selects every chunk.
func (s RangeSpec) IsAll() bool { return len(s.spans) == 1 && s.spans[0] == 0 }

// ChunkRanges converts s to selected chunk ranges.
func (s RangeSpec) ChunkRanges() ChunkRanges {
	var (
		current uint64
		on      bool
		out     ChunkRanges
	)
	for _, width := range s.spans {
		next := current + width
		if on && next > current {
			out.ranges = append(out.ranges, ChunkRange{Start: current, End: next})
		}
		current = next
		on = !on
	}
	if on {
		open := current
		out.open = &open
	}
	return out.normalize()
}

func (s RangeSpec) encode(b []byte) []byte {
	b = appendVarint(b, uint64(len(s.spans)))
	for _, span := range s.spans {
		b = appendVarint(b, span)
	}
	return b
}

func decodeRangeSpec(p *parser) (RangeSpec, error) {
	n, err := p.varint()
	if err != nil {
		return RangeSpec{}, wrapDecodeErr(err)
	}
	if n > uint64(len(p.b)-p.off) {
		return RangeSpec{}, wrapDecodeErr(endpointticket.ErrTruncated)
	}
	spans := make([]uint64, 0, n)
	for range n {
		span, err := p.varint()
		if err != nil {
			return RangeSpec{}, wrapDecodeErr(err)
		}
		spans = append(spans, span)
	}
	return RangeSpec{spans: spans}, nil
}

// ChunkRangesSeq selects ranges for a root blob and its children.
type ChunkRangesSeq struct {
	entries []chunkRangesSeqEntry
}

type chunkRangesSeqEntry struct {
	offset uint64
	ranges ChunkRanges
}

// ChunkRangesSeqEmpty returns a range sequence selecting nothing.
func ChunkRangesSeqEmpty() ChunkRangesSeq { return ChunkRangesSeq{} }

// ChunkRangesSeqAll returns a range sequence selecting all chunks forever.
func ChunkRangesSeqAll() ChunkRangesSeq {
	return ChunkRangesSeq{entries: []chunkRangesSeqEntry{{ranges: RangeAll()}}}
}

// ChunkRangesSeqRoot returns a range sequence selecting only the root blob.
func ChunkRangesSeqRoot() ChunkRangesSeq {
	return ChunkRangesSeqFromRanges([]ChunkRanges{RangeAll()})
}

// ChunkRangesSeqFromRanges returns a finite range sequence.
func ChunkRangesSeqFromRanges(ranges []ChunkRanges) ChunkRangesSeq {
	entries := chunkRangesSeqFromRanges(ranges)
	if len(entries) > 0 && !entries[len(entries)-1].ranges.IsEmpty() {
		entries = append(entries, chunkRangesSeqEntry{offset: uint64(len(ranges)), ranges: RangeEmpty()})
	}
	return ChunkRangesSeq{entries: entries}
}

// ChunkRangesSeqFromRangesOpen returns a range sequence whose last non-empty
// range repeats forever.
func ChunkRangesSeqFromRangesOpen(ranges []ChunkRanges) ChunkRangesSeq {
	return ChunkRangesSeq{entries: chunkRangesSeqFromRanges(ranges)}
}

func chunkRangesSeqFromRanges(ranges []ChunkRanges) []chunkRangesSeqEntry {
	var entries []chunkRangesSeqEntry
	prev := RangeEmpty()
	for i, r := range ranges {
		r = r.normalize()
		if !chunkRangesEqual(r, prev) {
			entries = append(entries, chunkRangesSeqEntry{offset: uint64(i), ranges: r})
			prev = r
		}
	}
	return entries
}

// Entries returns the explicit range changes in seq.
func (seq ChunkRangesSeq) Entries() []struct {
	Offset uint64
	Ranges ChunkRanges
} {
	out := make([]struct {
		Offset uint64
		Ranges ChunkRanges
	}, len(seq.entries))
	for i, e := range seq.entries {
		out[i] = struct {
			Offset uint64
			Ranges ChunkRanges
		}{Offset: e.offset, Ranges: e.ranges}
	}
	return out
}

// At returns the chunk ranges selected at offset.
func (seq ChunkRangesSeq) At(offset uint64) ChunkRanges {
	ranges := RangeEmpty()
	for _, e := range seq.entries {
		if e.offset > offset {
			break
		}
		ranges = e.ranges
	}
	return ranges
}

// IsBlob reports whether seq requests a single raw blob.
func (seq ChunkRangesSeq) IsBlob() bool {
	if len(seq.entries) != 2 {
		return false
	}
	return seq.entries[0].ranges.IsAll() && seq.entries[0].offset+1 == seq.entries[1].offset && seq.entries[1].ranges.IsEmpty()
}

// IsAll reports whether seq selects all chunks forever.
func (seq ChunkRangesSeq) IsAll() bool {
	return len(seq.entries) == 1 && seq.entries[0].ranges.IsAll()
}

func (seq ChunkRangesSeq) encode(b []byte) []byte {
	b = appendVarint(b, uint64(len(seq.entries)))
	var offset uint64
	for _, e := range seq.entries {
		b = appendVarint(b, e.offset-offset)
		b = RangeSpecFromRanges(e.ranges).encode(b)
		offset = e.offset
	}
	return b
}

func decodeChunkRangesSeq(p *parser) (ChunkRangesSeq, error) {
	n, err := p.varint()
	if err != nil {
		return ChunkRangesSeq{}, wrapDecodeErr(err)
	}
	if n > uint64(len(p.b)-p.off) {
		return ChunkRangesSeq{}, wrapDecodeErr(endpointticket.ErrTruncated)
	}
	entries := make([]chunkRangesSeqEntry, 0, n)
	var offset uint64
	for range n {
		delta, err := p.varint()
		if err != nil {
			return ChunkRangesSeq{}, wrapDecodeErr(err)
		}
		offset += delta
		spec, err := decodeRangeSpec(p)
		if err != nil {
			return ChunkRangesSeq{}, err
		}
		entries = append(entries, chunkRangesSeqEntry{offset: offset, ranges: spec.ChunkRanges()})
	}
	return ChunkRangesSeq{entries: entries}, nil
}

func chunkRangesEqual(a, b ChunkRanges) bool {
	a, b = a.normalize(), b.normalize()
	if len(a.ranges) != len(b.ranges) {
		return false
	}
	for i := range a.ranges {
		if a.ranges[i] != b.ranges[i] {
			return false
		}
	}
	if a.open == nil || b.open == nil {
		return a.open == nil && b.open == nil
	}
	return *a.open == *b.open
}

func decodeToEnd(b []byte, f func(*parser) error) error {
	p := parser{b: b}
	if err := f(&p); err != nil {
		return err
	}
	if !p.done() {
		return wrapDecodeErr(endpointticket.ErrTrailingBytes)
	}
	return nil
}
