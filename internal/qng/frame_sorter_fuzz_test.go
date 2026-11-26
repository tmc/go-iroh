package quic

// Differential fuzzing of the go-iroh frame sorter against a vendored copy of
// the upstream quic-go v0.59.1 frame sorter (MIT licensed, test-only).
//
// go-iroh's frameSorter.push adds an in-order fast path that upstream does not
// have. refSorter below is upstream's implementation with that fast path
// removed; everything else is byte-for-byte upstream logic. Both sorters are
// driven with the same operation tape, and their popped data and internal
// state (queue, gaps, readPos) are compared after every operation.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	list "github.com/tmc/go-iroh/internal/qng/internal/utils/linkedlist"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// ---------------------------------------------------------------------------
// refSorter: upstream quic-go v0.59.1 frame_sorter.go, verbatim except that
// the doneCb is dropped (we always push nil frames) and the type is renamed.
// ---------------------------------------------------------------------------

type refSorterEntry struct {
	Data []byte
}

type refSorter struct {
	queue   map[protocol.ByteCount]refSorterEntry
	readPos protocol.ByteCount
	gaps    *list.List[byteInterval]
}

func newRefSorter() *refSorter {
	s := refSorter{
		gaps:  list.New[byteInterval](),
		queue: make(map[protocol.ByteCount]refSorterEntry),
	}
	s.gaps.PushFront(byteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *refSorter) Push(data []byte, offset protocol.ByteCount) error {
	err := s.push(data, offset)
	if err == errDuplicateStreamData {
		return nil
	}
	return err
}

func (s *refSorter) push(data []byte, offset protocol.ByteCount) error {
	if len(data) == 0 {
		return errDuplicateStreamData
	}

	start := offset
	end := offset + protocol.ByteCount(len(data))

	if end <= s.gaps.Front().Value.Start {
		return errDuplicateStreamData
	}

	startGap, startsInGap := s.findStartGap(start)
	endGap, endsInGap := s.findEndGap(startGap, end)

	startGapEqualsEndGap := startGap == endGap

	if (startGapEqualsEndGap && end <= startGap.Value.Start) ||
		(!startGapEqualsEndGap && startGap.Value.End >= endGap.Value.Start && end <= startGap.Value.Start) {
		return errDuplicateStreamData
	}

	startGapNext := startGap.Next()
	startGapEnd := startGap.Value.End
	endGapStart := endGap.Value.Start
	endGapEnd := endGap.Value.End
	var adjustedStartGapEnd bool
	var wasCut bool

	pos := start
	var hasReplacedAtLeastOne bool
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		if end-pos > oldEntryLen || (hasReplacedAtLeastOne && end-pos == oldEntryLen) {
			delete(s.queue, pos)
			pos += oldEntryLen
			hasReplacedAtLeastOne = true
		} else {
			if !hasReplacedAtLeastOne {
				return errDuplicateStreamData
			}
			data = data[:pos-start]
			end = pos
			wasCut = true
			break
		}
	}

	if !startsInGap && !hasReplacedAtLeastOne {
		data = data[startGap.Value.Start-start:]
		start = startGap.Value.Start
		wasCut = true
	}
	if start <= startGap.Value.Start {
		if end >= startGap.Value.End {
			s.gaps.Remove(startGap)
		} else {
			startGap.Value.Start = end
		}
	} else if !hasReplacedAtLeastOne {
		startGap.Value.End = start
		adjustedStartGapEnd = true
	}

	if !startGapEqualsEndGap {
		s.deleteConsecutive(startGapEnd)
		var nextGap *list.Element[byteInterval]
		for gap := startGapNext; gap.Value.End < endGapStart; gap = nextGap {
			nextGap = gap.Next()
			s.deleteConsecutive(gap.Value.End)
			s.gaps.Remove(gap)
		}
	}

	if !endsInGap && start != endGapEnd && end > endGapEnd {
		data = data[:endGapEnd-start]
		end = endGapEnd
		wasCut = true
	}
	if end == endGapEnd {
		if !startGapEqualsEndGap {
			s.gaps.Remove(endGap)
		}
	} else {
		if startGapEqualsEndGap && adjustedStartGapEnd {
			s.gaps.InsertAfter(byteInterval{Start: end, End: startGapEnd}, startGap)
		} else if !startGapEqualsEndGap {
			endGap.Value.Start = end
		}
	}

	if wasCut && len(data) < protocol.MinStreamFrameBufferSize {
		newData := make([]byte, len(data))
		copy(newData, data)
		data = newData
	}

	if s.gaps.Len() > maxStreamFrameSorterGaps {
		return errors.New("too many gaps in received data")
	}

	s.queue[start] = refSorterEntry{Data: data}
	return nil
}

func (s *refSorter) findStartGap(offset protocol.ByteCount) (*list.Element[byteInterval], bool) {
	for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
		if offset >= gap.Value.Start && offset <= gap.Value.End {
			return gap, true
		}
		if offset < gap.Value.Start {
			return gap, false
		}
	}
	panic("no gap found")
}

func (s *refSorter) findEndGap(startGap *list.Element[byteInterval], offset protocol.ByteCount) (*list.Element[byteInterval], bool) {
	for gap := startGap; gap != nil; gap = gap.Next() {
		if offset >= gap.Value.Start && offset < gap.Value.End {
			return gap, true
		}
		if offset < gap.Value.Start {
			return gap.Prev(), false
		}
	}
	panic("no gap found")
}

func (s *refSorter) deleteConsecutive(pos protocol.ByteCount) {
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		delete(s.queue, pos)
		pos += protocol.ByteCount(len(oldEntry.Data))
	}
}

func (s *refSorter) Pop() (protocol.ByteCount, []byte) {
	entry, ok := s.queue[s.readPos]
	if !ok {
		return s.readPos, nil
	}
	delete(s.queue, s.readPos)
	offset := s.readPos
	s.readPos += protocol.ByteCount(len(entry.Data))
	if s.gaps.Front().Value.End <= s.readPos {
		panic("ref sorter BUG: read position higher than a gap")
	}
	return offset, entry.Data
}

func (s *refSorter) HasMoreData() bool { return len(s.queue) > 0 }

// ---------------------------------------------------------------------------
// tape + comparison helpers
// ---------------------------------------------------------------------------

type sorterOp struct {
	pop    bool
	offset protocol.ByteCount
	length int
}

func (o sorterOp) String() string {
	if o.pop {
		return "pop"
	}
	return fmt.Sprintf("push(off=%d,len=%d)", o.offset, o.length)
}

func tapeString(ops []sorterOp) string {
	parts := make([]string, len(ops))
	for i, o := range ops {
		parts[i] = o.String()
	}
	return strings.Join(parts, "\n")
}

// sorterPayload generates deterministic content so that content divergence is
// detectable: byte i of a frame at offset o is byte(o+i).
func sorterPayload(offset protocol.ByteCount, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(int(offset) + i)
	}
	return b
}

// decodeTape decodes fuzz input into a bounded operation tape.
// Each op is 3 bytes: kind/offset-lo, offset-hi, length.
func decodeTape(in []byte) []sorterOp {
	const maxOps = 64
	ops := make([]sorterOp, 0, maxOps)
	for i := 0; i+2 < len(in) && len(ops) < maxOps; i += 3 {
		a, b, c := in[i], in[i+1], in[i+2]
		if a&0xC0 == 0xC0 { // ~25% of ops are pops
			ops = append(ops, sorterOp{pop: true})
			continue
		}
		// Offsets in [0,1024), lengths in [0,256]. Small values make
		// duplicates, overlaps and adjacency likely.
		off := protocol.ByteCount(int(a&0x3F)<<4 | int(b>>4))
		length := int(c)
		ops = append(ops, sorterOp{offset: off, length: length})
	}
	return ops
}

func gapsOf(l *list.List[byteInterval]) []byteInterval {
	var out []byteInterval
	for e := l.Front(); e != nil; e = e.Next() {
		out = append(out, e.Value)
	}
	return out
}

func queueString(q map[protocol.ByteCount][]byte) string {
	var offsets []protocol.ByteCount
	for k := range q {
		offsets = append(offsets, k)
	}
	// simple insertion sort, avoids importing sort for ByteCount
	for i := 1; i < len(offsets); i++ {
		for j := i; j > 0 && offsets[j] < offsets[j-1]; j-- {
			offsets[j], offsets[j-1] = offsets[j-1], offsets[j]
		}
	}
	var sb strings.Builder
	for _, o := range offsets {
		fmt.Fprintf(&sb, "[%d,%d) ", o, o+protocol.ByteCount(len(q[o])))
	}
	return sb.String()
}

func gotQueue(s *frameSorter) map[protocol.ByteCount][]byte {
	m := make(map[protocol.ByteCount][]byte, len(s.queue))
	for k, v := range s.queue {
		m[k] = v.Data
	}
	return m
}

func refQueue(s *refSorter) map[protocol.ByteCount][]byte {
	m := make(map[protocol.ByteCount][]byte, len(s.queue))
	for k, v := range s.queue {
		m[k] = v.Data
	}
	return m
}

func FuzzFrameSorterDifferential(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x10, 0x00, 0x50, 0x10, 0xC0, 0x00, 0x00})
	f.Add([]byte{0x00, 0x10, 0x20, 0x00, 0x00, 0x40, 0x00, 0x20, 0x10})
	f.Add([]byte{0x00, 0x20, 0x08, 0xC0, 0, 0, 0x00, 0x00, 0x40, 0xC0, 0, 0})
	f.Add([]byte{0x00, 0x00, 0x05, 0x00, 0x50, 0x05, 0x00, 0x00, 0x20})

	f.Fuzz(func(t *testing.T, in []byte) {
		ops := decodeTape(in)
		if len(ops) == 0 {
			return
		}
		got := newFrameSorter()
		want := newRefSorter()

		fail := func(i int, format string, args ...any) {
			t.Fatalf("divergence at op %d (%s): %s\ntape:\n%s\ngot queue:  %s\nwant queue: %s\ngot gaps:  %v\nwant gaps: %v\ngot readPos=%d want readPos=%d",
				i, ops[i], fmt.Sprintf(format, args...), tapeString(ops[:i+1]),
				queueString(gotQueue(got)), queueString(refQueue(want)),
				chunkedGapsOf(got.gaps), gapsOf(want.gaps), got.readPos, want.readPos)
		}

		for i, op := range ops {
			if op.pop {
				gOff, gData, _ := got.Pop()
				wOff, wData := want.Pop()
				if gOff != wOff {
					fail(i, "pop offset %d != %d", gOff, wOff)
				}
				if len(gData) != len(wData) {
					fail(i, "pop len %d != %d", len(gData), len(wData))
				}
				for j := range gData {
					if gData[j] != wData[j] {
						fail(i, "pop data[%d] = %d != %d", j, gData[j], wData[j])
					}
					if gData[j] != byte(int(gOff)+j) {
						fail(i, "pop data[%d] = %d, want content byte %d", j, gData[j], byte(int(gOff)+j))
					}
				}
			} else {
				data := sorterPayload(op.offset, op.length)
				var frame *wire.StreamFrame
				gErr := got.Push(data, op.offset, frame)
				wErr := want.Push(sorterPayload(op.offset, op.length), op.offset)
				if (gErr != nil) != (wErr != nil) {
					fail(i, "push err %v != %v", gErr, wErr)
				}
				if gErr != nil {
					return // both errored out (too many gaps); stop the tape
				}
			}

			// State comparison after every op.
			gq, wq := gotQueue(got), refQueue(want)
			if len(gq) != len(wq) {
				fail(i, "queue len %d != %d", len(gq), len(wq))
			}
			for off, gd := range gq {
				wd, ok := wq[off]
				if !ok {
					fail(i, "queue has entry at %d that ref lacks", off)
				}
				if len(gd) != len(wd) {
					fail(i, "queue entry at %d has len %d != %d", off, len(gd), len(wd))
				}
				for j := range gd {
					if gd[j] != wd[j] {
						fail(i, "queue entry at %d byte %d = %d != %d", off, j, gd[j], wd[j])
					}
					if gd[j] != byte(int(off)+j) {
						fail(i, "queue entry at %d byte %d = %d, want content byte %d", off, j, gd[j], byte(int(off)+j))
					}
				}
			}
			gg, wg := chunkedGapsOf(got.gaps), gapsOf(want.gaps)
			if len(gg) != len(wg) {
				fail(i, "gap count %d != %d", len(gg), len(wg))
			}
			for j := range gg {
				if gg[j] != wg[j] {
					fail(i, "gap[%d] %v != %v", j, gg[j], wg[j])
				}
			}
			if got.readPos != want.readPos {
				fail(i, "readPos %d != %d", got.readPos, want.readPos)
			}
			if got.HasMoreData() != want.HasMoreData() {
				fail(i, "HasMoreData %v != %v", got.HasMoreData(), want.HasMoreData())
			}

			// Structural invariants on the go-iroh sorter itself.
			checkInvariants(t, got, ops[:i+1])
		}
	})
}

func chunkedGapsOf(chunks [][]byteInterval) []byteInterval {
	var out []byteInterval
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// checkInvariants verifies that the gap list is sorted, non-overlapping, and
// complementary to the queue: no queued entry may overlap a gap.
func checkInvariants(t *testing.T, s *frameSorter, ops []sorterOp) {
	t.Helper()
	gaps := chunkedGapsOf(s.gaps)
	for i, g := range gaps {
		if g.Start >= g.End {
			t.Fatalf("empty/inverted gap %v\ntape:\n%s", g, tapeString(ops))
		}
		if i > 0 && g.Start <= gaps[i-1].End {
			t.Fatalf("gaps not strictly ordered: %v then %v\ntape:\n%s", gaps[i-1], g, tapeString(ops))
		}
	}
	if len(gaps) > 0 && s.readPos > gaps[0].Start {
		t.Fatalf("readPos %d past first gap start %v\ntape:\n%s", s.readPos, gaps[0], tapeString(ops))
	}
	for off, e := range s.queue {
		start, end := off, off+protocol.ByteCount(len(e.Data))
		if start < s.readPos {
			t.Fatalf("queued entry [%d,%d) before readPos %d\ntape:\n%s", start, end, s.readPos, tapeString(ops))
		}
		for _, g := range gaps {
			if start < g.End && g.Start < end {
				t.Fatalf("queued entry [%d,%d) overlaps gap %v\ntape:\n%s", start, end, g, tapeString(ops))
			}
		}
	}
}
