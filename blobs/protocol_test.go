package blobs

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"

	"github.com/tmc/go-iroh/endpointticket"
)

func TestRangeSpecWireFormat(t *testing.T) {
	tests := []struct {
		name string
		spec RangeSpec
		hex  string
	}{
		{name: "empty", spec: RangeSpecEmpty(), hex: "00"},
		{name: "all", spec: RangeSpecAll(), hex: "0100"},
		{name: "tail64", spec: RangeSpecFromRanges(openRange(64)), hex: "0140"},
		{name: "tail10000", spec: RangeSpecFromRanges(openRange(10000)), hex: "01904e"},
		{name: "prefix64", spec: RangeSpecFromRanges(RangeChunks(0, 64)), hex: "020040"},
		{name: "fragmented", spec: RangeSpecFromRanges(unionRanges(RangeChunks(1, 3), RangeChunks(9, 13))), hex: "0401020604"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.encode(nil)
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("encode = %x, want %s", got, tt.hex)
			}
			var decoded RangeSpec
			if err := decodeToEnd(got, func(p *parser) error {
				spec, err := decodeRangeSpec(p)
				decoded = spec
				return err
			}); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !chunkRangesEqual(decoded.ChunkRanges(), tt.spec.ChunkRanges()) {
				t.Fatalf("round trip = %#v, want %#v", decoded.ChunkRanges(), tt.spec.ChunkRanges())
			}
		})
	}
}

func TestChunkRangesSeqWireFormat(t *testing.T) {
	tests := []struct {
		name string
		seq  ChunkRangesSeq
		hex  string
	}{
		{name: "empty", seq: ChunkRangesSeqEmpty(), hex: "00"},
		{name: "all", seq: ChunkRangesSeqAll(), hex: "01000100"},
		{
			name: "finite",
			seq: ChunkRangesSeqFromRanges([]ChunkRanges{
				RangeChunks(1, 3),
				RangeChunks(7, 13),
			}),
			hex: "0300020102010207060100",
		},
		{
			name: "open",
			seq: ChunkRangesSeqFromRangesOpen([]ChunkRanges{
				RangeEmpty(),
				RangeEmpty(),
				RangeEmpty(),
				openRange(7),
				RangeAll(),
			}),
			hex: "02030107010100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.seq.encode(nil)
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("encode = %x, want %s", got, tt.hex)
			}
			var decoded ChunkRangesSeq
			if err := decodeToEnd(got, func(p *parser) error {
				seq, err := decodeChunkRangesSeq(p)
				decoded = seq
				return err
			}); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if hex.EncodeToString(decoded.encode(nil)) != tt.hex {
				t.Fatalf("round trip encode = %x, want %s", decoded.encode(nil), tt.hex)
			}
		})
	}
}

func TestRequestWireFormat(t *testing.T) {
	var hash Hash
	for i := range hash {
		hash[i] = 0xda
	}
	tests := []struct {
		name string
		req  GetRequest
		hex  string
	}{
		{
			name: "blob",
			req:  GetBlob(hash),
			hex: "00" +
				"dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" +
				"020001000100",
		},
		{
			name: "all",
			req:  GetAll(hash),
			hex: "00" +
				"dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" +
				"01000100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeGetRequestBytes(tt.req)
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("encode = %x, want %s", got, tt.hex)
			}
			decoded, err := DecodeGetRequestBytes(got)
			if err != nil {
				t.Fatalf("DecodeGetRequestBytes: %v", err)
			}
			if decoded.Hash != tt.req.Hash || hex.EncodeToString(decoded.Ranges.encode(nil)) != hex.EncodeToString(tt.req.Ranges.encode(nil)) {
				t.Fatalf("round trip = %#v, want %#v", decoded, tt.req)
			}
		})
	}
}

func TestObserveRequestWireFormat(t *testing.T) {
	var hash Hash
	for i := range hash {
		hash[i] = 0xda
	}
	got := EncodeObserveRequestBytes(ObserveBlob(hash))
	want := "01" +
		"dadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada" +
		"0100"
	if hex.EncodeToString(got) != want {
		t.Fatalf("encode = %x, want %s", got, want)
	}
	decoded, err := DecodeObserveRequestBytes(got)
	if err != nil {
		t.Fatalf("DecodeObserveRequestBytes: %v", err)
	}
	if decoded.Hash != hash || !decoded.Ranges.IsAll() {
		t.Fatalf("round trip = %#v", decoded)
	}
}

func TestObserveItemWireFormat(t *testing.T) {
	item := CompleteBitfield(1234)
	var b []byte
	if err := writeObserveItem(bytesBuffer{&b}, item); err != nil {
		t.Fatalf("writeObserveItem: %v", err)
	}
	if hex.EncodeToString(b) != "04d2090100" {
		t.Fatalf("encode = %x, want 04d2090100", b)
	}
	got, err := readObserveItem(newByteReader(b))
	if err != nil {
		t.Fatalf("readObserveItem: %v", err)
	}
	if got.Size() != 1234 || !got.IsComplete() {
		t.Fatalf("bitfield = size %d complete %v", got.Size(), got.IsComplete())
	}
}

func TestObserveItemRejectsImpossibleBoundaryCount(t *testing.T) {
	_, err := readObserveItem(newByteReader(impossibleObserveItem()))
	if !errors.Is(err, endpointticket.ErrTruncated) {
		t.Fatalf("readObserveItem error = %v, want %v", err, endpointticket.ErrTruncated)
	}
}

func TestRequestDecodeErrors(t *testing.T) {
	if _, err := DecodeRequestBytes([]byte{byte(RequestPush)}); !errors.Is(err, endpointticket.ErrVerify) {
		t.Fatalf("DecodeRequestBytes unsupported error = %v", err)
	}
	if _, err := DecodeGetRequestBytes([]byte{byte(RequestGetMany), 0}); !errors.Is(err, endpointticket.ErrDecode) {
		t.Fatalf("DecodeGetRequestBytes malformed error = %v", err)
	}
}

func openRange(start uint64) ChunkRanges {
	r := RangeEmpty()
	r.open = &start
	return r
}

func unionRanges(rs ...ChunkRanges) ChunkRanges {
	var out ChunkRanges
	for _, r := range rs {
		out.ranges = append(out.ranges, r.ranges...)
		if r.open != nil {
			open := *r.open
			out.open = &open
		}
	}
	return out.normalize()
}

type bytesBuffer struct {
	b *[]byte
}

func (w bytesBuffer) Write(p []byte) (int, error) {
	*w.b = append(*w.b, p...)
	return len(p), nil
}

func newByteReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

func impossibleObserveItem() []byte {
	item := appendVarint(nil, 0)
	item = appendVarint(item, 1<<60)
	frame := appendVarint(nil, uint64(len(item)))
	return append(frame, item...)
}

// TestRequestTypeWireValues pins the Rust iroh-blobs wire discriminants. The
// gap at 2-7 is reserved by that numbering; these values are protocol, not
// implementation detail, and may not be renumbered.
func TestRequestTypeWireValues(t *testing.T) {
	for _, tt := range []struct {
		name string
		got  RequestType
		want uint64
	}{
		{"RequestGet", RequestGet, 0},
		{"RequestObserve", RequestObserve, 1},
		{"RequestPush", RequestPush, 8},
		{"RequestGetMany", RequestGetMany, 9},
	} {
		if uint64(tt.got) != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

func encodeRawRangeSpec(spans []uint64) []byte {
	b := appendVarint(nil, uint64(len(spans)))
	for _, s := range spans {
		b = appendVarint(b, s)
	}
	return b
}

type rawRangeSpecSeqItem struct {
	delta uint64
	spans []uint64
}

func encodeRawRangeSpecSeq(items []rawRangeSpecSeqItem) []byte {
	b := appendVarint(nil, uint64(len(items)))
	for _, item := range items {
		b = appendVarint(b, item.delta)
		b = append(b, encodeRawRangeSpec(item.spans)...)
	}
	return b
}

func TestDecodeRangeSpecRejectsNonCanonical(t *testing.T) {
	valid := []struct {
		name  string
		spans []uint64
		want  ChunkRanges
	}{
		{name: "empty", spans: nil, want: RangeEmpty()},
		{name: "all", spans: []uint64{0}, want: RangeAll()},
		{name: "verified size", spans: []uint64{math.MaxUint64}, want: RangeLastChunk()},
		{
			name:  "disjoint",
			spans: []uint64{2, 5, 3, 1},
			want:  RangeChunksMany(ChunkRange{Start: 2, End: 7}, ChunkRange{Start: 10, End: 11}),
		},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			var got RangeSpec
			err := decodeToEnd(encodeRawRangeSpec(tt.spans), func(p *parser) error {
				var err error
				got, err = decodeRangeSpec(p)
				return err
			})
			if err != nil {
				t.Fatalf("decodeRangeSpec(%v) error = %v", tt.spans, err)
			}
			if !chunkRangesEqual(got.ChunkRanges(), tt.want) {
				t.Fatalf("ChunkRanges = %#v, want %#v", got.ChunkRanges(), tt.want)
			}
		})
	}

	invalid := []struct {
		name  string
		spans []uint64
	}{
		{name: "repeated boundary", spans: []uint64{1, 0}},
		{name: "double zero", spans: []uint64{0, 0}},
		{name: "zero third span", spans: []uint64{1, 2, 0}},
		{name: "boundary overflow", spans: []uint64{math.MaxUint64, 1}},
		{name: "boundary overflow later", spans: []uint64{10, math.MaxUint64 - 5}},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			raw := encodeRawRangeSpec(tt.spans)
			err := decodeToEnd(raw, func(p *parser) error {
				_, err := decodeRangeSpec(p)
				return err
			})
			if !errors.Is(err, endpointticket.ErrVerify) {
				t.Fatalf("decodeRangeSpec(%v) error = %v, want %v", tt.spans, err, endpointticket.ErrVerify)
			}
			// ObserveRequest embeds RangeSpec directly, so it must reject the same input.
			var obs []byte
			obs = appendVarint(obs, uint64(RequestObserve))
			h := testHash()
			obs = append(obs, h[:]...)
			obs = append(obs, raw...)
			if _, err := DecodeObserveRequestBytes(obs); !errors.Is(err, endpointticket.ErrVerify) {
				t.Fatalf("DecodeObserveRequestBytes(%v) error = %v, want %v", tt.spans, err, endpointticket.ErrVerify)
			}
		})
	}
}

func TestDecodeChunkRangesSeqRejectsNonCanonical(t *testing.T) {
	valid := []struct {
		name  string
		items []rawRangeSpecSeqItem
		want  ChunkRangesSeq
	}{
		{
			name:  "empty",
			items: nil,
			want:  ChunkRangesSeqEmpty(),
		},
		{
			name: "single blob",
			items: []rawRangeSpecSeqItem{
				{delta: 0, spans: []uint64{0}},
				{delta: 1, spans: nil},
			},
			want: ChunkRangesSeqFromRanges([]ChunkRanges{RangeAll()}),
		},
		{
			name: "leading empty via first offset",
			items: []rawRangeSpecSeqItem{
				{delta: 2, spans: []uint64{0}},
			},
			want: ChunkRangesSeqFromRangesOpen([]ChunkRanges{RangeEmpty(), RangeEmpty(), RangeAll()}),
		},
	}
	for _, tt := range valid {
		t.Run("valid/"+tt.name, func(t *testing.T) {
			var got ChunkRangesSeq
			err := decodeToEnd(encodeRawRangeSpecSeq(tt.items), func(p *parser) error {
				var err error
				got, err = decodeChunkRangesSeq(p)
				return err
			})
			if err != nil {
				t.Fatalf("decodeChunkRangesSeq error = %v", err)
			}
			if !bytes.Equal(got.encode(nil), tt.want.encode(nil)) {
				t.Fatalf("decoded = %x, want %x", got.encode(nil), tt.want.encode(nil))
			}
		})
	}

	invalid := []struct {
		name  string
		items []rawRangeSpecSeqItem
	}{
		{
			name: "repeated offset",
			items: []rawRangeSpecSeqItem{
				{delta: 0, spans: []uint64{0}},
				{delta: 0, spans: nil},
			},
		},
		{
			name: "offset overflow",
			items: []rawRangeSpecSeqItem{
				{delta: math.MaxUint64, spans: []uint64{0}},
				{delta: 1, spans: nil},
			},
		},
		{
			name: "range boundary overflow",
			items: []rawRangeSpecSeqItem{
				{delta: 0, spans: []uint64{math.MaxUint64, 1}},
			},
		},
		{
			name: "repeated range boundary",
			items: []rawRangeSpecSeqItem{
				{delta: 0, spans: []uint64{1, 0}},
			},
		},
		{
			name: "repeated spec",
			items: []rawRangeSpecSeqItem{
				{delta: 0, spans: []uint64{0}},
				{delta: 1, spans: []uint64{0}},
			},
		},
		{
			name: "empty first spec at 0",
			items: []rawRangeSpecSeqItem{
				{delta: 0, spans: nil},
			},
		},
		{
			name: "empty first spec at nonzero",
			items: []rawRangeSpecSeqItem{
				{delta: 3, spans: nil},
				{delta: 1, spans: []uint64{0}},
			},
		},
	}
	for _, tt := range invalid {
		t.Run("invalid/"+tt.name, func(t *testing.T) {
			raw := encodeRawRangeSpecSeq(tt.items)
			err := decodeToEnd(raw, func(p *parser) error {
				_, err := decodeChunkRangesSeq(p)
				return err
			})
			if !errors.Is(err, endpointticket.ErrVerify) {
				t.Fatalf("decodeChunkRangesSeq error = %v, want %v", err, endpointticket.ErrVerify)
			}
			// RequestGet and RequestGetMany must also reject non-canonical sequences.
			h := testHash()
			var getReq []byte
			getReq = appendVarint(getReq, uint64(RequestGet))
			getReq = append(getReq, h[:]...)
			getReq = append(getReq, raw...)
			if _, err := DecodeGetRequestBytes(getReq); !errors.Is(err, endpointticket.ErrVerify) {
				t.Fatalf("DecodeGetRequestBytes error = %v, want %v", err, endpointticket.ErrVerify)
			}

			var getManyReq []byte
			getManyReq = appendVarint(getManyReq, uint64(RequestGetMany))
			getManyReq = appendVarint(getManyReq, 1)
			getManyReq = append(getManyReq, h[:]...)
			getManyReq = append(getManyReq, raw...)
			if _, err := DecodeRequestBytes(getManyReq); !errors.Is(err, endpointticket.ErrVerify) {
				t.Fatalf("DecodeRequestBytes(GetMany) error = %v, want %v", err, endpointticket.ErrVerify)
			}
		})
	}
}
