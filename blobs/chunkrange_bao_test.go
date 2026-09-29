package blobs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"lukechampine.com/blake3/bao"
)

func TestBlobChunkRangesTransfer(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		ranges ChunkRanges
	}{
		{name: "single chunk", size: ChunkSize, ranges: RangeAll()},
		{name: "partial group", size: 100_000, ranges: RangeChunks(5, 8)},
		{name: "disjoint in one group", size: 100_000, ranges: RangeChunksMany(ChunkRange{Start: 2, End: 4}, ChunkRange{Start: 7, End: 9})},
		{name: "disjoint groups", size: 100_000, ranges: RangeChunksMany(ChunkRange{Start: 5, End: 7}, ChunkRange{Start: 21, End: 23})},
		{name: "open suffix", size: 100_000, ranges: RangeChunksFrom(94)},
		{name: "last partial chunk", size: 100_000, ranges: RangeLastChunk()},
		{name: "past end selects last chunk", size: 100_000, ranges: RangeChunks(200, 201)},
		{name: "all", size: 100_000, ranges: RangeAll()},
		{name: "empty blob size proof", size: 0, ranges: RangeLastChunk()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := vectorData(tt.size)
			hash := NewHash(data)
			store := mustStore(t, data)
			client, server := newTestBidiStreamPair()
			errch := make(chan error, 1)
			go func() { errch <- ServeBlob(context.Background(), server, store) }()

			got, size, err := GetBlobChunksBytes(context.Background(), client, hash, tt.ranges)
			if err != nil {
				t.Fatalf("GetBlobChunksBytes: %v", err)
			}
			if size != uint64(len(data)) {
				t.Fatalf("size = %d, want %d", size, len(data))
			}
			want := selectedBytes(data, tt.ranges)
			if !bytes.Equal(got, want) {
				t.Fatalf("selected data length = %d, want %d", len(got), len(want))
			}
			if err := <-errch; err != nil {
				t.Fatalf("ServeBlob: %v", err)
			}
		})
	}
}

func TestRangeChunksManyNormalizesRanges(t *testing.T) {
	ranges := RangeChunksMany(
		ChunkRange{Start: 8, End: 10},
		ChunkRange{Start: 2, End: 4},
		ChunkRange{Start: 4, End: 6},
		ChunkRange{Start: 7, End: 7},
	)
	want := []ChunkRange{{Start: 2, End: 6}, {Start: 8, End: 10}}
	got := ranges.Ranges()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ranges = %v, want %v", got, want)
	}
}

func TestEncodeBlobChunksVerifiesOutboardAndDecode(t *testing.T) {
	data := vectorData(100_000)
	hash := NewHash(data)
	outboard, gotHash := bao.EncodeBuf(data, 4, true)
	if Hash(gotHash) != hash {
		t.Fatalf("BAO root = %x, want %s", gotHash, hash)
	}
	ranges := RangeChunksMany(ChunkRange{Start: 5, End: 8}, ChunkRange{Start: 20, End: 24})
	var encoded bytes.Buffer
	if err := EncodeBlobChunks(&encoded, hash, uint64(len(data)), bytes.NewReader(data), bytes.NewReader(outboard), ranges); err != nil {
		t.Fatalf("EncodeBlobChunks: %v", err)
	}
	got, size, err := DecodeBlobChunks(hash, encoded.Bytes(), ranges)
	if err != nil {
		t.Fatalf("DecodeBlobChunks: %v", err)
	}
	if size != uint64(len(data)) || !bytes.Equal(got, selectedBytes(data, ranges)) {
		t.Fatalf("decoded size/data mismatch: size=%d bytes=%d", size, len(got))
	}
	corruptOutboard := append([]byte(nil), outboard...)
	corruptOutboard[8] ^= 1
	if err := EncodeBlobChunks(io.Discard, hash, uint64(len(data)), bytes.NewReader(data), bytes.NewReader(corruptOutboard), ranges); err == nil {
		t.Fatal("EncodeBlobChunks accepted corrupt outboard")
	}
	corruptProof := append([]byte(nil), encoded.Bytes()...)
	corruptProof[len(corruptProof)-1] ^= 1
	if _, _, err := DecodeBlobChunks(hash, corruptProof, ranges); err == nil {
		t.Fatal("DecodeBlobChunks accepted corrupt proof")
	}
	withTrailing := append(append([]byte(nil), encoded.Bytes()...), 0)
	if _, _, err := DecodeBlobChunks(hash, withTrailing, ranges); err == nil {
		t.Fatal("DecodeBlobChunks accepted trailing bytes")
	}
}

func TestSingleChunkRootCV(t *testing.T) {
	data := vectorData(ChunkSize)
	want := NewHash(data)
	got := Hash(cvBytes(chunkCV(data, 0, true)))
	if got != want {
		t.Fatalf("root CV = %x, want %s", got, want)
	}
}

func TestDecodeBlobChunksRejectsUnprovedSize(t *testing.T) {
	var prefix [8]byte
	binary.LittleEndian.PutUint64(prefix[:], ChunkSize)
	if _, _, err := DecodeBlobChunks(NewHash([]byte("some other blob")), prefix[:], RangeEmpty()); err == nil {
		t.Fatal("DecodeBlobChunks accepted a size without a proof")
	}
	if _, size, err := DecodeBlobChunks(EmptyHash, make([]byte, 8), RangeEmpty()); err != nil || size != 0 {
		t.Fatalf("empty blob size proof = %d, %v; want 0, nil", size, err)
	}
}

func TestDownloadBlobRangeBeyondEndDoesNotWrite(t *testing.T) {
	data := vectorData(ChunkSize)
	hash := NewHash(data)
	clientStream, server := newTestBidiStreamPair()
	client := cancelReadTestStream{clientStream}
	store := mustStore(t, data)
	errch := make(chan error, 1)
	go func() { errch <- ServeBlob(context.Background(), server, store) }()
	var out bytes.Buffer
	err := DownloadBlobRange(context.Background(), client, hash, 2*ChunkSize, ChunkSize, &out)
	if !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("DownloadBlobRange error = %v, want %v", err, ErrInvalidBlob)
	}
	if out.Len() != 0 {
		t.Fatalf("DownloadBlobRange wrote %d bytes for an invalid range", out.Len())
	}
	if err := <-errch; err == nil {
		t.Fatal("ServeBlob succeeded after the client canceled the unread response")
	}
}

type cancelReadTestStream struct{ *testBidiStream }

func (s cancelReadTestStream) CancelRead(uint64) { _ = s.r.Close() }

func TestBlobChunkRangeWritersRejectShortWrites(t *testing.T) {
	data := vectorData(ChunkSize + 17)
	hash := NewHash(data)
	outboard, _ := bao.EncodeBuf(data, 4, true)
	if err := EncodeBlobChunks(shortChunkWriter{}, hash, uint64(len(data)), bytes.NewReader(data), bytes.NewReader(outboard), RangeAll()); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("EncodeBlobChunks short write error = %v, want %v", err, io.ErrShortWrite)
	}
	var encoded bytes.Buffer
	if err := EncodeBlobChunks(&encoded, hash, uint64(len(data)), bytes.NewReader(data), bytes.NewReader(outboard), RangeAll()); err != nil {
		t.Fatalf("EncodeBlobChunks: %v", err)
	}
	if _, err := DecodeBlobChunksToWriter(hash, bytes.NewReader(encoded.Bytes()), RangeAll(), shortChunkWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("DecodeBlobChunksToWriter short write error = %v, want %v", err, io.ErrShortWrite)
	}
}

type shortChunkWriter struct{}

func (shortChunkWriter) Write([]byte) (int, error) { return 0, nil }

func TestEncodeBlobChunksAllMatchesFullEncoding(t *testing.T) {
	data := vectorData(100_000)
	hash, full, err := EncodeBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	outboard, _ := bao.EncodeBuf(data, 4, true)
	var ranged bytes.Buffer
	if err := EncodeBlobChunks(&ranged, hash, uint64(len(data)), bytes.NewReader(data), bytes.NewReader(outboard), RangeAll()); err != nil {
		t.Fatalf("EncodeBlobChunks: %v", err)
	}
	if !bytes.Equal(ranged.Bytes(), full) {
		t.Fatalf("all-range proof differs from full encoding: %d bytes, want %d", ranged.Len(), len(full))
	}
}

func selectedBytes(data []byte, ranges ChunkRanges) []byte {
	chunks := (uint64(len(data)) + ChunkSize - 1) / ChunkSize
	selection := selectChunks(ranges, chunks)
	var out []byte
	for _, r := range selection {
		lo := min(r[0]*ChunkSize, uint64(len(data)))
		hi := min(r[1]*ChunkSize, uint64(len(data)))
		out = append(out, data[lo:hi]...)
	}
	return out
}
