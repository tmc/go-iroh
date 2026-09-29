package runner

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"

	"github.com/tmc/go-iroh/blobs"
	"lukechampine.com/blake3/bao"
)

var baoScenarios = []string{
	"vectors/bao-range-proofs",
	"vectors/bao-chunk-ranges",
}

type baoCorpus struct {
	Vectors []baoVector `json:"bao"`
}

type baoVector struct {
	Size    uint64   `json:"size"`
	Name    string   `json:"name"`
	Ranges  []uint64 `json:"ranges"`
	Hash    string   `json:"hash"`
	Encoded string   `json:"encoded"`
}

// baoCells checks go-iroh's chunk-range proofs against bao-tree's. For each
// corpus vector, go-iroh must encode the same bytes for the same ranges of the
// same blob, and must verify bao-tree's encoding and decode it to the selected
// chunks. The first cell holds the vectors a single byte range can express; the
// second holds the rest (several spans, the chunk at infinity, or a start past
// the end, which is how iroh-blobs asks for a size proof).
func baoCells(corpus []byte, version, digest string, pid int, peer string, duration int64) []Cell {
	var vectors baoCorpus
	if err := json.Unmarshal(corpus, &vectors); err != nil || len(vectors.Vectors) == 0 {
		return vectorCellsFor(baoScenarios, version, SetupError, "decode bao vectors", digest, pid, peer)
	}
	var sets [2]struct {
		total                        int
		encodeDiffers, decodeRejects []string
	}
	for _, v := range vectors.Vectors {
		name := fmt.Sprintf("%d/%s", v.Size, v.Name)
		want, err := hex.DecodeString(v.Encoded)
		if err != nil {
			return vectorCellsFor(baoScenarios, version, SetupError, "decode bao vector "+name, digest, pid, peer)
		}
		set := &sets[1]
		if _, _, ok := baoByteRange(v.Ranges, v.Size); ok {
			set = &sets[0]
		}
		set.total++
		ranges, ok := baoChunkRanges(v.Ranges)
		if !ok {
			set.encodeDiffers = append(set.encodeDiffers, name)
			set.decodeRejects = append(set.decodeRejects, name)
			continue
		}
		data := baoData(v.Size)
		outboard, root := bao.EncodeBuf(data, 4, true)
		hash := blobs.Hash(root)
		var got bytes.Buffer
		err = blobs.EncodeBlobChunks(&got, hash, v.Size, bytes.NewReader(data), bytes.NewReader(outboard), ranges)
		if err != nil || hex.EncodeToString(hash[:]) != v.Hash || !bytes.Equal(got.Bytes(), want) {
			set.encodeDiffers = append(set.encodeDiffers, name)
		}
		decoded, size, err := blobs.DecodeBlobChunks(hash, want, ranges)
		if err != nil || size != v.Size || !bytes.Equal(decoded, baoSelected(data, v.Ranges)) {
			set.decodeRejects = append(set.decodeRejects, name)
		}
	}
	kinds := [2]string{"byte-range", "multi-span, infinite, and past-the-end chunk-range"}
	cells := make([]Cell, len(baoScenarios))
	for i, set := range sets {
		mismatched := slices.Compact(slices.Sorted(slices.Values(slices.Concat(set.encodeDiffers, set.decodeRejects))))
		cells[i] = Cell{
			Scenario: baoScenarios[i], Iroh: version, Result: verdictFor(mismatched),
			Detail: fmt.Sprintf("Go matched bao-tree on %d/%d %s proofs", set.total-len(mismatched), set.total, kinds[i]),
			Peer:   peer, PeerPID: pid, PeerDigest: digest, DurationMS: duration,
			Evidence: map[string]any{"encode_differs": set.encodeDiffers, "decode_rejects": set.decodeRejects},
		}
		if set.total == 0 {
			cells[i].Result, cells[i].Detail = SetupError, "corpus has no "+kinds[i]+" vectors"
		}
	}
	return cells
}

// baoChunkRanges converts bao-tree range-set boundaries to go-iroh chunk
// ranges: pairs are half-open spans and an odd final boundary opens a span
// to infinity. It reports false for spans followed by an open span, which
// go-iroh's constructors cannot combine and the corpus does not contain.
func baoChunkRanges(boundaries []uint64) (blobs.ChunkRanges, bool) {
	switch {
	case len(boundaries) == 1:
		return blobs.RangeChunksFrom(boundaries[0]), true
	case len(boundaries)%2 != 0:
		return blobs.ChunkRanges{}, false
	}
	var spans []blobs.ChunkRange
	for i := 0; i < len(boundaries); i += 2 {
		spans = append(spans, blobs.ChunkRange{Start: boundaries[i], End: boundaries[i+1]})
	}
	return blobs.RangeChunksMany(spans...), true
}

// baoSelected returns the bytes of data that bao-tree's encoding of the
// range-set boundaries carries: the selected chunks in order, where a span
// starting at or past the last chunk selects the last chunk.
func baoSelected(data []byte, boundaries []uint64) []byte {
	const chunkSize = 1024
	chunks := (uint64(len(data)) + chunkSize - 1) / chunkSize
	if chunks == 0 {
		return nil
	}
	selected := make([]bool, chunks)
	for i := 0; i < len(boundaries); i += 2 {
		start, end := boundaries[i], uint64(math.MaxUint64)
		if i+1 < len(boundaries) {
			end = boundaries[i+1]
		}
		if start >= chunks {
			start, end = chunks-1, chunks
		}
		for c := start; c < min(end, chunks); c++ {
			selected[c] = true
		}
	}
	var out []byte
	for c, ok := range selected {
		if ok {
			out = append(out, data[uint64(c)*chunkSize:min(uint64(c+1)*chunkSize, uint64(len(data)))]...)
		}
	}
	return out
}

// baoData returns the corpus blob of the given size: byte i is i mod 251.
func baoData(size uint64) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}

// baoByteRange returns the byte range that chunk range boundaries select in a
// blob of size bytes, if they form one span that starts inside the blob.
func baoByteRange(boundaries []uint64, size uint64) (offset, length uint64, ok bool) {
	const chunkSize = 1024
	if len(boundaries) == 0 || len(boundaries) > 2 {
		return 0, 0, false
	}
	start := boundaries[0]
	if start > (size-min(size, 1))/chunkSize {
		return 0, 0, false
	}
	end := size
	if len(boundaries) == 2 {
		end = min(boundaries[1]*chunkSize, size)
	}
	return start * chunkSize, end - start*chunkSize, true
}
