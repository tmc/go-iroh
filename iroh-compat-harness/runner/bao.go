package runner

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/tmc/go-iroh/blobs"
)

const baoScenario = "vectors/bao-range-proofs"

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

// baoCell checks go-iroh's range proofs against bao-tree's. For each corpus
// vector, go-iroh must encode the same bytes for the same range of the same
// blob and must verify and decode bao-tree's encoding. Ranges that go-iroh's
// byte-offset API cannot express (several spans, or a start past the end) are
// listed as unchecked and do not affect the verdict.
func baoCell(corpus []byte, version, digest string, pid int, peer string, duration int64) Cell {
	var vectors baoCorpus
	if err := json.Unmarshal(corpus, &vectors); err != nil || len(vectors.Vectors) == 0 {
		return Cell{Scenario: baoScenario, Iroh: version, Result: SetupError, Detail: "decode bao vectors", Peer: peer, PeerPID: pid, PeerDigest: digest}
	}
	var encodeDiffers, decodeRejects, unchecked []string
	for _, v := range vectors.Vectors {
		name := fmt.Sprintf("%d/%s", v.Size, v.Name)
		offset, length, ok := baoByteRange(v.Ranges, v.Size)
		if !ok {
			unchecked = append(unchecked, name)
			continue
		}
		data := baoData(v.Size)
		hash, got, err := blobs.EncodeBlobRange(data, offset, length)
		if err != nil || hex.EncodeToString(hash[:]) != v.Hash || hex.EncodeToString(got) != v.Encoded {
			encodeDiffers = append(encodeDiffers, name)
		}
		want, err := hex.DecodeString(v.Encoded)
		if err != nil {
			return Cell{Scenario: baoScenario, Iroh: version, Result: SetupError, Detail: "decode bao vector " + name, Peer: peer, PeerPID: pid, PeerDigest: digest}
		}
		decoded, err := blobs.DecodeBlobRange(hash, want, offset, length)
		if err != nil || !slices.Equal(decoded, data[offset:offset+length]) {
			decodeRejects = append(decodeRejects, name)
		}
	}
	mismatched := slices.Compact(slices.Sorted(slices.Values(slices.Concat(encodeDiffers, decodeRejects))))
	checked := len(vectors.Vectors) - len(unchecked)
	return Cell{
		Scenario: baoScenario, Iroh: version, Result: verdictFor(mismatched),
		Detail: fmt.Sprintf("Go matched bao-tree on %d/%d range proofs (%d not expressible as a byte range)", checked-len(mismatched), checked, len(unchecked)),
		Peer:   peer, PeerPID: pid, PeerDigest: digest, DurationMS: duration,
		Evidence: map[string]any{"encode_differs": encodeDiffers, "decode_rejects": decodeRejects, "unchecked": unchecked},
	}
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
