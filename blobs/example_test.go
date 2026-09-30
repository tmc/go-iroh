package blobs_test

import (
	"bytes"
	"context"
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"lukechampine.com/blake3/bao"
)

func Example() {
	id, _ := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	hash, _ := blobs.ParseHash("0b84d358e4c8be6c38626b2182ff575818ba6bd3f4b90464994be14cb354a072")
	ticket := blobs.NewTicket(netaddr.NewEndpointAddr(id), hash, blobs.Raw)

	parsed, _ := blobs.ParseTicket(ticket.String())
	fmt.Println(parsed.Hash() == hash, parsed.Format())
	// Output: true Raw
}

func ExampleEncodeBlob() {
	hash, encoded, _ := blobs.EncodeBlob([]byte("hello"))
	data, _ := blobs.DecodeBlob(hash, encoded)
	fmt.Println(string(data))
	// Output: hello
}

func ExampleRangeChunksMany() {
	ranges := blobs.RangeChunksMany(
		blobs.ChunkRange{Start: 2, End: 4},
		blobs.ChunkRange{Start: 7, End: 9},
	)
	fmt.Println(ranges.Ranges())
	// Output: [{2 4} {7 9}]
}

func ExampleRangeChunksFrom() {
	start, ok := blobs.RangeChunksFrom(3).OpenStart()
	fmt.Println(start, ok)
	// Output: 3 true
}

func ExampleEncodeBlobChunks() {
	data := []byte("hello")
	hash, outboard := exampleChunkBlob(data)
	var encoded bytes.Buffer
	err := blobs.EncodeBlobChunks(
		&encoded, hash, uint64(len(data)),
		bytes.NewReader(data), bytes.NewReader(outboard),
		blobs.RangeChunks(0, 1),
	)
	fmt.Println(err, encoded.Len())
	// Output: <nil> 13
}

func ExampleDecodeBlobChunks() {
	hash, ranges, encoded := exampleChunkProof()
	data, size, err := blobs.DecodeBlobChunks(hash, encoded, ranges)
	fmt.Println(string(data), size, err)
	// Output: hello 5 <nil>
}

func ExampleDecodeBlobChunksToWriter() {
	hash, ranges, encoded := exampleChunkProof()
	var data bytes.Buffer
	size, err := blobs.DecodeBlobChunksToWriter(hash, bytes.NewReader(encoded), ranges, &data)
	fmt.Println(data.String(), size, err)
	// Output: hello 5 <nil>
}

func ExampleDownloadBlobChunks() {
	hash, ranges, encoded := exampleChunkProof()
	stream := &exampleBlobStream{Reader: bytes.NewReader(encoded)}
	var data bytes.Buffer
	size, err := blobs.DownloadBlobChunks(context.Background(), stream, hash, ranges, &data)
	fmt.Println(data.String(), size, err)
	// Output: hello 5 <nil>
}

func ExampleGetBlobChunksBytes() {
	hash, ranges, encoded := exampleChunkProof()
	stream := &exampleBlobStream{Reader: bytes.NewReader(encoded)}
	data, size, err := blobs.GetBlobChunksBytes(context.Background(), stream, hash, ranges)
	fmt.Println(string(data), size, err)
	// Output: hello 5 <nil>
}

type exampleBlobStream struct {
	*bytes.Reader
	request bytes.Buffer
}

func (s *exampleBlobStream) Write(p []byte) (int, error) { return s.request.Write(p) }
func (s *exampleBlobStream) Close() error                { return nil }
func (s *exampleBlobStream) CloseWrite() error           { return nil }

func exampleChunkBlob(data []byte) (blobs.Hash, []byte) {
	outboard, hash := bao.EncodeBuf(data, 4, true)
	return blobs.Hash(hash), outboard
}

func exampleChunkProof() (blobs.Hash, blobs.ChunkRanges, []byte) {
	data := []byte("hello")
	hash, outboard := exampleChunkBlob(data)
	ranges := blobs.RangeChunks(0, 1)
	var encoded bytes.Buffer
	if err := blobs.EncodeBlobChunks(
		&encoded, hash, uint64(len(data)),
		bytes.NewReader(data), bytes.NewReader(outboard), ranges,
	); err != nil {
		panic(err)
	}
	return hash, ranges, encoded.Bytes()
}
