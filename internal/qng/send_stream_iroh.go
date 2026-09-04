package quic

import (
	"io"
	"net"
)

// readFromChunkSize is the size of the staging buffer ReadFrom copies through.
const readFromChunkSize = 64 * 1024

// ReadFrom implements [io.ReaderFrom]. It reads from r until EOF or error,
// writing to the stream in chunks. Data is copied into stream-owned storage
// before each chunk write returns.
func (s *SendStream) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, readFromChunkSize)
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			wn, werr := s.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

// Writev writes the buffers in order. It returns the total number of bytes
// written and advances bufs to reflect exactly what was consumed, including a
// partially written element, so the caller can resume after a short write.
// The stream copies data into owned storage before Writev returns; the caller
// may reuse the underlying slices immediately.
//
// Writev does not hold the stream for the whole vector: another writer may
// interleave between elements. The delivered byte stream is identical to the
// equivalent sequence of Write calls.
//
// To send a [net.Buffers], call Writev directly: [net.Buffers] implements
// [io.WriterTo], which [io.Copy] prefers over [io.ReaderFrom], so
// io.Copy(stream, &bufs) degrades to one Write call per element.
func (s *SendStream) Writev(bufs *net.Buffers) (int64, error) {
	var total int64
	var err error
	for _, p := range *bufs {
		if len(p) == 0 {
			continue
		}
		var n int
		n, err = s.Write(p)
		total += int64(n)
		if err != nil {
			break
		}
	}
	consumed := total
	for consumed > 0 && len(*bufs) > 0 {
		if n := int64(len((*bufs)[0])); consumed >= n {
			consumed -= n
			*bufs = (*bufs)[1:]
			continue
		}
		(*bufs)[0] = (*bufs)[0][consumed:]
		consumed = 0
	}
	if total > 0 && len(*bufs) > 0 && err == nil {
		err = io.ErrShortWrite
	}
	return total, err
}
