package quic

import "github.com/tmc/go-iroh/internal/qng/internal/protocol"

// The write buffer is a go-iroh addition. Upstream returns from Write only
// once the data has been packetized, or once it fits the single-packet
// nextFrame; a stream written in small pieces therefore pays a wakeup per
// write. The buffer lets Write copy into stream-owned storage and return, so
// a burst of small writes costs one wakeup instead of one per write.
//
// Three places can hold unsent stream data, and they are drained in this
// order, which is also age order:
//
//	nextFrame      staged by a blocking write, oldest
//	writeBuffer    appended by the buffered fast path
//	dataForWriting the write currently blocked, newest
//
// Two rules keep that order true. The fast path appends only while no
// blocking write holds writeActive, so its bytes cannot land between an older
// write's staged bytes and the rest of that write. And canBufferStreamFrame
// refuses to extend nextFrame while the buffer holds data, so a later write
// cannot append bytes to nextFrame that are newer than buffered ones.

const (
	// sendStreamWriteBufferSize is the initial write buffer limit.
	sendStreamWriteBufferSize = 4096
	// sendStreamWriteBufferMaxSize caps the demand-grown write buffer limit.
	// Only streams under sustained full-buffer pressure reach it; it bounds
	// the worst-case buffered-unsent bytes on cancel.
	sendStreamWriteBufferMaxSize = 65536
	// maxBufferedWriteSize is the largest single write that buffers (and
	// grows the buffer). Larger writes keep the blocking path, whose frames
	// copy straight from the caller's slice — routing them through the
	// buffer would add a full extra copy per write.
	maxBufferedWriteSize = sendStreamWriteBufferMaxSize / 4
)

func (s *SendStream) bufferedWriteLen() int {
	return len(s.writeBuffer) - s.writeBufferHead
}

// writeBufferLimitLocked returns the current demand-grown buffer limit
// without growing it. The caller holds s.mutex.
func (s *SendStream) writeBufferLimitLocked() int {
	if s.writeBufferLimit == 0 {
		return sendStreamWriteBufferSize
	}
	return s.writeBufferLimit
}

// growWriteBufferFor reports whether n more bytes fit the write buffer,
// doubling the demand-grown limit toward the cap when they do not. Growth
// happens only here, on the write path, never on the drain side. The caller
// holds s.mutex.
func (s *SendStream) growWriteBufferFor(n int) bool {
	limit := s.writeBufferLimitLocked()
	need := s.bufferedWriteLen() + n
	for need > limit && limit < sendStreamWriteBufferMaxSize {
		limit *= 2
	}
	s.writeBufferLimit = limit
	return need <= limit
}

func (s *SendStream) appendWriteBuffer(p []byte) {
	if s.writeBuffer == nil {
		s.writeBuffer = make([]byte, 0, sendStreamWriteBufferSize)
	}
	if cap(s.writeBuffer)-len(s.writeBuffer) < len(p) {
		copy(s.writeBuffer, s.writeBuffer[s.writeBufferHead:])
		s.writeBuffer = s.writeBuffer[:s.bufferedWriteLen()]
		s.writeBufferHead = 0
	}
	s.writeBuffer = append(s.writeBuffer, p...)
}

// dropWriteBuffer discards buffered data. The caller holds s.mutex.
func (s *SendStream) dropWriteBuffer() {
	s.writeBuffer = nil
	s.writeBufferHead = 0
}

// takeWriteBuffer copies up to maxBytes buffered bytes into f, reporting how
// many it took. The caller holds s.mutex.
func (s *SendStream) takeWriteBuffer(p []byte) int {
	n := min(s.bufferedWriteLen(), len(p))
	if n == 0 {
		return 0
	}
	copy(p, s.writeBuffer[s.writeBufferHead:s.writeBufferHead+n])
	s.writeBufferHead += n
	if s.writeBufferHead == len(s.writeBuffer) {
		s.writeBuffer = s.writeBuffer[:0]
		s.writeBufferHead = 0
	}
	return n
}

// bufferStartOffset is the stream offset of the first buffered byte. The
// caller holds s.mutex.
func (s *SendStream) bufferStartOffset() protocol.ByteCount {
	offset := s.writeOffset
	if s.nextFrame != nil {
		offset += s.nextFrame.DataLen()
	}
	return offset
}
