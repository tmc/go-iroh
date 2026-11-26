package quic

import (
	"bytes"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
)

// testStreamFCWindow returns a flow controller whose send window starts at
// sendWindow, so a writer can be parked and later released by updateSendWindow.
func testStreamFCWindow(sendWindow protocol.ByteCount) *streamFlowController {
	const window = protocol.ByteCount(1) << 40
	cfc := newConnectionFlowController(window, window, nil, utils.NewRTTStats(), utils.DefaultLogger)
	cfc.UpdateSendWindow(window)
	return newStreamFlowController(0, cfc, window, window, sendWindow, utils.NewRTTStats(), utils.DefaultLogger)
}

// popped records a frame taken off the stream.
type popped struct {
	offset protocol.ByteCount
	data   []byte
}

// checkStreamCoverage reports whether the popped frames tile want exactly:
// every byte covered once, in the right place, with no gap, overlap or
// duplicate. This is the property that a write taken out of order would break,
// and it does not depend on knowing which interleaving broke it.
func checkStreamCoverage(t *testing.T, frames []popped, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	seen := make([]bool, len(want))
	for _, f := range frames {
		off := int(f.offset)
		if off < 0 || off+len(f.data) > len(want) {
			t.Fatalf("frame at offset %d length %d runs outside the %d bytes written", off, len(f.data), len(want))
		}
		for i, b := range f.data {
			if seen[off+i] {
				t.Fatalf("byte at offset %d sent twice", off+i)
			}
			seen[off+i] = true
			got[off+i] = b
		}
	}
	for i, ok := range seen {
		if !ok {
			t.Fatalf("byte at offset %d never sent (%d frames, %d bytes written)", i, len(frames), len(want))
		}
	}
	if !bytes.Equal(got, want) {
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("byte at offset %d is %#x, want %#x", i, got[i], want[i])
			}
		}
	}
}

// The stream must hand the packetizer every byte exactly once, in the right
// place, while writes and packetization interleave. writeFast takes writes
// without holding writeOnce, so the guards in it are what keep the buffered
// bytes and a parked blocking write's bytes in offset order; this checks the
// resulting byte stream rather than the guards, so it can catch an ordering
// hazard without being told which one to look for.
//
// It does not reach nextFrame, the third place a stream can hold data, and no
// sequence of plain Writes would: see
// TestSendStreamOffsetOrderStagedFrameAheadOfWriteBuffer for why, and for the
// interleaving that does reach it.
func TestSendStreamOffsetIntegrityUnderConcurrentDrain(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sendWindow protocol.ByteCount // 0 means an effectively unlimited window
	}{
		{name: "unconstrained"},
		{name: "flow control parks the writer", sendWindow: 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := &countingStreamSender{ch: make(chan struct{}, 16)}
			fc := testStreamFC()
			if tc.sendWindow != 0 {
				fc = testStreamFCWindow(tc.sendWindow)
			}
			str := newSendStream(t.Context(), 0, sender, fc, false)

			rnd := rand.New(rand.NewSource(1))
			var want []byte
			for len(want) < 1<<18 {
				// Mostly small writes, which take the fast path, and
				// occasionally one too large to buffer, which parks in the
				// blocking path and sets dataForWriting.
				n := 1 + rnd.Intn(64)
				if rnd.Intn(64) == 0 {
					n = maxBufferedWriteSize + 1 + rnd.Intn(4096)
				}
				chunk := make([]byte, n)
				for i := range chunk {
					chunk[i] = byte(len(want) + i)
				}
				want = append(want, chunk...)
			}

			var (
				mu     sync.Mutex
				frames []popped
			)
			done := make(chan struct{})

			// The packetizer: pop with a varying budget so frames split at
			// unaligned boundaries, and open the window as bytes are sent.
			var drain sync.WaitGroup
			drain.Add(1)
			go func() {
				defer drain.Done()
				drnd := rand.New(rand.NewSource(2))
				var sent protocol.ByteCount
				for {
					// The packetizer never asks for more than one packet's
					// worth, which is what a pooled frame can hold.
					budget := protocol.ByteCount(1 + drnd.Intn(int(protocol.MaxPacketBufferSize)))
					f, _, _ := str.popStreamFrame(budget, protocol.Version1)
					if f.Frame != nil && f.Frame.DataLen() > 0 {
						data := append([]byte(nil), f.Frame.Data...)
						mu.Lock()
						frames = append(frames, popped{offset: f.Frame.Offset, data: data})
						mu.Unlock()
						sent += f.Frame.DataLen()
						if tc.sendWindow != 0 {
							str.updateSendWindow(sent + tc.sendWindow)
						}
						continue
					}
					select {
					case <-done:
						// The writer has finished. Drain whatever is left.
						f, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
						if f.Frame != nil && f.Frame.DataLen() > 0 {
							data := append([]byte(nil), f.Frame.Data...)
							mu.Lock()
							frames = append(frames, popped{offset: f.Frame.Offset, data: data})
							mu.Unlock()
							sent += f.Frame.DataLen()
							if tc.sendWindow != 0 {
								str.updateSendWindow(sent + tc.sendWindow)
							}
							continue
						}
						if more == sendStateIdle {
							return
						}
					default:
					}
				}
			}()

			// A single writer: concurrent Write is not permitted.
			deadline := time.Now().Add(30 * time.Second)
			for off := 0; off < len(want); {
				n := 1 + rnd.Intn(64)
				if rnd.Intn(64) == 0 {
					n = maxBufferedWriteSize + 1 + rnd.Intn(4096)
				}
				n = min(n, len(want)-off)
				if _, err := str.Write(want[off : off+n]); err != nil {
					t.Errorf("write at offset %d: %v", off, err)
					break
				}
				off += n
				if time.Now().After(deadline) {
					t.Errorf("writer did not finish within 30s at offset %d", off)
					break
				}
			}
			close(done)
			drain.Wait()

			mu.Lock()
			defer mu.Unlock()
			checkStreamCoverage(t, frames, want)
		})
	}
}

// TryWriteAll queues into nextFrame, which is drained ahead of the write
// buffer, so it must refuse rather than queue behind buffered bytes it would
// then be sent in front of. Write and TryWriteAll are both exported and may be
// mixed; nothing about the hazard needs concurrency.
func TestSendStreamTryWriteAllRefusesBehindBufferedWrite(t *testing.T) {
	sender := &countingStreamSender{ch: make(chan struct{}, 16)}
	str := newSendStream(t.Context(), 0, sender, testStreamFC(), false)

	if _, err := str.Write([]byte("AAAAAAAA")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := str.TryWriteAll([]byte("BBBBBBBB")); err != ErrWouldBlock {
		t.Fatalf("TryWriteAll behind a buffered write = %v, want %v", err, ErrWouldBlock)
	}

	// Refusing must queue nothing, including flow control credit, so the same
	// write succeeds once the buffer has drained.
	var frames []popped
	for range 8 {
		f, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
		if f.Frame != nil && f.Frame.DataLen() > 0 {
			frames = append(frames, popped{offset: f.Frame.Offset, data: append([]byte(nil), f.Frame.Data...)})
		}
		if more == sendStateIdle {
			break
		}
	}
	if err := str.TryWriteAll([]byte("BBBBBBBB")); err != nil {
		t.Fatalf("TryWriteAll after the drain: %v", err)
	}
	f, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if f.Frame != nil && f.Frame.DataLen() > 0 {
		frames = append(frames, popped{offset: f.Frame.Offset, data: append([]byte(nil), f.Frame.Data...)})
	}
	checkStreamCoverage(t, frames, []byte("AAAAAAAABBBBBBBB"))
}

// nextFrame is drained ahead of the write buffer, so bytes staged there while
// the buffer is occupied would go out in front of older bytes. canBufferStreamFrame
// refuses for exactly that reason, and this is the interleaving that depends on it.
//
// Reaching nextFrame at all takes a write deadline. The fork's write buffer
// added a retry branch ahead of the staging branch in write's loop, and
// between them the two are mutually exclusive for a plain Write: the retry
// branch takes anything up to maxBufferedWriteSize (16384), and
// canBufferStreamFrame caps what it will stage at MaxPacketBufferSize (1452),
// so a write is always small enough for the first or too large for the second.
// A deadline is one of the three things that skips the retry branch -- a write
// limiter and a write buffer too full to grow are the others -- which is what
// makes upstream's staging path reachable here.
func TestSendStreamOffsetOrderStagedFrameAheadOfWriteBuffer(t *testing.T) {
	sender := &countingStreamSender{ch: make(chan struct{}, 16)}
	str := newSendStream(t.Context(), 0, sender, testStreamFC(), false)

	// Fills the write buffer: no deadline yet, so this takes the retry branch.
	if _, err := str.Write([]byte("AAAA")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := str.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	// With the retry branch skipped, this write can only be staged into
	// nextFrame, which it must not be while "AAAA" is still buffered. It parks
	// until the drain below empties the buffer, then stages at the right offset.
	done := make(chan error, 1)
	go func() {
		_, err := str.Write([]byte("BBBB"))
		done <- err
	}()

	// Nothing has been popped, so on correct code this write cannot finish: the
	// only place left for it is nextFrame, and staging there is refused while
	// the buffer is occupied. Completing early is the defect itself, and is a
	// sharper signal than the byte order, which a concurrent drain can hide by
	// emptying the buffer before the write looks at it.
	select {
	case err := <-done:
		str.mutex.Lock()
		staged := str.nextFrame
		str.mutex.Unlock()
		if err == nil && staged != nil {
			t.Fatalf("write finished before anything drained, staging %q at offset %d behind %d buffered bytes",
				staged.Data, staged.Offset, str.bufferedWriteLen())
		}
		t.Fatalf("write finished before anything drained: err=%v", err)
	case <-time.After(50 * time.Millisecond):
	}

	var frames []popped
	deadline := time.After(10 * time.Second)
	for len(frames) < 2 {
		select {
		case <-deadline:
			t.Fatalf("stream never produced both frames, got %d", len(frames))
		default:
		}
		f, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
		if f.Frame != nil && f.Frame.DataLen() > 0 {
			frames = append(frames, popped{offset: f.Frame.Offset, data: append([]byte(nil), f.Frame.Data...)})
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("deadline write: %v", err)
	}
	checkStreamCoverage(t, frames, []byte("AAAABBBB"))
}
