package quic

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// waitForParkedWrite waits until a blocking write has registered its data, so
// the packetizer below runs against a write that is actually in flight.
func waitForParkedWrite(t *testing.T, str *SendStream) {
	t.Helper()
	for range 1000 {
		str.mutex.Lock()
		parked := str.dataForWriting != nil
		str.mutex.Unlock()
		if parked {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("write never parked")
}

// The limiter meters one WriteWithLimit call. Bytes an earlier ordinary Write
// left in the write buffer are not that call's bytes, so packetizing them must
// not consult the limiter or spend its credit: a caller that budgets 25 bytes
// has said nothing about the 6 bytes somebody else wrote before it.
//
// The write buffer is a go-iroh addition, and it is what makes this reachable.
// popNewStreamFrameForPacket decides a write is limited by writeLimiter != nil
// && nextFrame == nil. Upstream puts a small write in nextFrame, so the check
// excludes it; here the same write lands in the buffer instead, which the check
// does not look at.
func TestSendStreamWriteWithLimitIgnoresBufferedBytes(t *testing.T) {
	sender := &countingStreamSender{ch: make(chan struct{}, 16)}
	str := newSendStream(t.Context(), 0, sender, testStreamFC(), false)

	if _, err := str.Write([]byte("header")); err != nil {
		t.Fatal(err)
	}

	var (
		mu    sync.Mutex
		calls []int
	)
	done := make(chan error, 1)
	data := bytes.Repeat([]byte("x"), 40)
	go func() {
		_, err := str.WriteWithLimit(data, func(maxBytes int) int {
			mu.Lock()
			calls = append(calls, maxBytes)
			mu.Unlock()
			return min(maxBytes, 25)
		})
		done <- err
	}()
	waitForParkedWrite(t, str)

	f, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	mu.Lock()
	seen := append([]int(nil), calls...)
	mu.Unlock()

	if f.Frame == nil {
		t.Fatal("no frame popped")
	}
	if !bytes.Equal(f.Frame.Data, []byte("header")) {
		t.Errorf("first frame = %q at offset %d, want the buffered %q", f.Frame.Data, f.Frame.Offset, "header")
	}
	if len(seen) != 0 {
		t.Errorf("limiter consulted %d times (maxBytes %v) while packetizing bytes written before it", len(seen), seen)
	}
}

// The same confusion, in its damaging form. A limiter with no credit to give
// used to set writeLimited while the frame on offer was built from the write
// buffer, and popNewStreamFrameForPacket returns early on writeLimited: the
// stream reported hasMoreData false with an earlier write's bytes still
// queued, so a scheduler that believes it drops the stream.
func TestSendStreamWriteWithLimitRefusalLeavesBufferedBytesSchedulable(t *testing.T) {
	sender := &countingStreamSender{ch: make(chan struct{}, 16)}
	str := newSendStream(t.Context(), 0, sender, testStreamFC(), false)

	if _, err := str.Write([]byte("header")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := str.WriteWithLimit(bytes.Repeat([]byte("x"), 40), func(int) int {
			return 0 // no external credit at all
		})
		done <- err
	}()
	waitForParkedWrite(t, str)

	f, _, hasMore := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if f.Frame == nil {
		str.mutex.Lock()
		buffered := str.bufferedWriteLen()
		str.mutex.Unlock()
		t.Fatalf("no frame popped with %d buffered bytes queued, hasMoreData = %v", buffered, hasMore)
	}
	if !bytes.Equal(f.Frame.Data, []byte("header")) {
		t.Errorf("first frame = %q, want the buffered %q", f.Frame.Data, "header")
	}
	if hasMore == sendStateIdle {
		t.Error("sendState = idle with a limited write still parked behind the buffer")
	}

	// Now the buffer is empty, so the next frame really is the limited write's,
	// and refusing it is the limiter's business.
	if f, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1); f.Frame != nil {
		t.Errorf("second frame = %q, want nothing: the limiter gave no credit", f.Frame.Data)
	}
	if err := <-done; err != ErrWriteLimitReached {
		t.Errorf("WriteWithLimit err = %v, want %v", err, ErrWriteLimitReached)
	}
}

// The same over-metering defect through the other staging area: bytes an
// earlier ordinary Write left in nextFrame are not the limited write's data
// either. Upstream's `s.nextFrame == nil` term is what stops it, and nothing
// in this module tests that term.
func TestSendStreamWriteWithLimitIgnoresStagedBytes(t *testing.T) {
	str := newSendStream(t.Context(), 0, sendStreamIrohSender{}, testStreamFC(), false)

	// A deadline makes write() skip both buffered paths, so the remainder of a
	// parked write lands in nextFrame the way it does upstream.
	str.SetWriteDeadline(time.Now().Add(30 * time.Second))
	big := bytes.Repeat([]byte("h"), 4000)
	done := make(chan error, 1)
	go func() { _, err := str.Write(big); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("the write never staged anything in nextFrame")
		}
		str.mutex.Lock()
		staged := str.nextFrame != nil
		remaining := len(str.dataForWriting)
		str.mutex.Unlock()
		if staged {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the write returned (err=%v) without staging anything in nextFrame", err)
		default:
		}
		// Once the remainder fits a packet the write stages it itself; popping
		// again would take it back off before it is observed.
		if remaining > 0 && remaining <= protocol.MaxPacketBufferSize {
			runtime.Gosched()
			continue
		}
		f, _, _ := str.popStreamFrame(600, protocol.Version1)
		if f.Frame != nil {
			f.Frame.PutBack()
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("staging write: %v", err)
	}
	str.mutex.Lock()
	nf := str.nextFrame != nil
	buffered := str.bufferedWriteLen()
	str.mutex.Unlock()
	if !nf || buffered != 0 {
		t.Fatalf("setup did not reach the state under test: nextFrame staged = %v, buffered = %d bytes, want staged with an empty buffer", nf, buffered)
	}

	str.SetWriteDeadline(time.Time{})
	var (
		mu    sync.Mutex
		calls []int
	)
	limited := make(chan error, 1)
	go func() {
		_, err := str.WriteWithLimit(bytes.Repeat([]byte("x"), 40), func(maxBytes int) int {
			mu.Lock()
			calls = append(calls, maxBytes)
			mu.Unlock()
			return min(maxBytes, 25)
		})
		limited <- err
	}()
	waitForParkedWrite(t, str)

	f, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	mu.Lock()
	seen := append([]int(nil), calls...)
	mu.Unlock()
	if f.Frame == nil {
		t.Fatal("no frame popped")
	}
	if !bytes.Equal(f.Frame.Data, bytes.Repeat([]byte("h"), len(f.Frame.Data))) {
		t.Errorf("frame carried %q, want the earlier write's bytes", f.Frame.Data)
	}
	if len(seen) != 0 {
		t.Errorf("limiter consulted %d times (maxBytes %v) for bytes staged in nextFrame by an earlier Write", len(seen), seen)
	}
}
