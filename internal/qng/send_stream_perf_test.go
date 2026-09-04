package quic

import (
	"bytes"
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

type sendStreamTestSender struct {
	streamData int
}

type sendStreamNotificationSender struct {
	streamData chan struct{}
}

func (s *sendStreamTestSender) onHasConnectionData() {}
func (s *sendStreamTestSender) onHasStreamData(protocol.StreamID, *SendStream) {
	s.streamData++
}
func (s *sendStreamNotificationSender) onHasConnectionData() {}
func (s *sendStreamNotificationSender) onHasStreamData(protocol.StreamID, *SendStream) {
	s.streamData <- struct{}{}
}
func (s *sendStreamNotificationSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (s *sendStreamNotificationSender) onStreamCompleted(protocol.StreamID) {}

func TestSendStreamCoalescesActiveNotifications(t *testing.T) {
	sender := new(sendStreamTestSender)
	str := newSendStream(context.Background(), 0, sender, testStreamFC(), false)
	for range 2 {
		if _, err := str.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := sender.streamData, 1; got != want {
		t.Fatalf("notifications before pop: got %d, want %d", got, want)
	}
	if frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1); frame.Frame == nil || more {
		t.Fatalf("popStreamFrame = (%v, more %t), want frame and no more", frame.Frame, more)
	}
	if _, err := str.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if got, want := sender.streamData, 2; got != want {
		t.Fatalf("notifications after pop: got %d, want %d", got, want)
	}
}
func (s *sendStreamTestSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (s *sendStreamTestSender) onStreamCompleted(protocol.StreamID) {}

func TestSendStreamConnectionWindowUpdateRequeuesPendingData(t *testing.T) {
	sender := &sendStreamTestSender{}
	str := newSendStream(context.Background(), 0, sender, testStreamFC(), false)

	str.mutex.Lock()
	str.dataForWriting = []byte("x")
	str.mutex.Unlock()

	str.onConnectionSendWindowUpdated()
	if sender.streamData != 1 {
		t.Fatalf("stream data notifications = %d, want 1", sender.streamData)
	}
}

func TestSendStreamConnectionWindowUpdateNoPendingData(t *testing.T) {
	sender := &sendStreamTestSender{}
	str := newSendStream(context.Background(), 0, sender, testStreamFC(), false)

	str.onConnectionSendWindowUpdated()
	if sender.streamData != 0 {
		t.Fatalf("stream data notifications = %d, want 0", sender.streamData)
	}
}

func TestSendStreamWriteBufferReliableCancel(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), true)
	if _, err := str.Write([]byte("reliable")); err != nil {
		t.Fatal(err)
	}
	str.SetReliableBoundary()
	if _, err := str.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	str.CancelWrite(1)

	frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame == nil || string(frame.Frame.Data) != "reliable" || more {
		t.Fatalf("popStreamFrame = (%v, more %t); want reliable data only", frame.Frame, more)
	}
	frame.Frame.PutBack()
}

func TestSendStreamWriteBufferUnreliableCancel(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), true)
	if _, err := str.Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	str.CancelWrite(1)
	frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame != nil || more {
		t.Fatalf("popStreamFrame = (%v, more %t); want no data", frame.Frame, more)
	}
}

func TestSendStreamWriteImmediateReturnUnlocks(t *testing.T) {
	shutdownErr := errors.New("shutdown")
	tests := []struct {
		name    string
		prepare func(*SendStream)
		p       []byte
		wantErr error
	}{
		{
			name: "reset",
			prepare: func(str *SendStream) {
				str.resetErr = &StreamError{StreamID: str.streamID, ErrorCode: 1}
			},
			p:       []byte("x"),
			wantErr: &StreamError{},
		},
		{
			name: "shutdown",
			prepare: func(str *SendStream) {
				str.shutdownErr = shutdownErr
			},
			p:       []byte("x"),
			wantErr: shutdownErr,
		},
		{
			name: "closed",
			prepare: func(str *SendStream) {
				str.finishedWriting = true
			},
			p: []byte("x"),
		},
		{
			name: "deadline",
			prepare: func(str *SendStream) {
				str.deadline = monotime.Now().Add(-time.Second)
			},
			p:       []byte("x"),
			wantErr: errDeadline,
		},
		{name: "empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
			if tt.prepare != nil {
				tt.prepare(str)
			}
			n, err := str.Write(tt.p)
			if n != 0 {
				t.Errorf("Write returned %d bytes, want 0", n)
			}
			switch tt.name {
			case "closed":
				if err == nil {
					t.Error("Write returned nil error")
				}
			case "reset":
				var streamErr *StreamError
				if !errors.As(err, &streamErr) {
					t.Errorf("Write error = %v, want StreamError", err)
				}
			default:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Write error = %v, want %v", err, tt.wantErr)
				}
			}
			if !str.mutex.TryLock() {
				t.Fatal("Write left stream mutex locked")
			}
			str.mutex.Unlock()
		})
	}
}

func TestSendStreamSerializesConcurrentWrites(t *testing.T) {
	sender := &sendStreamNotificationSender{streamData: make(chan struct{}, 1)}
	str := newSendStream(context.Background(), 0, sender, testStreamFC(), false)
	const (
		writers = 4
		writes  = 500
	)
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range writes {
				if n, err := str.Write([]byte("x")); n != 1 || err != nil {
					t.Errorf("Write = %d, %v; want 1, nil", n, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	var got int
	for {
		frame, _, more := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
		if frame.Frame != nil {
			got += len(frame.Frame.Data)
			frame.Frame.PutBack()
		}
		if !more {
			break
		}
	}
	if want := writers * writes; got != want {
		t.Fatalf("popped %d bytes, want %d", got, want)
	}
}

func TestSendStreamFastPathDeadlineFallsBack(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	if _, err := str.Write([]byte("warm")); err != nil {
		t.Fatal(err)
	}
	if err := str.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := str.Write([]byte("x")); !errors.Is(err, errDeadline) || n != 0 {
		t.Fatalf("Write with expired deadline = %d, %v; want 0, deadline error", n, err)
	}
	if err := str.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := str.Write([]byte("y")); err != nil || n != 1 {
		t.Fatalf("Write after clearing deadline = %d, %v; want 1, nil", n, err)
	}
}

func TestSendStreamFastPathCancelBetweenWrites(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	if _, err := str.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	str.CancelWrite(1)
	n, err := str.Write([]byte("after"))
	var streamErr *StreamError
	if !errors.As(err, &streamErr) || n != 0 {
		t.Fatalf("Write after CancelWrite = %d, %v; want 0, StreamError", n, err)
	}
}

func TestSendStreamFastPathCloseFlushesTail(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	want := []byte("buffered tail")
	if _, err := str.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	var got []byte
	var fin bool
	for {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame != nil {
			got = append(got, frame.Frame.Data...)
			fin = frame.Frame.Fin
			frame.Frame.PutBack()
		}
		if !more {
			break
		}
	}
	if !bytes.Equal(got, want) || !fin {
		t.Fatalf("popped %q fin=%v; want %q fin=true", got, fin, want)
	}
}

func TestSendStreamWriteCopiesCallerBuffer(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	p := []byte("immutable contract")
	want := append([]byte(nil), p...)
	if _, err := str.Write(p); err != nil {
		t.Fatal(err)
	}
	for i := range p {
		p[i] = 'X'
	}
	frame, _, _ := str.popStreamFrame(257, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	defer frame.Frame.PutBack()
	if !bytes.Equal(frame.Frame.Data, want) {
		t.Fatalf("frame data %q; want %q — stream retained the caller's buffer", frame.Frame.Data, want)
	}
}

func TestSendStreamWritevCopiesCallerBuffers(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	a, b := []byte("first"), []byte("second")
	want := []byte("firstsecond")
	bufs := net.Buffers{a, b}
	if n, err := str.Writev(&bufs); err != nil || n != int64(len(want)) {
		t.Fatalf("Writev = %d, %v; want %d, nil", n, err, len(want))
	}
	if len(bufs) != 0 {
		t.Fatalf("bufs not fully consumed: %d elements remain", len(bufs))
	}
	for i := range a {
		a[i] = 'X'
	}
	for i := range b {
		b[i] = 'X'
	}
	var got []byte
	for {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame != nil {
			got = append(got, frame.Frame.Data...)
			frame.Frame.PutBack()
		}
		if !more {
			break
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("popped %q; want %q — stream retained a caller buffer", got, want)
	}
}

func (s *sendStreamTestSender) onHasStreamRetransmission(protocol.StreamID, *SendStream)  {}
func (s *sendStreamTestSender) updateStreamPriority(protocol.StreamID)                    {}
func (s *sendStreamTestSender) recordStreamPriorityUpdated(protocol.StreamID, int8, bool) {}

func (s *sendStreamNotificationSender) onHasStreamRetransmission(protocol.StreamID, *SendStream) {
}
func (s *sendStreamNotificationSender) updateStreamPriority(protocol.StreamID)                    {}
func (s *sendStreamNotificationSender) recordStreamPriorityUpdated(protocol.StreamID, int8, bool) {}
func TestSendStreamWriteBufferPreservesOrder(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	want := bytes.Repeat([]byte("0123456789abcdef"), sendStreamWriteBufferSize/16)
	for p := want; len(p) > 0; {
		n := min(37, len(p))
		if got, err := str.Write(p[:n]); err != nil || got != n {
			t.Fatalf("Write = %d, %v; want %d, nil", got, err, n)
		}
		p = p[n:]
	}

	var got []byte
	for {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame != nil {
			got = append(got, frame.Frame.Data...)
			frame.Frame.PutBack()
		}
		if !more {
			break
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("popped data differs: got %d bytes, want %d", len(got), len(want))
	}
}

// fillSendStreamWriteBuffer fills str's write buffer to the demand-grown
// cap using cutoff-sized writes, which buffer and grow; a subsequent
// write must block.

func fillSendStreamWriteBuffer(t *testing.T, str *SendStream) {
	t.Helper()
	for total := 0; total < sendStreamWriteBufferMaxSize; total += maxBufferedWriteSize {
		if n, err := str.Write(make([]byte, maxBufferedWriteSize)); err != nil || n != maxBufferedWriteSize {
			t.Fatalf("fill Write = %d, %v", n, err)
		}
	}
}

func TestSendStreamWriteBufferDeadline(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := str.Write(make([]byte, 2*sendStreamWriteBufferMaxSize))
		done <- result{n: n, err: err}
	}()
	waitForBlockedSendStreamWrite(t, str, done)
	frame, _, _ := str.popStreamFrame(257, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	wantN := len(frame.Frame.Data)
	frame.Frame.PutBack()
	if err := str.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.n != wantN || !errors.Is(r.err, errDeadline) {
			t.Fatalf("Write = %d, %v; want %d, deadline error", r.n, r.err, wantN)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not unblock after deadline")
	}
}

func TestSendStreamWriteBufferFin(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	if _, err := str.Write(make([]byte, sendStreamWriteBufferSize)); err != nil {
		t.Fatal(err)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; ; i++ {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame == nil {
			t.Fatal("popStreamFrame returned no frame")
		}
		if frame.Frame.Fin != !more {
			t.Fatalf("frame %d: Fin = %t, more = %t; FIN must appear only on last frame", i, frame.Frame.Fin, more)
		}
		frame.Frame.PutBack()
		if !more {
			break
		}
	}
}

func TestSendStreamConcurrentWriteWaitsForBlockedWriter(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	fillSendStreamWriteBuffer(t, str)
	type result struct {
		n   int
		err error
	}
	first := make(chan result, 1)
	go func() {
		n, err := str.Write([]byte("a"))
		first <- result{n: n, err: err}
	}()
	waitForBlockedSendStreamWrite(t, str, first)
	second := make(chan result, 1)
	go func() {
		n, err := str.Write([]byte("b"))
		second <- result{n: n, err: err}
	}()

	frame, _, _ := str.popStreamFrame(257, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	got := append([]byte(nil), frame.Frame.Data...)
	frame.Frame.PutBack()
	for name, done := range map[string]<-chan result{"first": first, "second": second} {
		select {
		case r := <-done:
			if r.n != 1 || r.err != nil {
				t.Errorf("%s Write = %d, %v; want 1, nil", name, r.n, r.err)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s Write did not complete", name)
		}
	}
	for {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame != nil {
			got = append(got, frame.Frame.Data...)
			frame.Frame.PutBack()
		}
		if !more {
			break
		}
	}
	if want := sendStreamWriteBufferMaxSize + 2; len(got) != want {
		t.Fatalf("popped %d bytes, want %d", len(got), want)
	}
	if tail := string(got[len(got)-2:]); tail != "ab" {
		t.Fatalf("popped tail %q, want %q", tail, "ab")
	}
}

func TestSendStreamFastPathBufferBoundary(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	for i := 0; i < 3; i++ {
		if n, err := str.Write(make([]byte, maxBufferedWriteSize)); err != nil || n != maxBufferedWriteSize {
			t.Fatalf("fill Write = %d, %v", n, err)
		}
	}
	if n, err := str.Write(make([]byte, maxBufferedWriteSize-1)); err != nil || n != maxBufferedWriteSize-1 {
		t.Fatalf("near-full Write = %d, %v", n, err)
	}
	// One byte still fits the buffer; two must block until a frame is popped.
	if n, err := str.Write([]byte("a")); err != nil || n != 1 {
		t.Fatalf("boundary Write = %d, %v; want 1, nil", n, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if n, err := str.Write([]byte("bc")); err != nil || n != 2 {
			t.Errorf("straddling Write = %d, %v; want 2, nil", n, err)
		}
	}()
	waitForBlockedSendStreamWrite(t, str, done)
	select {
	case <-done:
		t.Fatal("straddling Write returned without buffer space")
	default:
	}
	frame, _, _ := str.popStreamFrame(257, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	frame.Frame.PutBack()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("straddling Write did not unblock")
	}
}

func TestSendStreamWritevPartialConsumption(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	// Element 0 fits the buffer; element 1 straddles it and blocks; the
	// deadline then fires mid-element. bufs must reflect exactly the
	// consumed prefix, including the partial element.
	el0 := bytes.Repeat([]byte("a"), maxBufferedWriteSize-8)
	el1 := bytes.Repeat([]byte("b"), 4*sendStreamWriteBufferMaxSize)
	bufs := net.Buffers{el0, el1}
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := str.Writev(&bufs)
		done <- result{n, err}
	}()
	waitForBlockedSendStreamWrite(t, str, done)
	// Pop enough small frames to drain past el0 and partway into el1.
	for popped := 0; popped <= len(el0)+maxBufferedWriteSize/2; {
		frame, _, _ := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame == nil {
			t.Fatal("popStreamFrame returned no frame")
		}
		popped += len(frame.Frame.Data)
		frame.Frame.PutBack()
	}
	if err := str.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	var r result
	select {
	case r = <-done:
	case <-time.After(time.Second):
		t.Fatal("Writev did not unblock after deadline")
	}
	if !errors.Is(r.err, errDeadline) {
		t.Fatalf("Writev error = %v; want deadline error", r.err)
	}
	if r.n <= int64(len(el0)) || r.n >= int64(len(el0)+len(el1)) {
		t.Fatalf("Writev consumed %d bytes; want a mid-element count in (%d, %d)", r.n, len(el0), len(el0)+len(el1))
	}
	remaining := int64(len(el0)+len(el1)) - r.n
	if len(bufs) != 1 || int64(len(bufs[0])) != remaining {
		t.Fatalf("bufs after partial = %d elements, first %d bytes; want 1 element of %d bytes", len(bufs), len(bufs[0]), remaining)
	}
	if bufs[0][0] != 'b' {
		t.Fatalf("remaining element starts with %q; want 'b'", bufs[0][0])
	}
}

func TestSendStreamReadFrom(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	want := bytes.Repeat([]byte("0123456789abcdef"), sendStreamWriteBufferSize/16/2)
	n, err := str.ReadFrom(bytes.NewReader(want))
	if err != nil || n != int64(len(want)) {
		t.Fatalf("ReadFrom = %d, %v; want %d, nil", n, err, len(want))
	}
	var got []byte
	for {
		frame, _, more := str.popStreamFrame(257, protocol.Version1)
		if frame.Frame != nil {
			got = append(got, frame.Frame.Data...)
			frame.Frame.PutBack()
		}
		if !more {
			break
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("popped %d bytes; want %d", len(got), len(want))
	}
}

func TestSendStreamWriteBufferDemandGrowth(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	if _, err := str.Write(make([]byte, 100)); err != nil {
		t.Fatal(err)
	}
	str.mutex.Lock()
	limit := str.writeBufferLimitLocked()
	str.mutex.Unlock()
	if limit != sendStreamWriteBufferSize {
		t.Fatalf("limit after small write = %d, want %d (no speculative growth)", limit, sendStreamWriteBufferSize)
	}
	if _, err := str.Write(make([]byte, sendStreamWriteBufferSize)); err != nil {
		t.Fatal(err)
	}
	str.mutex.Lock()
	limit = str.writeBufferLimitLocked()
	str.mutex.Unlock()
	if limit != 2*sendStreamWriteBufferSize {
		t.Fatalf("limit after first overflow = %d, want %d (geometric doubling)", limit, 2*sendStreamWriteBufferSize)
	}
	for i := 0; i < 3; i++ {
		if _, err := str.Write(make([]byte, maxBufferedWriteSize)); err != nil {
			t.Fatal(err)
		}
	}
	str.mutex.Lock()
	limit = str.writeBufferLimitLocked()
	str.mutex.Unlock()
	if limit != sendStreamWriteBufferMaxSize {
		t.Fatalf("limit under sustained pressure = %d, want cap %d", limit, sendStreamWriteBufferMaxSize)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = str.Write(make([]byte, maxBufferedWriteSize))
	}()
	waitForBlockedSendStreamWrite(t, str, done)
	select {
	case <-done:
		t.Fatal("Write past the cap returned without buffer space")
	default:
	}
	str.closeForShutdown(errors.New("test done"))
	<-done
}

func TestSendStreamWriteBufferBackpressure(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	fillSendStreamWriteBuffer(t, str)

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := str.Write([]byte("x"))
		done <- result{n: n, err: err}
	}()
	waitForBlockedSendStreamWrite(t, str, done)
	select {
	case r := <-done:
		t.Fatalf("Write returned without buffer space: %d, %v", r.n, r.err)
	default:
	}

	frame, _, _ := str.popStreamFrame(257, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	frame.Frame.PutBack()
	select {
	case r := <-done:
		if r.n != 1 || r.err != nil {
			t.Fatalf("unblocked Write = %d, %v; want 1, nil", r.n, r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not unblock after buffer space became available")
	}
}

func TestSendStreamWriteBufferShutdown(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	fillSendStreamWriteBuffer(t, str)
	done := make(chan error, 1)
	go func() {
		_, err := str.Write([]byte("x"))
		done <- err
	}()
	waitForBlockedSendStreamWrite(t, str, done)
	want := errors.New("shutdown")
	str.closeForShutdown(want)
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("Write error = %v; want %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not unblock on shutdown")
	}
}

// waitForBlockedSendStreamWrite waits until the Write running in another
// goroutine parks with data still to send. done is the channel that goroutine
// sends on when Write returns, which is the only other thing that can happen:
// waiting for one of the two events keeps the wait from having to guess how
// long a parked writer takes to become visible.
func waitForBlockedSendStreamWrite[T any](t *testing.T, str *SendStream, done <-chan T) {
	t.Helper()
	for {
		select {
		case <-done:
			t.Fatal("Write did not block")
		default:
		}
		str.mutex.Lock()
		blocked := str.dataForWriting != nil
		str.mutex.Unlock()
		if blocked {
			return
		}
		runtime.Gosched()
	}
}

// TestSendStreamWriteBufferFlowControlCharge checks that a frame built from the
// write buffer is charged for exactly the bytes it carries. Charging for the
// larger blocked write queued behind the buffer leaks send window on every
// packet, and the connection stalls with the writer parked and nothing to send.
func TestSendStreamWriteBufferFlowControlCharge(t *testing.T) {
	str := newSendStream(context.Background(), 0, new(sendStreamTestSender), testStreamFC(), false)
	if _, err := str.Write([]byte("buffered")); err != nil {
		t.Fatal(err)
	}
	// A write too large to buffer parks behind the buffered bytes.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = str.Write(make([]byte, 4*maxBufferedWriteSize))
	}()
	waitForBlockedSendStreamWrite(t, str, done)

	before := str.flowController.SendWindowSize()
	frame, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
	if frame.Frame == nil {
		t.Fatal("popStreamFrame returned no frame")
	}
	sent := protocol.ByteCount(frame.Frame.DataLen())
	frame.Frame.PutBack()
	if got, want := before-str.flowController.SendWindowSize(), sent; got != want {
		t.Fatalf("flow control charged %d bytes for a %d byte frame", got, want)
	}
}
