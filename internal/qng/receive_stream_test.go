package quic

import (
	"io"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

type receiveStreamTestSender struct{}

func (receiveStreamTestSender) onHasConnectionData()                           {}
func (receiveStreamTestSender) onHasStreamData(protocol.StreamID, *SendStream) {}
func (receiveStreamTestSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (receiveStreamTestSender) onStreamCompleted(protocol.StreamID) {}

// testStreamFC is a stream flow controller with windows wide enough that
// flow control never blocks the tests that use it.
func testStreamFC() *streamFlowController {
	const window = protocol.ByteCount(1) << 40
	cfc := newConnectionFlowController(window, window, nil, utils.NewRTTStats(), utils.DefaultLogger)
	cfc.UpdateSendWindow(window)
	return newStreamFlowController(0, cfc, window, window, window, utils.NewRTTStats(), utils.DefaultLogger)
}

func newReceiveStreamForTest() *ReceiveStream {
	return newReceiveStream(0, receiveStreamTestSender{}, testStreamFC())
}

func TestReceiveStreamInOrderFrameRead(t *testing.T) {
	s := newReceiveStreamForTest()
	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	n, err := s.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || buf[0] != 'a' {
		t.Fatalf("Read = %d, %q; want 1, a", n, buf[:n])
	}
}

func TestReceiveStreamBlockedReadDirectHandoff(t *testing.T) {
	s := newReceiveStreamForTest()

	type result struct {
		n   int
		err error
		buf [1]byte
	}
	done := make(chan result, 1)
	go func() {
		var buf [1]byte
		n, err := s.Read(buf[:])
		done <- result{n: n, err: err, buf: buf}
	}()

	var waiting bool
	for i := 0; i < 100; i++ {
		s.mutex.Lock()
		waiting = s.pendingRead != nil
		s.mutex.Unlock()
		if waiting {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !waiting {
		t.Fatal("Read did not block")
	}

	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.n != 1 || got.buf[0] != 'a' {
			t.Fatalf("Read = %d, %q; want 1, a", got.n, got.buf[:got.n])
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not complete")
	}
	if s.frameQueue.HasMoreData() {
		t.Fatal("direct handoff left data queued")
	}
}

func TestReceiveStreamDuplicateAfterInOrderRead(t *testing.T) {
	s := newReceiveStreamForTest()
	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if _, err := s.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	dup := &wire.StreamFrame{StreamID: 0, Data: []byte("b")}
	if err := s.handleStreamFrame(dup, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if s.frameQueue.HasMoreData() {
		t.Fatal("duplicate data queued after in-order read")
	}
}

func TestReceiveStreamOutOfOrderFallback(t *testing.T) {
	s := newReceiveStreamForTest()
	later := &wire.StreamFrame{StreamID: 0, Offset: 1, Data: []byte("b")}
	if err := s.handleStreamFrame(later, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	first := &wire.StreamFrame{StreamID: 0, Data: []byte("a")}
	if err := s.handleStreamFrame(first, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [2]byte
	n, err := s.Read(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || string(buf[:]) != "ab" {
		t.Fatalf("Read = %d, %q; want 2, ab", n, buf[:])
	}
}

func TestReceiveStreamFinAfterInOrderFrame(t *testing.T) {
	s := newReceiveStreamForTest()
	frame := &wire.StreamFrame{StreamID: 0, Data: []byte("a"), Fin: true}
	if err := s.handleStreamFrame(frame, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [2]byte
	n, err := s.Read(buf[:])
	if err != io.EOF {
		t.Fatalf("Read err = %v, want EOF", err)
	}
	if n != 1 || buf[0] != 'a' {
		t.Fatalf("Read = %d, %q; want 1, a", n, buf[:n])
	}
}

type receiveStreamCompletionSender struct {
	completed chan protocol.StreamID
}

func (receiveStreamCompletionSender) onHasConnectionData()                           {}
func (receiveStreamCompletionSender) onHasStreamData(protocol.StreamID, *SendStream) {}
func (receiveStreamCompletionSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (s receiveStreamCompletionSender) onStreamCompleted(id protocol.StreamID) {
	select {
	case s.completed <- id:
	default:
	}
}

// A FIN that arrives with no new readable bytes while the reader is parked in
// Read must still complete the stream: completion is what deletes the stream
// from the incoming streams map and grants the peer MAX_STREAMS credit, so a
// missed completion permanently leaks a stream slot.
func TestReceiveStreamLateFinWhileBlockedCompletesStream(t *testing.T) {
	sender := receiveStreamCompletionSender{completed: make(chan protocol.StreamID, 1)}
	s := newReceiveStream(0, sender, testStreamFC())

	if err := s.handleStreamFrame(&wire.StreamFrame{StreamID: 0, Data: []byte("a")}, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if n, err := s.Read(buf[:]); n != 1 || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}

	readErr := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := s.Read(b[:])
		readErr <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the reader park in Read

	// The FIN arrives late, carrying no new data (retransmission after the
	// reader drained the stream).
	if err := s.handleStreamFrame(&wire.StreamFrame{StreamID: 0, Offset: 1, Fin: true}, monotime.Now()); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-readErr:
		if err != io.EOF {
			t.Fatalf("Read err = %v, want io.EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not return")
	}
	select {
	case <-sender.completed:
	case <-time.After(time.Second):
		t.Fatal("stream never completed: MAX_STREAMS credit is never granted")
	}
}

// Control case: the same late FIN with the reader not parked.
func TestReceiveStreamLateFinCompletesStream(t *testing.T) {
	sender := receiveStreamCompletionSender{completed: make(chan protocol.StreamID, 1)}
	s := newReceiveStream(0, sender, testStreamFC())
	if err := s.handleStreamFrame(&wire.StreamFrame{StreamID: 0, Data: []byte("a")}, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if n, err := s.Read(buf[:]); n != 1 || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if err := s.handleStreamFrame(&wire.StreamFrame{StreamID: 0, Offset: 1, Fin: true}, monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(buf[:]); err != io.EOF {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	select {
	case <-sender.completed:
	case <-time.After(time.Second):
		t.Fatal("stream never completed")
	}
}
