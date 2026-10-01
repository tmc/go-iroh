package quic

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

// countingStreamSender records how many times the stream woke the sender.
type countingStreamSender struct {
	sendStreamIrohSender
	mu    sync.Mutex
	wakes int
	ch    chan struct{}
}

func (c *countingStreamSender) onHasStreamData(protocol.StreamID, *SendStream) {
	c.mu.Lock()
	c.wakes++
	c.mu.Unlock()
	select {
	case c.ch <- struct{}{}:
	default:
	}
}

func (c *countingStreamSender) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wakes
}

func newCorkTestStream() (*SendStream, *countingStreamSender) {
	s := &countingStreamSender{ch: make(chan struct{}, 16)}
	return newSendStream(context.Background(), 0, s, testStreamFC(), false), s
}

// An isolated write must reach the sender immediately. Corking every write
// would add the tail delay to the request half of a ping-pong.
func TestSendStreamIsolatedWriteWakesSenderImmediately(t *testing.T) {
	str, sender := newCorkTestStream()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != 1 {
		t.Fatalf("sender woken %d times, want 1", got)
	}
}

// A stream drained in the middle of a burst is corked: the next write must not
// wake the sender on its own, so the writes behind it can fill a packet.
func TestSendStreamCorksAfterBurstDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		str, sender := newCorkTestStream()
		for range sendStreamBurstMinWrites {
			if _, err := str.Write(make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
		}
		drainOnce(t, str)
		armBurst(str)
		before := sender.count()
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if got := sender.count(); got != before {
			t.Fatalf("sender woken %d times after the burst drain, want 0: the write was not corked", got-before)
		}
		str.mutex.Lock()
		corked := str.corkPending
		str.mutex.Unlock()
		if !corked {
			t.Fatal("corkPending not set")
		}
	})
}

// A stream drained after only a few writes is not in a burst, so the next
// write is not corked.
func TestSendStreamDoesNotCorkOutsideABurst(t *testing.T) {
	str, sender := newCorkTestStream()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	drainOnce(t, str)
	before := sender.count()
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if got := sender.count(); got != before+1 {
		t.Fatalf("sender woken %d times, want 1: an isolated write must not be corked", got-before)
	}
}

// The cork is released early once the buffer holds a packet's worth, so the
// tail delay never holds back data that is already ready to send.
func TestSendStreamCorkReleasesAtThreshold(t *testing.T) {
	// Hold off the tail delay, so a wakeup during the loop below can only be
	// the threshold releasing the cork and never the timer expiring. Without
	// this the test is a race between the two under -race.
	defer func(d time.Duration) { sendStreamTailDelay = d }(sendStreamTailDelay)
	sendStreamTailDelay = time.Minute

	str, sender := newCorkTestStream()
	for range sendStreamBurstMinWrites {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	drainOnce(t, str)
	armBurst(str)
	before := sender.count()
	// Writes of 32 bytes each, until the buffer crosses the threshold.
	for i := range sendStreamActivationThreshold/32 + 2 {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if sender.count() > before {
			str.mutex.Lock()
			buffered := str.bufferedWriteLen()
			str.mutex.Unlock()
			if buffered < sendStreamActivationThreshold {
				t.Fatalf("uncorked after write %d with only %d bytes buffered, want >= %d", i, buffered, sendStreamActivationThreshold)
			}
			return
		}
	}
	t.Fatalf("never uncorked after %d bytes buffered", sendStreamActivationThreshold+64)
}

// A corked write must still reach the sender when the tail delay expires;
// otherwise a stream that stops writing mid-burst stalls.
func TestSendStreamCorkTimerWakesSender(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		str, sender := newCorkTestStream()
		for range sendStreamBurstMinWrites {
			if _, err := str.Write(make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
		}
		drainOnce(t, str)
		armBurst(str)
		// Discard wakeups from the burst above, so the receive below can only
		// observe a wakeup caused by the corked write's timer.
		for len(sender.ch) > 0 {
			<-sender.ch
		}
		before := sender.count()
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if sender.count() != before {
			t.Fatal("write was not corked, so this test would not exercise the timer")
		}
		select {
		case <-sender.ch:
		case <-time.After(2 * time.Second):
			t.Fatal("cork timer never woke the sender: a stream that stops writing mid-burst would stall")
		}
	})
}

// armBurst puts the stream in the state a burst drain leaves it in, without
// depending on sendStreamBurstFreshness (10us) still being unexpired by the
// time the test gets to its next write.
func armBurst(str *SendStream) {
	str.mutex.Lock()
	str.burstUntil = monotime.Now().Add(time.Minute)
	str.mutex.Unlock()
}

// drainOnce pops frames until the stream reports no more data, which is what
// ends a burst episode.
func drainOnce(t *testing.T, str *SendStream) {
	t.Helper()
	for range 100 {
		_, _, hasMore := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
		if !hasMore {
			return
		}
	}
	t.Fatal("stream never drained")
}

// A write too large to buffer takes the blocking path, which hands the stream
// straight to the sender. It must drop a pending cork on the way. Otherwise
// the timer outlives the episode, and since activateOrDelayLocked arms one
// only while the field is nil, the next cork gets no timer of its own: its
// deadline is still the first cork's, so the tail delay it was supposed to
// wait out is skipped.
func TestSendStreamLargeWriteDropsPendingCork(t *testing.T) {
	// A 5us tail delay would fire on its own during the drain below and clear
	// the field for the wrong reason.
	defer func(d time.Duration) { sendStreamTailDelay = d }(sendStreamTailDelay)
	sendStreamTailDelay = time.Minute

	str, _ := newCorkTestStream()
	corkOnce := func() (gen uint64) {
		t.Helper()
		armBurst(str)
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		str.mutex.Lock()
		defer str.mutex.Unlock()
		if !str.corkPending || str.activationTimer == nil {
			t.Fatalf("write not corked: corkPending=%v timer armed=%v", str.corkPending, str.activationTimer != nil)
		}
		return str.activationGen
	}

	for range sendStreamBurstMinWrites {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	drainOnce(t, str)
	first := corkOnce()

	// The blocking path parks until the packetizer takes the data, so drain
	// alongside it.
	done := make(chan error, 1)
	go func() { _, err := str.Write(make([]byte, maxBufferedWriteSize+1)); done <- err }()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("large write: %v", err)
			}
			drainOnce(t, str)
			str.mutex.Lock()
			armed := str.activationTimer != nil
			str.mutex.Unlock()
			if armed {
				t.Fatal("cork timer still armed after the episode ended")
			}
			if second := corkOnce(); second == first {
				t.Fatalf("the next cork reused generation %d, so it got no timer of its own", second)
			}
			return
		default:
			str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
		}
	}
}

// CancelWrite with a reliable boundary keeps sending the bytes below that
// boundary, so it has to reach the sender. On a corked stream both ways of
// doing that are gone at once: the branch itself only queues the control
// frame, and the pending cork timer -- the one wakeup that would otherwise
// still fire -- bails because CancelWrite has just set resetErr. The reliable
// bytes are then buffered on a stream the sender does not know about.
func TestSendStreamCancelWriteWithReliableBoundaryWakesCorkedStream(t *testing.T) {
	// Keep the cork timer from firing on its own and waking the sender for a
	// reason this test is not about.
	defer func(d time.Duration) { sendStreamTailDelay = d }(sendStreamTailDelay)
	sendStreamTailDelay = time.Minute

	str, sender := newCorkTestStream()
	str.enableResetStreamAt()
	for range sendStreamBurstMinWrites {
		if _, err := str.Write(make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	drainOnce(t, str)

	armBurst(str)
	if _, err := str.Write(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	str.mutex.Lock()
	corked := str.corkPending && !str.active
	str.mutex.Unlock()
	if !corked {
		t.Fatal("write was not corked, so the test is not exercising the hazard")
	}

	str.SetReliableBoundary()
	before := sender.count()
	str.CancelWrite(7)

	if got := sender.count(); got == before {
		f, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
		if f.Frame != nil && f.Frame.DataLen() > 0 {
			t.Fatalf("sender was not woken, yet the stream still holds %d reliable bytes", f.Frame.DataLen())
		}
		t.Fatal("sender was not woken after CancelWrite with a reliable boundary")
	}
}
