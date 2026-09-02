package socket

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// burstTransport pushes n datagrams at recv without reading anything back and
// records what recv reported, plus whether ctx was done at that moment.
type burstTransport struct {
	n       int
	results []bool
	ctxDone []bool
	done    chan struct{}
}

func (t *burstTransport) Serve(ctx context.Context, recv func(CustomDatagram) bool) {
	defer close(t.done)
	for range t.n {
		ok := recv(CustomDatagram{
			Remote: netaddr.NewCustomAddr(7, []byte("peer")),
			Data:   []byte("x"),
		})
		t.results = append(t.results, ok)
		t.ctxDone = append(t.ctxDone, ctx.Err() != nil)
	}
}

func (t *burstTransport) Send(netaddr.CustomAddr, *netaddr.CustomAddr, []byte) bool { return true }

// TestCustomTransportRecvFalseIsNotShutdown pins the recv contract: under a
// burst that outruns the receive queue, recv reports false while ctx is still
// live. A transport that reads false as "shutting down" and returns would tear
// itself down on the first burst; shutdown is reported through ctx alone.
func TestCustomTransportRecvFalseIsNotShutdown(t *testing.T) {
	const queue = 2
	recvCh := make(chan recvBatch, queue)
	fake := &burstTransport{n: queue + 4, done: make(chan struct{})}
	ct := newCustomTransport(fake, recvCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ct.Serve(ctx)

	select {
	case <-fake.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}

	if got := len(fake.results); got != queue+4 {
		t.Fatalf("recv called %d times, want %d", got, queue+4)
	}
	for i := range queue {
		if !fake.results[i] {
			t.Errorf("recv %d = false, want true while the queue has room", i)
		}
	}
	sawDrop := false
	for i := queue; i < len(fake.results); i++ {
		if fake.results[i] {
			continue
		}
		sawDrop = true
		if fake.ctxDone[i] {
			t.Errorf("recv %d reported false with ctx already done", i)
		}
	}
	if !sawDrop {
		t.Fatal("no datagram was dropped; the queue never filled")
	}
	if len(recvCh) != queue {
		t.Errorf("queued %d datagrams, want %d", len(recvCh), queue)
	}
}
