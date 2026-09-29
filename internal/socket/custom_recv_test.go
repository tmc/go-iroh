package socket

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
)

// burstTransport pushes n datagrams at recv, signalling calling before each
// call and reporting each result on results.
type burstTransport struct {
	n       int
	calling chan int
	results chan bool
}

func (t *burstTransport) Serve(ctx context.Context, recv func(CustomDatagram) bool) {
	for i := range t.n {
		t.calling <- i
		t.results <- recv(CustomDatagram{
			Remote: netaddr.NewCustomAddr(7, []byte("peer")),
			Data:   []byte("x"),
		})
	}
	<-ctx.Done()
}

func (t *burstTransport) Send(netaddr.CustomAddr, *netaddr.CustomAddr, []byte) bool { return true }

// TestCustomTransportRecvBlocks pins the recv contract: when the receive queue
// is full, recv waits for room instead of dropping the datagram, and reports
// false only once ctx is done.
func TestCustomTransportRecvBlocks(t *testing.T) {
	const queue = 2
	recvCh := make(chan recvBatch, queue)
	fake := &burstTransport{n: queue + 2, calling: make(chan int, queue+2), results: make(chan bool, queue+2)}
	ct := newCustomTransport(fake, recvCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ct.Serve(ctx)

	for i := range queue {
		<-fake.calling
		if !<-fake.results {
			t.Fatalf("recv %d = false, want true while the queue has room", i)
		}
	}
	<-fake.calling // the recv into the full queue has begun
	select {
	case ok := <-fake.results:
		t.Fatalf("recv into a full queue returned %v, want it to wait", ok)
	case <-time.After(50 * time.Millisecond):
	}

	<-recvCh // make room
	if !<-fake.results {
		t.Fatal("recv after the queue drained = false, want true")
	}

	<-fake.calling
	cancel()
	if <-fake.results {
		t.Fatal("recv after ctx is done = true, want false")
	}
}
