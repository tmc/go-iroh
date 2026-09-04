package quic

import (
	"net"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

type orderedSendConn struct {
	writes  chan byte
	release chan struct{}
}

func (c *orderedSendConn) Write(p []byte, _ uint16, _ protocol.ECN) error {
	c.writes <- p[0]
	if p[0] == 1 {
		<-c.release
	}
	return nil
}

func (*orderedSendConn) WriteTo([]byte, net.Addr, packetInfo) error { return nil }
func (*orderedSendConn) Close() error                               { return nil }
func (*orderedSendConn) LocalAddr() net.Addr                        { return &net.UDPAddr{} }
func (*orderedSendConn) RemoteAddr() net.Addr                       { return &net.UDPAddr{} }
func (*orderedSendConn) ChangeRemoteAddr(net.Addr, packetInfo)      {}
func (*orderedSendConn) capabilities() connCapabilities             { return connCapabilities{} }

func TestSendQueueDoesNotInlinePastInFlightWrite(t *testing.T) {
	conn := &orderedSendConn{writes: make(chan byte, 2), release: make(chan struct{})}
	queue := newSendQueue(conn).(*sendQueue)
	done := make(chan error, 1)
	go func() { done <- queue.Run() }()

	first := getPacketBuffer()
	first.Data = append(first.Data, 1)
	queue.Send(first, 1, protocol.ECNUnsupported)
	if got := <-conn.writes; got != 1 {
		t.Fatalf("first write = %d, want 1", got)
	}
	if len(queue.queue) != 0 {
		t.Fatal("worker did not dequeue first write")
	}

	second := getPacketBuffer()
	second.Data = append(second.Data, 2)
	queue.Send(second, 0, protocol.ECNUnsupported)
	select {
	case got := <-conn.writes:
		t.Fatalf("write %d started before first write completed", got)
	default:
	}
	close(conn.release)
	select {
	case got := <-conn.writes:
		if got != 2 {
			t.Fatalf("second write = %d, want 2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("second write did not start")
	}

	queue.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
