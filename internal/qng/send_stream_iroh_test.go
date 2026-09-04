package quic

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
)

type sendStreamIrohSender struct{}

func (sendStreamIrohSender) onHasConnectionData()                           {}
func (sendStreamIrohSender) onHasStreamData(protocol.StreamID, *SendStream) {}
func (sendStreamIrohSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
}
func (sendStreamIrohSender) onStreamCompleted(protocol.StreamID) {}

// drainSendStream pops frames in the background until the stream sends FIN,
// then reports the bytes the stream put on the wire. Write blocks until the
// data has been packetized, so the drain has to run concurrently with it.
func drainSendStream(str *SendStream) <-chan []byte {
	ch := make(chan []byte, 1)
	go func() {
		var got []byte
		for {
			frame, _, _ := str.popStreamFrame(protocol.MaxPacketBufferSize, protocol.Version1)
			if frame.Frame == nil {
				time.Sleep(time.Millisecond)
				continue
			}
			got = append(got, frame.Frame.Data...)
			fin := frame.Frame.Fin
			frame.Frame.PutBack()
			if fin {
				ch <- got
				return
			}
		}
	}()
	return ch
}

func TestSendStreamReadFrom(t *testing.T) {
	str := newSendStream(context.Background(), 0, sendStreamIrohSender{}, testStreamFC(), false)
	got := drainSendStream(str)
	want := bytes.Repeat([]byte("0123456789abcdef"), readFromChunkSize/16+3)
	if n, err := str.ReadFrom(bytes.NewReader(want)); err != nil || n != int64(len(want)) {
		t.Fatalf("ReadFrom = %d, %v; want %d, nil", n, err, len(want))
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(<-got, want) {
		t.Fatal("stream did not deliver the bytes ReadFrom read")
	}
}

func TestSendStreamWritevConsumesBuffers(t *testing.T) {
	str := newSendStream(context.Background(), 0, sendStreamIrohSender{}, testStreamFC(), false)
	got := drainSendStream(str)
	bufs := net.Buffers{[]byte("hello "), nil, []byte("wor"), []byte("ld")}
	n, err := str.Writev(&bufs)
	if err != nil || n != 11 {
		t.Fatalf("Writev = %d, %v; want 11, nil", n, err)
	}
	if len(bufs) != 0 {
		t.Fatalf("bufs = %v, want fully consumed", bufs)
	}
	if err := str.Close(); err != nil {
		t.Fatal(err)
	}
	if s := string(<-got); s != "hello world" {
		t.Fatalf("stream delivered %q, want %q", s, "hello world")
	}
}

func TestSendStreamWritevStopsOnError(t *testing.T) {
	str := newSendStream(context.Background(), 0, sendStreamIrohSender{}, testStreamFC(), false)
	str.closeForShutdown(io.ErrClosedPipe)
	bufs := net.Buffers{[]byte("a"), []byte("b")}
	if n, err := str.Writev(&bufs); err == nil || n != 0 {
		t.Fatalf("Writev on a shut-down stream = %d, %v; want 0, error", n, err)
	}
	if len(bufs) != 2 {
		t.Fatalf("bufs = %v, want untouched", bufs)
	}
}
