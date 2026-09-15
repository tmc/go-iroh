//go:build linux

package socket

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestIpTransportGROCoalesces exercises the UDP_GRO receive path against a
// UDP_SEGMENT sender on loopback: the kernel must hand the run of equally sized
// datagrams to one read, and Serve must queue it as a single strided recvBatch
// that ReadFrom can split back into the original datagrams.
func TestIpTransportGROCoalesces(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	recvCh := make(chan recvBatch, 16)
	tr := NewIpTransport(udp, recvCh)
	if !tr.gro {
		t.Skip("UDP_GRO not available on this kernel")
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	const (
		segSize = 1200
		segs    = 8
	)
	payload := make([]byte, segSize*segs)
	for i := range payload {
		payload[i] = byte('a' + i/segSize)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Serve(ctx)

	dst := udp.LocalAddr().(*net.UDPAddr)
	if _, _, err := sender.WriteMsgUDP(payload, udpSegmentMessage(segSize), dst); err != nil {
		t.Fatalf("segmented write: %v", err)
	}

	var got []byte
	coalesced := false
	deadline := time.After(10 * time.Second)
	for len(got) < len(payload) {
		select {
		case b := <-recvCh:
			segs := batchSegments(b)
			if len(segs) > 1 {
				coalesced = true
			}
			for i, seg := range segs {
				if len(seg) != segSize {
					t.Errorf("segment %d is %d bytes, want %d", i, len(seg), segSize)
				}
				got = append(got, seg...)
			}
			b.release()
		case <-deadline:
			t.Fatalf("got %d of %d bytes", len(got), len(payload))
		}
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("received %d bytes, not the bytes sent", len(got))
	}
	if !coalesced {
		t.Errorf("no read returned more than one datagram: UDP_GRO did not coalesce")
	}
}

// TestGROSegmentSize checks the control-message parse the receive path splits by.
func TestGROSegmentSize(t *testing.T) {
	for _, test := range []struct {
		name string
		oob  []byte
		want int
	}{
		{name: "none"},
		{name: "segment", oob: groSegmentMessage(1200), want: 1200},
		{name: "other cmsg then segment", oob: append(udpSegmentMessage(7), groSegmentMessage(1452)...), want: 1452},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := groSegmentSize(test.oob); got != test.want {
				t.Fatalf("groSegmentSize = %d, want %d", got, test.want)
			}
		})
	}
}

// groSegmentMessage builds the UDP_GRO control message the kernel returns.
func groSegmentMessage(size int32) []byte {
	const dataLen = 4
	b := make([]byte, unix.CmsgSpace(dataLen))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	header.Level = syscall.IPPROTO_UDP
	header.Type = unix.UDP_GRO
	header.SetLen(unix.CmsgLen(dataLen))
	*(*int32)(unsafe.Pointer(&b[unix.CmsgSpace(0)])) = size
	return b
}

// TestIpTransportGRORecordsArrivalAddress pins the intersection of the two
// receive-side features: a wildcard-bound socket must still record the local
// address a run arrived at, even when the kernel hands the whole run to one
// read. The GRO loop is a second receive loop, so the arrival-address bookkeeping
// the ordinary loop does is not inherited -- without it a reply to this peer
// would leave from whatever address the route picks.
func TestIpTransportGRORecordsArrivalAddress(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	recvCh := make(chan recvBatch, 16)
	tr := NewIpTransport(udp, recvCh)
	if !tr.gro {
		t.Skip("UDP_GRO not available on this kernel")
	}
	if !tr.pktinfo {
		t.Skip("no arrival address on this kernel")
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	const (
		segSize = 1200
		segs    = 8
	)
	payload := make([]byte, segSize*segs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Serve(ctx)

	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udp.LocalAddr().(*net.UDPAddr).Port}
	if _, _, err := sender.WriteMsgUDP(payload, udpSegmentMessage(segSize), dst); err != nil {
		t.Fatalf("segmented write: %v", err)
	}

	coalesced := false
	got := 0
	deadline := time.After(10 * time.Second)
	for got < len(payload) {
		select {
		case b := <-recvCh:
			if len(batchSegments(b)) > 1 {
				coalesced = true
			}
			got += len(b.data)
			b.release()
		case <-deadline:
			t.Fatalf("got %d of %d bytes", got, len(payload))
		}
	}
	if !coalesced {
		t.Skip("UDP_GRO did not coalesce: the single-datagram path is covered elsewhere")
	}

	from := canonicalAddrPort(sender.LocalAddr().(*net.UDPAddr).AddrPort())
	tr.localMu.Lock()
	e, ok := tr.local[from]
	tr.localMu.Unlock()
	if !ok {
		t.Fatalf("no arrival address recorded for %s after a coalesced run", from)
	}
	if want := netip.MustParseAddr("127.0.0.1"); e.addr != want {
		t.Fatalf("arrival address for %s = %s, want %s", from, e.addr, want)
	}
	if e.cmsg == nil {
		t.Fatalf("no packet-info message built for %s", from)
	}
}

// TestIpTransportGROReadsAFullRun holds the floor under groBufSize. The kernel
// assembles a run without regard for the buffer the reader will offer, and a
// short buffer takes the head of the run and drops the rest -- silently, as far
// as the reader can tell, and as loss as far as the peer can tell. Sending a run
// far longer than any plausible smaller buffer makes that truncation a test
// failure rather than a retransmission somebody else has to explain.
func TestIpTransportGROReadsAFullRun(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	recvCh := make(chan recvBatch, 64)
	tr := NewIpTransport(udp, recvCh)
	if !tr.gro {
		t.Skip("UDP_GRO not available on this kernel")
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	const (
		segSize = 1400
		segs    = 46 // 64400 bytes: one read's worth, and four times 16 KiB
	)
	payload := make([]byte, segSize*segs)
	for i := range payload {
		payload[i] = byte(i)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Serve(ctx)

	dst := udp.LocalAddr().(*net.UDPAddr)
	if _, _, err := sender.WriteMsgUDP(payload, udpSegmentMessage(segSize), dst); err != nil {
		t.Fatalf("segmented write: %v", err)
	}

	var got []byte
	longest := 0
	deadline := time.After(10 * time.Second)
	for len(got) < len(payload) {
		select {
		case b := <-recvCh:
			if len(b.data) > longest {
				longest = len(b.data)
			}
			for _, seg := range batchSegments(b) {
				got = append(got, seg...)
			}
			b.release()
		case <-deadline:
			t.Fatalf("got %d of %d bytes: the run was truncated", len(got), len(payload))
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received %d bytes, not the bytes sent", len(got))
	}
	// Without a read this long the run never reached past a shorter buffer,
	// so a shorter buffer would have passed too.
	if longest <= 16384 {
		t.Skipf("longest read was %d bytes: the kernel split the run too finely to test the bound", longest)
	}
}
