package socket

import (
	"context"

	"github.com/tmc/go-iroh/netaddr"
)

// CustomDatagram is one datagram received by a [CustomTransport].
type CustomDatagram struct {
	Remote   netaddr.CustomAddr
	Local    netaddr.CustomAddr
	HasLocal bool
	Data     []byte
}

// Packet is one custom transport packet whose buffer is owned by the transport.
type Packet struct {
	Remote   netaddr.CustomAddr
	Local    netaddr.CustomAddr
	HasLocal bool
	Data     []byte
	Free     func()
}

// CustomTransport is a pluggable transport backend for custom addresses. It is
// intentionally small: the transport owns its wire format and reports datagrams
// as iroh custom addresses for the magic socket to map into qng paths.
type CustomTransport interface {
	// Serve runs the transport until ctx is done, passing each received
	// datagram to recv.
	//
	// recv reports whether the datagram was taken. A false result means the
	// datagram was dropped, most often because the receive queue was full
	// under a burst; it is not a signal to stop. Serve must keep serving and
	// return only when ctx is done, so `if !recv(d) { return }` tears the
	// transport down on the first burst. Shutdown is reported through ctx
	// alone, which is cancelled before the queue stops being drained.
	Serve(ctx context.Context, recv func(CustomDatagram) bool)

	// Send sends p to remote. local is nil when qng did not select a specific
	// local custom address for the path.
	Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool
}

// PacketTransport is a custom transport that owns received packet buffers.
type PacketTransport interface {
	CustomTransport

	// ServePackets runs the transport until ctx is done. Received packets are
	// owned by the transport until their Free callback runs. recv follows the
	// same contract as [CustomTransport.Serve]: a false result means the packet
	// was dropped, not that the transport should stop. A dropped packet's Free
	// callback has already run.
	ServePackets(ctx context.Context, recv func(Packet) bool)

	// SendPacket sends p to remote. The transport must not retain p after the
	// call returns.
	SendPacket(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool
}

type customTransport struct {
	transport CustomTransport
	recvCh    chan<- recvBatch
}

func newCustomTransport(t CustomTransport, recvCh chan<- recvBatch) *customTransport {
	return &customTransport{transport: t, recvCh: recvCh}
}

func (t *customTransport) Serve(ctx context.Context) {
	if p, ok := t.transport.(PacketTransport); ok {
		t.servePackets(ctx, p)
		return
	}
	t.transport.Serve(ctx, func(d CustomDatagram) bool {
		data := make([]byte, len(d.Data))
		copy(data, d.Data)
		select {
		case t.recvCh <- recvBatch{
			data: data,
			info: RecvInfo{Remote: CustomAddr(d.Remote), Local: d.Local, HasLocal: d.HasLocal},
		}:
			return true
		case <-ctx.Done():
			return false
		default:
			return false
		}
	})
}

func (t *customTransport) servePackets(ctx context.Context, p PacketTransport) {
	p.ServePackets(ctx, func(pkt Packet) bool {
		select {
		case t.recvCh <- recvBatch{
			data:      pkt.Data,
			info:      RecvInfo{Remote: CustomAddr(pkt.Remote), Local: pkt.Local, HasLocal: pkt.HasLocal},
			releaseFn: pkt.Free,
		}:
			return true
		case <-ctx.Done():
			if pkt.Free != nil {
				pkt.Free()
			}
			return false
		default:
			if pkt.Free != nil {
				pkt.Free()
			}
			return false
		}
	})
}

func (t *customTransport) Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool {
	if pt, ok := t.transport.(PacketTransport); ok {
		return pt.SendPacket(remote, local, p)
	}
	data := make([]byte, len(p))
	copy(data, p)
	return t.transport.Send(remote, local, data)
}
