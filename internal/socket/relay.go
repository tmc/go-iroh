package socket

import (
	"bytes"
	"context"

	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/watch"
)

// RelayTransport is the magic socket's relay path: it owns a [RelayActor],
// forwards datagrams received from relays into the [MagicConn]'s recv channel
// (tagged so they surface as a [RelayMappedAddr]), and routes outgoing datagrams
// addressed to a relay mapped address to the right relay connection.
//
// It is the Go analog of the Rust RelayTransport
// (iroh/src/socket/transports/relay.rs:31). Create one with [NewRelayTransport]
// and start it with [RelayTransport.Serve]. The zero value is not usable.
type RelayTransport struct {
	sock   *Socket
	actor  *RelayActor
	recvCh chan<- recvBatch
}

// NewRelayTransport returns a RelayTransport that drives actor and delivers
// received relay datagrams to recvCh. sock supplies the relay mapped-address
// table shared with the [MagicConn]. The transport does not start the actor;
// call [RelayTransport.Serve].
func NewRelayTransport(sock *Socket, actor *RelayActor, recvCh chan<- recvBatch) *RelayTransport {
	return &RelayTransport{sock: sock, actor: actor, recvCh: recvCh}
}

// Serve runs the relay actor and the recv-forwarding loop until ctx is
// cancelled. It blocks; run it in its own goroutine.
func (t *RelayTransport) Serve(ctx context.Context) {
	go t.actor.Run(ctx)
	t.forwardRecv(ctx)
}

// forwardRecv drains datagrams from the actor and forwards each as a recvBatch
// tagged with the relay [Addr], so [MagicConn.recvAddr] rewrites it to the
// relay mapped IPv6 ULA quic-go addresses the path by.
func (t *RelayTransport) forwardRecv(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case dm, ok := <-t.actor.Recv():
			if !ok {
				return
			}
			t.deliver(ctx, dm)
		}
	}
}

// deliver forwards dm as one recvBatch whose stride is the segment size, so
// ReadFrom hands quic-go one datagram at a time (the Rust poll_recv re-batches
// the same way, iroh/src/socket/transports/relay.rs:115). The pooled Contents
// buffer is released once ReadFrom has copied out the last segment.
func (t *RelayTransport) deliver(ctx context.Context, dm RelayRecvDatagram) {
	remote := RelayAddr(dm.URL, dm.Src)
	b := dm.Datagrams.Contents
	stride := max(len(b), 1)
	if dm.Datagrams.SegmentSize != 0 {
		stride = int(dm.Datagrams.SegmentSize)
	}
	rb := recvBatch{data: b, stride: stride, info: RecvInfo{Remote: remote}, releaseFn: dm.Datagrams.Release}
	select {
	case t.recvCh <- rb:
	case <-ctx.Done():
	}
}

// Send routes p to the relay addressed by the relay mapped address m. It looks
// up the (relay url, endpoint id) pair m maps to and queues a datagram to the
// relay actor. It reports whether the datagram was routed; a false result means
// the address is unknown or the send queue was full, in which case the datagram
// is treated as lost (QUIC's loss recovery retransmits), matching the Rust
// blackhole-on-failure invariant (iroh/src/socket/transports.rs:1176).
func (t *RelayTransport) Send(m RelayMappedAddr, p []byte) bool {
	return t.SendBatch(m, p, 0)
}

// maxRelayBatch is the largest Datagrams.Contents that fits a relay frame.
const maxRelayBatch = relayproto.MaxPacketSize - key.PublicKeySize - 3

// SendBatch is Send for a GSO-style buffer of segSize-sized datagrams (the
// last may be shorter). segSize 0 means a single datagram.
func (t *RelayTransport) SendBatch(m RelayMappedAddr, p []byte, segSize int) bool {
	rk, ok := t.sock.LookupRelay(m)
	if !ok {
		return false
	}
	if segSize <= 0 || segSize >= len(p) {
		return t.actor.Send(RelaySendItem{
			RemoteEndpoint: rk.EID,
			URL:            rk.URL,
			Datagrams:      relayproto.DatagramsFromBytes(p),
		})
	}
	per := max(1, maxRelayBatch/segSize) * segSize
	for len(p) > 0 {
		n := min(len(p), per)
		d := relayproto.Datagrams{Contents: bytes.Clone(p[:n])}
		if n > segSize {
			d.SegmentSize = uint16(segSize)
		}
		if !t.actor.Send(RelaySendItem{RemoteEndpoint: rk.EID, URL: rk.URL, Datagrams: d}) {
			return false
		}
		p = p[n:]
	}
	return true
}

// SetHomeRelay designates url as the endpoint's home relay. See
// [RelayActor.SetHomeRelay].
func (t *RelayTransport) SetHomeRelay(url netaddr.RelayURL) { t.actor.SetHomeRelay(url) }

// InsertRelay adds or replaces a relay config in the underlying actor.
func (t *RelayTransport) InsertRelay(url netaddr.RelayURL, cfg relay.Config) (relay.Config, bool) {
	return t.actor.InsertRelay(url, cfg)
}

// RemoveRelay removes a relay config from the underlying actor.
func (t *RelayTransport) RemoveRelay(url netaddr.RelayURL) (relay.Config, bool) {
	return t.actor.RemoveRelay(url)
}

// HomeRelayStatus returns a watcher over the home relay's connection status. See
// [RelayActor.HomeRelayStatus].
func (t *RelayTransport) HomeRelayStatus() watch.Observer[*RelayStatus] {
	return t.actor.HomeRelayStatus()
}
