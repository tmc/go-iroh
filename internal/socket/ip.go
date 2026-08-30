package socket

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

// maxDatagramSize bounds a single read from the UDP socket. QUIC packets never
// exceed this; larger reads would be truncated by quic-go anyway.
const maxDatagramSize = 1452 + 512 // generous: max QUIC packet plus headroom

var ipRecvPool = make(chan []byte, 1024)

// IpTransport is the direct-UDP transport: it reads datagrams from a
// net.PacketConn and forwards them to the [MagicConn]'s recv channel, and sends
// datagrams the magic socket routes to it. It is the Go analog of the Rust
// IpTransport (iroh/src/socket/transports/ip.rs).
//
// Create one with [NewIpTransport] and start its recv loop with [IpTransport.Serve].
type IpTransport struct {
	conn   *net.UDPConn
	recvCh chan<- recvBatch
	gro    bool
}

const groBufSize = 65535

var groRecvPool = sync.Pool{New: func() any { b := make([]byte, groBufSize); return &b }}

// NewIpTransport returns an IpTransport over conn that delivers received
// datagrams to recvCh. The transport does not take ownership of conn; the caller
// closes it.
func NewIpTransport(conn *net.UDPConn, recvCh chan<- recvBatch) *IpTransport {
	return &IpTransport{conn: conn, recvCh: recvCh, gro: enableGRO(conn)}
}

// LocalAddr returns the bound local address of the underlying socket.
func (t *IpTransport) LocalAddr() net.Addr { return t.conn.LocalAddr() }

// Serve runs the receive loop until ctx is cancelled or the socket is closed.
// Each datagram is delivered to the recv channel tagged with its real remote IP
// address (canonicalized: an IPv4-mapped IPv6 source becomes plain IPv4, to
// match iroh/src/socket/transports/ip.rs:221 to_canonical). Empty datagrams and
// transient errors are skipped; a closed socket ends the loop cleanly.
func (t *IpTransport) Serve(ctx context.Context) {
	if t.gro {
		t.serveGRO(ctx)
		return
	}
	for {
		if ctx.Err() != nil {
			return
		}
		buf := getIPRecvBuffer()
		n, ap, err := t.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			putIPRecvBuffer(buf)
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Transient read error (e.g. ICMP-driven recv error on some
			// platforms): keep serving.
			continue
		}
		if n == 0 {
			putIPRecvBuffer(buf)
			// Timeout or platform quirk; nothing to deliver.
			continue
		}
		recordUDPReceive(1, false)
		// The transport address is internal to iroh and is always the canonical
		// (unmapped) form. iroh/src/socket/transports/ip.rs:219.
		cap := canonicalAddrPort(ap)
		b := recvBatch{data: buf[:n], ip: cap, releaseIP: true}
		if !t.enqueue(ctx, b) {
			return
		}
	}
}

func (t *IpTransport) serveGRO(ctx context.Context) {
	var oob [groOOBSize]byte
	for {
		if ctx.Err() != nil {
			return
		}
		bp := groRecvPool.Get().(*[]byte)
		buf := *bp
		n, oobn, _, ap, err := t.conn.ReadMsgUDPAddrPort(buf, oob[:])
		if err != nil {
			groRecvPool.Put(bp)
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}
		if n == 0 {
			groRecvPool.Put(bp)
			continue
		}
		seg := groSegmentSize(oob[:oobn])
		if seg <= 0 || seg > n {
			seg = n
		}
		recordUDPReceive((n+seg-1)/seg, seg < n)
		b := recvBatch{data: buf[:n], stride: seg, ip: canonicalAddrPort(ap), groBuf: bp}
		if !t.enqueue(ctx, b) {
			return
		}
	}
}

func (t *IpTransport) enqueue(ctx context.Context, b recvBatch) bool {
	select {
	case t.recvCh <- b:
		return true
	default:
	}
	select {
	case t.recvCh <- b:
		return true
	case <-ctx.Done():
		b.release()
		return false
	}
}

func getIPRecvBuffer() []byte {
	select {
	case buf := <-ipRecvPool:
		return buf
	default:
		return make([]byte, maxDatagramSize)
	}
}

func putIPRecvBuffer(buf []byte) {
	if cap(buf) != maxDatagramSize {
		return
	}
	select {
	case ipRecvPool <- buf[:maxDatagramSize]:
	default:
	}
}

// send writes p to the IP destination dst. The destination is canonicalized so
// an IPv4-mapped IPv6 address is sent as plain IPv4, matching
// iroh/src/socket/transports/ip.rs:310 canonical_addr. It reports the number of
// bytes written.
func (t *IpTransport) send(p []byte, dst netip.AddrPort) (int, error) {
	dst = canonicalAddrPort(dst)
	n, err := t.conn.WriteToUDPAddrPort(p, dst)
	return n, err
}

func canonicalAddrPort(ap netip.AddrPort) netip.AddrPort {
	addr := ap.Addr()
	if !addr.Is4In6() {
		return ap
	}
	return netip.AddrPortFrom(addr.Unmap(), ap.Port())
}

func udpAddrFromAddrPort(ap netip.AddrPort) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(canonicalAddrPort(ap))
}

func addrPortFromUDPAddr(addr *net.UDPAddr) netip.AddrPort {
	return canonicalAddrPort(addr.AddrPort())
}

// addrPort extracts a netip.AddrPort from a net.Addr, handling the *net.UDPAddr
// that net.PacketConn.ReadFrom returns as well as anything already carrying an
// AddrPort.
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return addrPortFromUDPAddr(v), true
	case interface{ AddrPort() netip.AddrPort }:
		return canonicalAddrPort(v.AddrPort()), true
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		return canonicalAddrPort(ap), true
	}
}
