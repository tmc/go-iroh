package socket

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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

	// pktinfo is set when the socket is bound to the unspecified address and
	// the platform delivers the destination address of received datagrams.
	// A wildcard socket has no fixed source address: the kernel picks one per
	// reply by route, which on a multi-homed host, or one whose peer is
	// reached over a bridge or a container network, need not be the address
	// the peer sent to. A QUIC peer then receives packets from an address it
	// never dialed and fails path validation. The transport records the local
	// address each remote last reached and answers from it, as quinn does
	// for the Rust iroh through quinn-udp's RecvMeta::dst_ip and
	// Transmit::src_ip.
	pktinfo bool
	localMu sync.Mutex
	local   map[netip.AddrPort]*localEntry
	// heard orders entries by the last datagram heard from each remote,
	// circularly through this sentinel: heard.next is newest, heard.prev
	// oldest and first to be evicted.
	heard localEntry
}

// localAddr is the local address a remote's datagrams arrive at.
type localAddr struct {
	addr    netip.Addr
	ifIndex int
}

// localEntry is a remote's entry in the arrival-address table. cmsg is the
// packet-info message that makes a reply leave from the address; it is
// shared with senders and never written after it is built.
type localEntry struct {
	remote netip.AddrPort
	localAddr
	cmsg       []byte
	prev, next *localEntry
}

// maxLocalAddrs bounds the arrival-address table. A full table drops the
// remote heard from longest ago; a reply to a peer not in the table leaves
// from the address the kernel picks, as before the table.
const maxLocalAddrs = 4096

// NewIpTransport returns an IpTransport over conn that delivers received
// datagrams to recvCh. The transport does not take ownership of conn; the caller
// closes it.
func NewIpTransport(conn *net.UDPConn, recvCh chan<- recvBatch) *IpTransport {
	t := &IpTransport{conn: conn, recvCh: recvCh}
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.IP.IsUnspecified() {
		t.pktinfo = enablePacketInfo(conn)
		if t.pktinfo {
			t.local = make(map[netip.AddrPort]*localEntry)
			t.heard.prev, t.heard.next = &t.heard, &t.heard
		}
	}
	return t
}

// enablePacketInfo asks the kernel for the destination address of received
// datagrams. Either family may fail: an IPv4 socket has no IPv6 options, and
// some platforms have neither. It reports whether at least one family took.
func enablePacketInfo(conn *net.UDPConn) bool {
	ok4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true) == nil
	ok6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true) == nil
	return ok4 || ok6
}

// recordLocal notes the local address remote's datagram arrived at.
func (t *IpTransport) recordLocal(remote netip.AddrPort, oob []byte) {
	if la, ok := parsePacketInfo(oob); ok {
		t.record(remote, la)
	}
}

// record notes la as remote's arrival address and remote as the most
// recently heard. The control message is rebuilt only when la changes.
func (t *IpTransport) record(remote netip.AddrPort, la localAddr) {
	t.localMu.Lock()
	defer t.localMu.Unlock()
	if e, ok := t.local[remote]; ok {
		if e.localAddr != la {
			e.localAddr = la
			e.cmsg = packetInfoMessage(remote, la)
		}
		t.unlink(e)
		t.linkFront(e)
		return
	}
	if len(t.local) >= maxLocalAddrs {
		oldest := t.heard.prev
		t.unlink(oldest)
		delete(t.local, oldest.remote)
	}
	e := &localEntry{remote: remote, localAddr: la, cmsg: packetInfoMessage(remote, la)}
	t.local[remote] = e
	t.linkFront(e)
}

// linkFront puts e at the head of the recency list. Caller holds localMu.
func (t *IpTransport) linkFront(e *localEntry) {
	e.prev, e.next = &t.heard, t.heard.next
	e.prev.next, e.next.prev = e, e
}

// unlink removes e from the recency list. Caller holds localMu.
func (t *IpTransport) unlink(e *localEntry) {
	e.prev.next, e.next.prev = e.next, e.prev
	e.prev, e.next = nil, nil
}

// forgetLocal drops remote's arrival address after the kernel refused it.
func (t *IpTransport) forgetLocal(remote netip.AddrPort) {
	t.localMu.Lock()
	if e, ok := t.local[remote]; ok {
		t.unlink(e)
		delete(t.local, remote)
	}
	t.localMu.Unlock()
}

// packetInfoFor returns the control message that makes a datagram to remote
// leave from the address remote last reached, or nil when none is known. The
// message is shared and must not be modified.
func (t *IpTransport) packetInfoFor(remote netip.AddrPort) []byte {
	if !t.pktinfo {
		return nil
	}
	var cmsg []byte
	t.localMu.Lock()
	if e, ok := t.local[remote]; ok {
		cmsg = e.cmsg
	}
	t.localMu.Unlock()
	return cmsg
}

// packetInfoMessage builds the packet-info control message naming la as the
// source of datagrams to remote, or nil when it cannot be. The source must
// be of the destination's family: IPv4 traffic on a dual-stack socket
// carries IP-level control messages in both directions, so an IPv4 remote
// gets an IPv4 message whatever the socket.
func packetInfoMessage(remote netip.AddrPort, la localAddr) []byte {
	if remote.Addr().Is4() {
		if !la.addr.Is4() {
			return nil
		}
		return (&ipv4.ControlMessage{Src: la.addr.AsSlice()}).Marshal()
	}
	if !la.addr.Is6() || la.addr.Is4In6() {
		return nil
	}
	return (&ipv6.ControlMessage{Src: la.addr.AsSlice(), IfIndex: la.ifIndex}).Marshal()
}

// maxControlSize bounds the control messages read with a datagram: a
// packet-info message of either family plus headroom.
const maxControlSize = 128

// LocalAddr returns the bound local address of the underlying socket.
func (t *IpTransport) LocalAddr() net.Addr { return t.conn.LocalAddr() }

// Serve runs the receive loop until ctx is cancelled or the socket is closed.
// Each datagram is delivered to the recv channel tagged with its real remote IP
// address (canonicalized: an IPv4-mapped IPv6 source becomes plain IPv4, to
// match iroh/src/socket/transports/ip.rs:221 to_canonical). Empty datagrams and
// transient errors are skipped; a closed socket ends the loop cleanly.
func (t *IpTransport) Serve(ctx context.Context) {
	var oob []byte
	if t.pktinfo {
		oob = make([]byte, maxControlSize)
	}
	for {
		if ctx.Err() != nil {
			return
		}
		buf := getIPRecvBuffer()
		var (
			n, oobn int
			ap      netip.AddrPort
			err     error
		)
		if t.pktinfo {
			n, oobn, _, ap, err = t.conn.ReadMsgUDPAddrPort(buf, oob)
		} else {
			n, ap, err = t.conn.ReadFromUDPAddrPort(buf)
		}
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
		if t.pktinfo {
			t.recordLocal(cap, oob[:oobn])
		}
		b := recvBatch{data: buf[:n], ip: cap, releaseIP: true}
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
// iroh/src/socket/transports/ip.rs:310 canonical_addr. When dst has reached
// this socket before, the datagram leaves from the address it arrived at. It
// reports the number of bytes written.
func (t *IpTransport) send(p []byte, dst netip.AddrPort) (int, error) {
	dst = canonicalAddrPort(dst)
	if oob := t.packetInfoFor(dst); oob != nil {
		n, _, err := t.conn.WriteMsgUDPAddrPort(p, oob, dst)
		if err == nil {
			return n, nil
		}
		// The kernel refused the source (an address that has since gone,
		// or a platform quirk): fall back to its own choice, and stop asking
		// until the peer reaches us again.
		t.forgetLocal(dst)
	}
	n, err := t.conn.WriteToUDPAddrPort(p, dst)
	return n, err
}

// withPacketInfo prepends the packet-info control message for dst, when one
// is known, to oob. The result is built in buf, grown if too small; oob and
// the shared message are not written to.
func (t *IpTransport) withPacketInfo(dst netip.AddrPort, oob, buf []byte) []byte {
	pi := t.packetInfoFor(dst)
	if pi == nil {
		return oob
	}
	buf = append(buf[:0], pi...)
	return append(buf, oob...)
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
