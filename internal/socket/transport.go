package socket

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/tmc/go-iroh/key"
)

// Transports multiplexes the magic socket's network paths: a direct-IP
// transport plus optional relay and custom transports. It is the Go analog of
// the Rust Transports struct (iroh/src/socket/transports.rs:47).
//
// The IP transport is nil for relay-only endpoints. The relay transport is
// present when the endpoint has relays configured; otherwise relay-addressed
// sends are blackholed (reported as success so quic-go's loss recovery
// retransmits). Custom transports are present only when callers configure them.
type Transports struct {
	ip     *IpTransport
	relay  *RelayTransport
	custom []*customTransport
}

// MagicConn is the single net.PacketConn handed to a quic-go Transport. It
// presents every iroh network path — direct IP, relay, custom — as one UDP
// socket, mapping non-IP paths to synthetic IPv6 ULAs so quic-go can address
// them. It is the Go analog of the Rust `impl AsyncUdpSocket for Transport`
// (iroh/src/socket/transports.rs:1067).
//
// MagicConn satisfies net.PacketConn. It deliberately does not satisfy
// quic-go's OOBCapablePacketConn: GRO and ECN receive metadata do not
// generalize across relay and custom transports. On Linux it exposes a narrower
// send-message method so qng can use GSO for direct IP destinations and split
// the same write for other transports. Correctness does not depend on it.
//
// Create one with [NewMagicConn] and start it with [MagicConn.Serve]. The zero
// value is not usable.
type MagicConn struct {
	sock       *Socket
	transports *Transports
	udp        *net.UDPConn
	localAddr  net.Addr

	recvCh chan recvBatch
	// cur is the batch ReadFrom is draining. quic-go reads from a single
	// goroutine per Transport.
	cur     recvBatch
	curOff  int
	curAddr net.Addr

	readDeadline  deadline
	writeDeadline deadline

	recvAddrsMu sync.RWMutex
	recvAddrs   map[netip.AddrPort]*net.UDPAddr

	metrics Metrics

	endpointMu     sync.RWMutex
	endpointSender func(key.EndpointID, []byte) bool
}

// NewMagicConn returns a MagicConn whose sole transport is an [IpTransport]
// bound to udp. sock holds the mapped-address tables shared with the transports.
// Start the receive loop with [MagicConn.Serve] before handing the MagicConn to
// a quic-go Transport.
func NewMagicConn(sock *Socket, udp *net.UDPConn) *MagicConn {
	return NewMagicConnWithRelay(sock, udp, nil)
}

// NewMagicConnWithRelay returns a MagicConn with an IP transport over udp and,
// if actor is non-nil, a relay transport driven by it. Datagrams received from
// relays surface through [MagicConn.ReadFrom] as a [RelayMappedAddr]; sends to a
// relay mapped address route to the actor. Start the receive loops with
// [MagicConn.Serve].
func NewMagicConnWithRelay(sock *Socket, udp *net.UDPConn, actor *RelayActor) *MagicConn {
	return NewMagicConnWithTransports(sock, udp, actor)
}

// NewMagicConnWithTransports returns a MagicConn with direct IP, optional relay,
// and optional custom transports.
func NewMagicConnWithTransports(sock *Socket, udp *net.UDPConn, actor *RelayActor, custom ...CustomTransport) *MagicConn {
	return newMagicConn(sock, udp, actor, custom...)
}

// NewMagicConnRelayOnly returns a MagicConn with no direct-IP transport. Relay
// and custom transports are still available. Start the receive loops with
// [MagicConn.Serve].
func NewMagicConnRelayOnly(sock *Socket, actor *RelayActor, custom ...CustomTransport) *MagicConn {
	return newMagicConn(sock, nil, actor, custom...)
}

func newMagicConn(sock *Socket, udp *net.UDPConn, actor *RelayActor, custom ...CustomTransport) *MagicConn {
	recvCh := make(chan recvBatch, 4)
	transports := &Transports{}
	var localAddr net.Addr
	if udp != nil {
		transports.ip = NewIpTransport(udp, recvCh)
		localAddr = udp.LocalAddr()
	} else {
		localAddr = mappedUDPAddr(NewRelayMappedAddr().Addr())
	}
	if actor != nil {
		transports.relay = NewRelayTransport(sock, actor, recvCh)
	}
	for _, t := range custom {
		if t != nil {
			transports.custom = append(transports.custom, newCustomTransport(t, recvCh))
		}
	}
	m := &MagicConn{
		sock:       sock,
		transports: transports,
		udp:        udp,
		localAddr:  localAddr,
		recvCh:     recvCh,
		recvAddrs:  make(map[netip.AddrPort]*net.UDPAddr),
	}
	m.readDeadline.init()
	m.writeDeadline.init()
	if actor != nil {
		actor.setMetrics(&m.metrics)
	}
	return m
}

// Relay returns the relay transport, or nil if no relay actor was configured.
func (m *MagicConn) Relay() *RelayTransport { return m.transports.relay }

// SetEndpointSender sets the callback used for endpoint-id mapped addresses.
// The callback should route p through the remote endpoint's actor and report
// whether it accepted the datagram. A nil callback restores blackhole behavior.
func (m *MagicConn) SetEndpointSender(send func(key.EndpointID, []byte) bool) {
	m.endpointMu.Lock()
	m.endpointSender = send
	m.endpointMu.Unlock()
}

// Serve runs the magic socket's receive loops until ctx is cancelled or the
// underlying socket is closed. It blocks; run it in its own goroutine.
func (m *MagicConn) Serve(ctx context.Context) {
	if m.transports.ip == nil {
		for _, t := range m.transports.custom {
			go t.Serve(ctx)
		}
		if m.transports.relay != nil {
			m.transports.relay.Serve(ctx)
			return
		}
		<-ctx.Done()
		return
	}
	if m.transports.relay != nil {
		go m.transports.relay.Serve(ctx)
	}
	for _, t := range m.transports.custom {
		go t.Serve(ctx)
	}
	m.transports.ip.Serve(ctx)
}

// ReadFrom delivers the next datagram from any transport into p, returning its
// length and the net.Addr quic-go should associate with the path it arrived on.
// For IP paths that addr is the real remote IP; for relay and custom paths it is
// the synthetic mapped IPv6 ULA (port 12345). It implements net.PacketConn.
func (m *MagicConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if m.curOff < len(m.cur.data) {
			seg := m.cur.data[m.curOff:]
			if m.cur.stride > 0 && len(seg) > m.cur.stride {
				seg = seg[:m.cur.stride]
			}
			m.curOff += len(seg)
			n := copy(p, seg)
			addr := m.curAddr
			if m.curOff >= len(m.cur.data) {
				m.cur.release()
				m.cur, m.curAddr = recvBatch{}, nil
			}
			return n, addr, nil
		}
		select {
		case b := <-m.recvCh:
			addr, ok := m.recvBatchAddr(b)
			if !ok {
				b.release()
				// Unknown relay/custom source: cannot present a stable path to
				// quic-go. Drop and keep reading.
				continue
			}
			m.recordRecv(b.recvAddr(), b.count())
			m.cur, m.curOff, m.curAddr = b, 0, addr
		case <-m.readDeadline.wait():
			return 0, nil, timeoutError{}
		}
	}
}

func (m *MagicConn) recvBatchAddr(b recvBatch) (net.Addr, bool) {
	if b.ip.IsValid() {
		addr := m.udpAddr(b.ip)
		return addr, true
	}
	addr, ok := m.recvAddr(b.info)
	return addr, ok
}

// Metrics returns a point-in-time copy of magic-socket counters.
func (m *MagicConn) Metrics() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	return m.metrics.snapshot()
}

// MetricsSet returns the shared magic-socket counter set.
func (m *MagicConn) MetricsSet() *Metrics {
	if m == nil {
		return nil
	}
	return &m.metrics
}

// RecordRelayHomeChange increments the relay-home change counter.
func (m *MagicConn) RecordRelayHomeChange() {
	if m != nil {
		m.metrics.relayHomeChange.Add(1)
	}
}

// recvAddr maps a received datagram's RecvInfo to the net.Addr quic-go sees: the
// real IP for an IP path, or the synthetic mapped IPv6 ULA for a relay or custom
// path. It mirrors the Rust recv rewrite in process_datagrams
// (iroh/src/socket.rs:596).
func (m *MagicConn) recvAddr(info RecvInfo) (net.Addr, bool) {
	switch info.Remote.kind {
	case AddrIP:
		ap, _ := info.Remote.IP()
		addr := m.udpAddr(ap)
		return addr, true
	case AddrRelay:
		url, eid, _ := info.Remote.Relay()
		mapped := m.sock.RelayMappedAddrFor(url, eid).AddrPort()
		addr := m.udpAddr(mapped)
		return addr, true
	case AddrCustom:
		c, _ := info.Remote.Custom()
		mapped := m.sock.CustomMappedAddrFor(c).AddrPort()
		addr := m.udpAddr(mapped)
		return addr, true
	default:
		return nil, false
	}
}

// udpAddr returns the *net.UDPAddr for ap, caching it so that repeated
// receives from one peer return the same value. ReadFrom may run from several
// goroutines, so the cache is locked; the read path takes the shared lock and
// only a first sighting takes the exclusive one.
func (m *MagicConn) udpAddr(ap netip.AddrPort) *net.UDPAddr {
	ap = canonicalAddrPort(ap)
	m.recvAddrsMu.RLock()
	addr, ok := m.recvAddrs[ap]
	m.recvAddrsMu.RUnlock()
	if ok {
		return addr
	}
	m.recvAddrsMu.Lock()
	defer m.recvAddrsMu.Unlock()
	// Another goroutine may have added ap since the shared lock was dropped.
	// Reuse its value so that one peer keeps one address.
	if addr, ok := m.recvAddrs[ap]; ok {
		return addr
	}
	addr = udpAddrFromAddrPort(ap)
	m.recvAddrs[ap] = addr
	return addr
}

// mappedUDPAddr wraps a mapped IPv6 ULA as a *net.UDPAddr at the fixed dummy
// port quic-go uses to address the path.
func mappedUDPAddr(a netip.Addr) *net.UDPAddr {
	return udpAddrFromAddrPort(netip.AddrPortFrom(a, mappedPort))
}

// WriteTo routes p to the transport addressed by addr and reports success.
//
// addr is classified by [Classify]: a real IP routes to the IP transport; the
// EndpointID, relay, and custom mapped ULAs route to their transports. A send to
// a path with no live transport, an unknown mapped address, or a closed socket
// is blackholed — WriteTo still returns (len(p), nil). quic-go observes the send
// as successful and its loss recovery retransmits the lost datagram, matching
// the Rust Sender::poll_send blackhole invariant
// (iroh/src/socket/transports.rs:1176).
func (m *MagicConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if m.sock.IsClosed() {
		return len(p), nil
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		ap := udp.AddrPort()
		if isDefinitelyIP(ap.Addr()) || Classify(ap.Addr()) == KindIP {
			if m.transports.ip == nil {
				m.metrics.blackholed.Add(1)
				return len(p), nil
			}
			if _, err := m.transports.ip.send(p, ap); err == nil {
				m.recordIPSent(ap)
			} else {
				m.metrics.blackholed.Add(1)
			}
			return len(p), nil
		}
	}
	ap, ok := addrPort(addr)
	if !ok {
		return len(p), nil
	}
	switch Classify(ap.Addr()) {
	case KindIP:
		m.sendAddr(IPAddr(ap), p)
		return len(p), nil
	case KindEndpointID:
		if id, ok := m.sock.LookupEndpointID(EndpointIDMappedAddrFromAddr(ap.Addr())); ok {
			m.endpointMu.RLock()
			send := m.endpointSender
			m.endpointMu.RUnlock()
			if send != nil {
				if send(id, p) {
					m.metrics.endpointIDSent.Add(1)
				} else {
					m.metrics.blackholed.Add(1)
				}
			} else {
				m.metrics.blackholed.Add(1)
			}
		} else {
			m.metrics.blackholed.Add(1)
		}
		return len(p), nil
	case KindRelay:
		if addr, ok := relayAddrForMapped(m.sock, ap.Addr()); ok {
			m.sendAddr(addr, p)
		} else {
			m.metrics.blackholed.Add(1)
		}
		return len(p), nil
	case KindCustom:
		if c, ok := m.sock.LookupCustom(CustomMappedAddr{a: ap.Addr()}); ok {
			m.sendAddr(CustomAddr(c), p)
		} else {
			m.metrics.blackholed.Add(1)
		}
		return len(p), nil
	default:
		m.metrics.blackholed.Add(1)
		return len(p), nil
	}
}

func isDefinitelyIP(addr netip.Addr) bool {
	if !addr.Is6() {
		return true
	}
	return addr.As16()[0] != 0xfd
}

func segmentCount(n, segmentSize int) int {
	if segmentSize <= 0 {
		return 1
	}
	return (n + segmentSize - 1) / segmentSize
}

// sendRelayBatch forwards a segmented buffer to a relay mapped destination as
// relay batch frames. It reports false if dst is not a known relay address.
func (m *MagicConn) sendRelayBatch(dst netip.Addr, p []byte, segSize int) bool {
	if m.transports.relay == nil || Classify(dst) != KindRelay {
		return false
	}
	mapped := RelayMappedAddrFromAddr(dst)
	if _, ok := m.sock.LookupRelay(mapped); !ok {
		return false
	}
	segs := uint64(segmentCount(len(p), segSize))
	if m.transports.relay.SendBatch(mapped, p, segSize) {
		m.metrics.relaySent.Add(segs)
	} else {
		m.metrics.blackholed.Add(segs)
	}
	return true
}

// relayAddrForMapped returns the relay Addr for mapped.
func relayAddrForMapped(sock *Socket, mapped netip.Addr) (Addr, bool) {
	if rk, ok := sock.LookupRelay(RelayMappedAddrFromAddr(mapped)); ok {
		return RelayAddr(rk.URL, rk.EID), true
	}
	return Addr{}, false
}

// sendAddr routes p to one concrete transport address. It reports whether the
// datagram was accepted by a transport. Errors are loss, not socket failures.
func (m *MagicConn) sendAddr(addr Addr, p []byte) bool {
	switch addr.Kind() {
	case AddrIP:
		ap, _ := addr.IP()
		if !ap.IsValid() || ap.Port() == 0 {
			m.metrics.blackholed.Add(1)
			return false
		}
		if m.transports.ip == nil {
			m.metrics.blackholed.Add(1)
			return false
		}
		_, err := m.transports.ip.send(p, ap)
		if err == nil {
			m.recordIPSent(ap)
			return true
		}
		m.metrics.blackholed.Add(1)
		return false
	case AddrRelay:
		if m.transports.relay == nil {
			m.metrics.blackholed.Add(1)
			return false
		}
		url, eid, _ := addr.Relay()
		mapped := m.sock.RelayMappedAddrFor(url, eid)
		if m.transports.relay.Send(mapped, p) {
			m.metrics.relaySent.Add(1)
			return true
		}
		m.metrics.blackholed.Add(1)
		return false
	case AddrCustom:
		c, _ := addr.Custom()
		for _, t := range m.transports.custom {
			if t.Send(c, nil, p) {
				m.metrics.customSent.Add(1)
				return true
			}
		}
		m.metrics.blackholed.Add(1)
		return false
	default:
		m.metrics.blackholed.Add(1)
		return false
	}
}

// SendAddr routes p to one concrete magic-socket transport address. It is used
// by RemoteStateActor endpoint-id fanout.
func (m *MagicConn) SendAddr(addr Addr, p []byte) bool {
	if m.sock.IsClosed() {
		m.metrics.blackholed.Add(1)
		return false
	}
	return m.sendAddr(addr, p)
}

func (m *MagicConn) recordRecv(addr Addr, n uint64) {
	m.metrics.recvDatagrams.Add(n)
	switch addr.Kind() {
	case AddrIP:
		ap, _ := addr.IP()
		if ap.Addr().Is4() {
			m.metrics.ipv4Recv.Add(n)
		} else {
			m.metrics.ipv6Recv.Add(n)
		}
	case AddrRelay:
		m.metrics.relayRecv.Add(n)
	case AddrCustom:
		m.metrics.customRecv.Add(n)
	}
}

func (m *MagicConn) recordIPSent(ap netip.AddrPort) {
	if ap.Addr().Is4() {
		m.metrics.ipv4Sent.Add(1)
	} else {
		m.metrics.ipv6Sent.Add(1)
	}
}

// LocalAddr returns the bound local address of the underlying UDP socket. It
// implements net.PacketConn.
func (m *MagicConn) LocalAddr() net.Addr { return m.localAddr }

// Close releases the magic socket. It marks the shared [Socket] closed and
// closes the underlying UDP socket, which ends the receive loop. It implements
// net.PacketConn.
func (m *MagicConn) Close() error {
	m.sock.Close()
	m.readDeadline.set(time.Unix(0, 1))
	if m.udp == nil {
		return nil
	}
	return m.udp.Close()
}

// SetDeadline sets both the read and write deadlines. It implements
// net.PacketConn.
func (m *MagicConn) SetDeadline(t time.Time) error {
	m.readDeadline.set(t)
	if m.udp == nil {
		return nil
	}
	return m.udp.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future ReadFrom calls. It implements
// net.PacketConn.
func (m *MagicConn) SetReadDeadline(t time.Time) error {
	m.readDeadline.set(t)
	return nil
}

// SetWriteDeadline sets the deadline for future WriteTo calls. Writes go
// straight to the underlying socket, so the deadline is applied there. It
// implements net.PacketConn.
func (m *MagicConn) SetWriteDeadline(t time.Time) error {
	if m.udp == nil {
		return nil
	}
	return m.udp.SetWriteDeadline(t)
}

// SyscallConn returns the underlying UDP socket's raw connection. quic-go uses
// it to size the kernel receive buffer and to set the Don't Fragment bit on the
// direct-IP path. Exposing it does not make MagicConn an OOBCapablePacketConn.
// On Linux qng combines it with MagicConn's send-message method for send-side
// GSO only.
func (m *MagicConn) SyscallConn() (syscall.RawConn, error) {
	if m.udp == nil {
		return nil, errors.ErrUnsupported
	}
	return m.udp.SyscallConn()
}

// SetReadBuffer sets the kernel receive buffer size on the underlying UDP
// socket. quic-go calls it to raise the buffer to its desired size.
func (m *MagicConn) SetReadBuffer(n int) error {
	if m.udp == nil {
		return nil
	}
	return m.udp.SetReadBuffer(n)
}

// SetWriteBuffer sets the kernel send buffer size on the underlying UDP socket.
func (m *MagicConn) SetWriteBuffer(n int) error {
	if m.udp == nil {
		return nil
	}
	return m.udp.SetWriteBuffer(n)
}

var _ net.PacketConn = (*MagicConn)(nil)
