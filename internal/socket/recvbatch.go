package socket

import (
	"net/netip"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// AddrKind tags the variant of an [Addr].
type AddrKind int

const (
	// AddrIP is a direct IP address path.
	AddrIP AddrKind = iota
	// AddrRelay is a relay path, identified by a relay URL and endpoint id.
	AddrRelay
	// AddrCustom is a custom-transport path.
	AddrCustom
)

// Addr is the transport-level address of a network path, internal to the magic
// socket. It is one of three kinds — IP, relay, or custom — mirroring the Rust
// transports::Addr enum (iroh/src/socket/transports.rs:795). The zero Addr is an
// unspecified IPv6 IP address, matching Rust's Default (transports.rs:830).
//
// An Addr is never sent on the wire; it is the magic socket's own routing key.
type Addr struct {
	kind     AddrKind
	ip       netip.AddrPort     // AddrIP
	relayURL netaddr.RelayURL   // AddrRelay
	eid      key.EndpointID     // AddrRelay
	custom   netaddr.CustomAddr // AddrCustom
}

// IPAddr returns an [Addr] for a direct IP path. The address is canonicalized
// so an IPv4-mapped IPv6 address becomes a plain IPv4 address, matching Rust's
// SocketAddr -> Addr conversion (iroh/src/socket/transports.rs:825).
func IPAddr(ap netip.AddrPort) Addr {
	return Addr{kind: AddrIP, ip: canonicalAddrPort(ap)}
}

// RelayAddr returns an [Addr] for a relay path reaching eid through url.
func RelayAddr(url netaddr.RelayURL, eid key.EndpointID) Addr {
	return Addr{kind: AddrRelay, relayURL: url, eid: eid}
}

// CustomAddr returns an [Addr] for a custom-transport path.
func CustomAddr(c netaddr.CustomAddr) Addr {
	return Addr{kind: AddrCustom, custom: c}
}

// Kind reports which variant a is.
func (a Addr) Kind() AddrKind { return a.kind }

// String renders a in a stable "kind:value" form. It is suitable as a map key
// (two Addrs are equal iff their String values are equal) and for diagnostics.
// It mirrors the Rust transports::Addr Display (iroh/src/socket/transports.rs).
func (a Addr) String() string {
	switch a.kind {
	case AddrIP:
		return "ip:" + a.ip.String()
	case AddrRelay:
		return "relay:" + a.relayURL.String() + "|" + a.eid.String()
	case AddrCustom:
		return "custom:" + a.custom.String()
	default:
		return "unknown"
	}
}

// IP returns the IP socket address and true if a is an [AddrIP].
func (a Addr) IP() (netip.AddrPort, bool) {
	return a.ip, a.kind == AddrIP
}

// Relay returns the relay URL, endpoint id, and true if a is an [AddrRelay].
func (a Addr) Relay() (netaddr.RelayURL, key.EndpointID, bool) {
	return a.relayURL, a.eid, a.kind == AddrRelay
}

// Custom returns the custom address and true if a is an [AddrCustom].
func (a Addr) Custom() (netaddr.CustomAddr, bool) {
	return a.custom, a.kind == AddrCustom
}

// RecvInfo carries the per-datagram metadata a transport reports alongside the
// payload: the remote [Addr] it came from and, for custom transports, the local
// custom address that received it. It mirrors the Rust RecvInfo
// (iroh/src/socket/transports.rs:572). For IP and relay paths Local is the zero
// value.
type RecvInfo struct {
	Remote Addr
	Local  netaddr.CustomAddr
	// HasLocal reports whether Local is set (custom transports only).
	HasLocal bool
}

// recvBatch is one received datagram and its metadata, queued from a transport's
// recv loop to [MagicConn.ReadFrom]. The payload is owned by the batch until it
// is copied into the caller's buffer.
type recvBatch struct {
	data      []byte
	stride    int // segment size when data holds several datagrams; 0 = one
	info      RecvInfo
	ip        netip.AddrPort
	releaseIP bool
	groBuf    *[]byte
	releaseFn func()
}

func (b recvBatch) count() uint64 {
	if b.stride <= 0 || len(b.data) == 0 {
		return 1
	}
	return uint64((len(b.data) + b.stride - 1) / b.stride)
}

func (b recvBatch) release() {
	if b.releaseIP {
		putIPRecvBuffer(b.data)
	}
	if b.groBuf != nil {
		groRecvPool.Put(b.groBuf)
	}
	if b.releaseFn != nil {
		b.releaseFn()
	}
}

// recvAddr returns the transport address the batch arrived from. The IP
// transport reports its source in ip rather than in info, so a batch carrying
// a valid ip is an IP-path datagram; only relay and custom transports fill in
// info.Remote.
func (b recvBatch) recvAddr() Addr {
	if b.ip.IsValid() {
		return Addr{kind: AddrIP, ip: b.ip}
	}
	return b.info.Remote
}
