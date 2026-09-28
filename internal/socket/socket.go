package socket

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// Socket holds the magic socket's mapped-address tables: the bidirectional maps
// between transport addresses and the synthetic IPv6 ULAs that quic-go uses to
// address paths. It is the Go analog of the Rust Socket's mapped_addrs
// (iroh/src/socket.rs:332).
//
// A Socket is created by [NewSocket] and shared by a [MagicConn] and its
// [Transports]. It is safe for concurrent use. The zero Socket is not usable;
// use [NewSocket].
type Socket struct {
	// endpointAddrs maps endpoint ids to endpoint-id mapped addresses used for
	// initial packets before a concrete path is selected.
	endpointAddrs *AddrMap[key.EndpointID, EndpointIDMappedAddr]

	// relayAddrs maps (relay url, endpoint id) pairs to relay mapped addresses.
	// Keyed by the URL's string form because netaddr.RelayURL wraps a pointer
	// and is not reliably comparable across separately-parsed URLs.
	relayAddrs *AddrMap[relayMapKey, RelayMappedAddr]
	// relayByKey recovers the original RelayKey. relayHeard is the sentinel
	// of a list of its entries, most recently used first.
	relayMu    sync.Mutex
	relayByKey map[relayMapKey]*relayEntry
	relayHeard relayEntry

	// customAddrs maps a custom address (by its string key) to a custom mapped
	// address.
	customAddrs *AddrMap[string, CustomMappedAddr]
	// customByKey recovers the original netaddr.CustomAddr from its string key.
	customMu    sync.Mutex
	customByKey map[string]netaddr.CustomAddr

	closed atomic.Bool
}

type relayMapKey struct {
	url string
	eid key.EndpointID
}

// relayEntry is one relay mapping in the recency list.
type relayEntry struct {
	RelayKey
	key        relayMapKey
	prev, next *relayEntry
}

// maxRelayAddrs bounds the relay mapped-address table. A datagram from any
// endpoint id the relay forwards creates a mapping before QUIC parses it, and
// only a remote that completes a handshake is ever evicted, so a relay-side
// peer cycling endpoint ids could otherwise retain state for the life of the
// socket. A full table drops the mapping used longest ago; a remote still
// exchanging datagrams refreshes its mapping on every one and keeps it. The
// bound matches maxLocalAddrs, the other per-remote table in this package.
const maxRelayAddrs = maxLocalAddrs

// RelayKey identifies a relay path: a relay URL together with the remote
// endpoint reached through it. It is the key type of the relay mapped-address
// table.
type RelayKey struct {
	URL netaddr.RelayURL
	EID key.EndpointID
}

// NewSocket returns a ready Socket with empty mapped-address tables.
func NewSocket() *Socket {
	s := &Socket{
		endpointAddrs: NewAddrMap[key.EndpointID, EndpointIDMappedAddr](
			NewEndpointIDMappedAddr,
			func(v EndpointIDMappedAddr) netip.Addr { return v.Addr() },
		),
		relayAddrs: NewAddrMap[relayMapKey, RelayMappedAddr](
			NewRelayMappedAddr,
			func(v RelayMappedAddr) netip.Addr { return v.Addr() },
		),
		relayByKey: make(map[relayMapKey]*relayEntry),
		customAddrs: NewAddrMap[string, CustomMappedAddr](
			NewCustomMappedAddr,
			func(v CustomMappedAddr) netip.Addr { return v.Addr() },
		),
		customByKey: make(map[string]netaddr.CustomAddr),
	}
	s.relayHeard.prev, s.relayHeard.next = &s.relayHeard, &s.relayHeard
	return s
}

// Close marks the socket closed. Subsequent sends are dropped (blackholed) so
// quic-go's loss recovery handles in-flight datagrams rather than seeing a hard
// error. It is idempotent.
func (s *Socket) Close() { s.closed.Store(true) }

// IsClosed reports whether the socket has been closed.
func (s *Socket) IsClosed() bool { return s.closed.Load() }

// EndpointIDMappedAddrFor returns the endpoint-id mapped address for id,
// allocating one on first use.
func (s *Socket) EndpointIDMappedAddrFor(id key.EndpointID) EndpointIDMappedAddr {
	return s.endpointAddrs.Get(id)
}

// LookupEndpointID returns the endpoint id for an endpoint-id mapped address, if
// known.
func (s *Socket) LookupEndpointID(m EndpointIDMappedAddr) (key.EndpointID, bool) {
	return s.endpointAddrs.Lookup(m.Addr())
}

// RelayMappedAddrFor returns the relay mapped address for the (url, eid) pair,
// allocating one on first use. Each call marks the pair as the most recently
// used; see [maxRelayAddrs].
func (s *Socket) RelayMappedAddrFor(url netaddr.RelayURL, eid key.EndpointID) RelayMappedAddr {
	key := relayMapKey{url.String(), eid}
	s.relayMu.Lock()
	defer s.relayMu.Unlock()
	if e, ok := s.relayByKey[key]; ok {
		s.relayUnlink(e)
		s.relayLinkFront(e)
	} else {
		if len(s.relayByKey) >= maxRelayAddrs {
			s.relayForget(s.relayHeard.prev)
		}
		e := &relayEntry{RelayKey: RelayKey{URL: url, EID: eid}, key: key}
		s.relayByKey[key] = e
		s.relayLinkFront(e)
	}
	return s.relayAddrs.Get(key)
}

// relayForget drops the relay mapping e. Caller holds relayMu.
func (s *Socket) relayForget(e *relayEntry) {
	s.relayUnlink(e)
	delete(s.relayByKey, e.key)
	s.relayAddrs.Remove(e.key)
}

// relayLinkFront puts e at the head of the recency list. Caller holds relayMu.
func (s *Socket) relayLinkFront(e *relayEntry) {
	e.prev, e.next = &s.relayHeard, s.relayHeard.next
	e.next.prev = e
	s.relayHeard.next = e
}

// relayUnlink removes e from the recency list. Caller holds relayMu.
func (s *Socket) relayUnlink(e *relayEntry) {
	e.prev.next, e.next.prev = e.next, e.prev
	e.prev, e.next = nil, nil
}

// LookupRelay returns the (url, eid) pair for a relay mapped address, if known.
func (s *Socket) LookupRelay(m RelayMappedAddr) (RelayKey, bool) {
	key, ok := s.relayAddrs.Lookup(m.Addr())
	if !ok {
		return RelayKey{}, false
	}
	s.relayMu.Lock()
	e, ok := s.relayByKey[key]
	s.relayMu.Unlock()
	if !ok {
		return RelayKey{}, false
	}
	return e.RelayKey, true
}

// CustomMappedAddrFor returns the custom mapped address for c, allocating one on
// first use and recording the reverse mapping back to c.
func (s *Socket) CustomMappedAddrFor(c netaddr.CustomAddr) CustomMappedAddr {
	key := c.String()
	s.customMu.Lock()
	s.customByKey[key] = c
	s.customMu.Unlock()
	return s.customAddrs.Get(key)
}

// PathAddr classifies a QUIC connection's remote net.Addr into the magic
// socket's transport [Addr]: a real IP becomes an IP path; a relay or custom
// mapped ULA is reverse-looked-up through the mapped-address tables. An unknown
// mapped address (or one whose mapping has been forgotten) falls back to an IP
// path so the per-remote actor still tracks a stable address. remoteID is used
// for relay paths, which are keyed by (relay url, endpoint id).
func (s *Socket) PathAddr(remoteID key.EndpointID, ra net.Addr) Addr {
	ap, ok := addrPort(ra)
	if !ok {
		return Addr{}
	}
	switch Classify(ap.Addr()) {
	case KindRelay:
		if rk, ok := s.LookupRelay(RelayMappedAddrFromAddr(ap.Addr())); ok {
			return RelayAddr(rk.URL, rk.EID)
		}
		return IPAddr(ap)
	case KindCustom:
		if c, ok := s.LookupCustom(CustomMappedAddr{a: ap.Addr()}); ok {
			return CustomAddr(c)
		}
		return IPAddr(ap)
	default:
		return IPAddr(ap)
	}
}

// EvictRemote drops the mapped addresses recorded for a reaped remote: the
// endpoint-id mapping for id, every relay mapping whose remote endpoint is id,
// and the custom mappings among addrs (the remote's known transport
// addresses). Without eviction the tables grow without bound under peer churn
// (the upstream Rust implementation has the same leak, iroh issue #4293). A
// mapping is regenerated on the next use of the same key, so evicting a remote
// that immediately returns only costs a fresh mapped address.
func (s *Socket) EvictRemote(id key.EndpointID, addrs []Addr) {
	s.endpointAddrs.Remove(id)

	s.relayMu.Lock()
	for _, e := range s.relayByKey {
		if e.EID == id {
			s.relayForget(e)
		}
	}
	s.relayMu.Unlock()

	for _, a := range addrs {
		c, ok := a.Custom()
		if !ok {
			continue
		}
		k := c.String()
		s.customMu.Lock()
		delete(s.customByKey, k)
		s.customMu.Unlock()
		s.customAddrs.Remove(k)
	}
}

// LookupCustom returns the custom address for a custom mapped address, if known.
func (s *Socket) LookupCustom(m CustomMappedAddr) (netaddr.CustomAddr, bool) {
	key, ok := s.customAddrs.Lookup(m.Addr())
	if !ok {
		return netaddr.CustomAddr{}, false
	}
	s.customMu.Lock()
	c, ok := s.customByKey[key]
	s.customMu.Unlock()
	return c, ok
}
