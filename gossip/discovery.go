package gossip

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"lukechampine.com/blake3"
)

const (
	// Provenance is the provenance reported on resolved gossip discovery items.
	Provenance = "gossip"

	defaultDiscoveryTimeout = 10 * time.Second

	// discoveryPeerCap bounds the peers a Discovery remembers. Any topic
	// member can announce data for any number of identities, so past the
	// cap the least recently updated peer is forgotten.
	discoveryPeerCap = 1024
)

// DefaultDiscoveryTopic is the default topic used by Discovery.
var DefaultDiscoveryTopic = TopicID(blake3.Sum256([]byte("iroh-gossip-discovery-v1")))

// Option configures a Discovery.
type Option func(*Discovery)

// WithGossip configures the gossip overlay used by a Discovery.
func WithGossip(g *Gossip, topic TopicID, bootstrap []netaddr.EndpointAddr) Option {
	return func(d *Discovery) {
		d.gossip = g
		d.topicID = topic
		d.bootstrap = append([]netaddr.EndpointAddr(nil), bootstrap...)
	}
}

// WithLookupTimeout sets how long Resolve waits after a cache miss.
func WithLookupTimeout(timeout time.Duration) Option {
	return func(d *Discovery) {
		if timeout > 0 {
			d.timeout = timeout
		}
	}
}

// Discovery publishes and resolves endpoint addressing information over a
// gossip topic. The zero value is not usable; create one with [New].
type Discovery struct {
	id        key.EndpointID
	gossip    *Gossip
	topicID   TopicID
	bootstrap []netaddr.EndpointAddr
	timeout   time.Duration

	mu      sync.Mutex
	peers   map[key.EndpointID]*discoveryPeer
	updated discoveryPeer // sentinel of a list of remote peers, most recently updated first
	topic   *Topic
	pending *dns.EndpointData
}

type discoveryPeer struct {
	id          key.EndpointID
	data        dns.EndpointData
	lastUpdated uint64
	prev, next  *discoveryPeer
}

// New returns a Discovery for id.
func New(id key.EndpointID, opts ...Option) *Discovery {
	d := &Discovery{
		id:      id,
		topicID: DefaultDiscoveryTopic,
		timeout: defaultDiscoveryTimeout,
		peers:   make(map[key.EndpointID]*discoveryPeer),
	}
	d.updated.prev, d.updated.next = &d.updated, &d.updated
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Start subscribes to the configured gossip topic until ctx is cancelled.
func (d *Discovery) Start(ctx context.Context) error {
	if d == nil {
		return errors.New("gossip: nil Discovery")
	}
	if d.gossip == nil {
		<-ctx.Done()
		return nil
	}
	d.mu.Lock()
	pending := cloneEndpointDataPtr(d.pending)
	d.mu.Unlock()
	if pending != nil {
		d.publishPeerData(*pending)
	}
	topic, err := d.gossip.Subscribe(ctx, d.topicID, d.bootstrap)
	if err != nil {
		return fmt.Errorf("gossip: discovery subscribe: %w", err)
	}
	d.mu.Lock()
	d.topic = topic
	d.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = topic.Close()
	}()
	for ev, err := range topic.Events() {
		if err != nil {
			return err
		}
		if ev.Kind == NeighborUp {
			d.mu.Lock()
			pending := cloneEndpointDataPtr(d.pending)
			d.mu.Unlock()
			if pending != nil {
				d.publishPeerData(*pending)
			}
			continue
		}
		if ev.Kind != PeerData {
			continue
		}
		if err := d.handlePeerData(ev.Peer, ev.Data); err != nil {
			continue
		}
	}
	return nil
}

// Publish advertises data on the gossip topic. It is fire-and-forget and
// returns immediately, matching iroh.AddressPublisher.
func (d *Discovery) Publish(data dns.EndpointData) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.pending = &data
	// The local entry is not on the recency list, so it is never evicted.
	d.peers[d.id] = &discoveryPeer{
		id:          d.id,
		data:        cloneEndpointData(data),
		lastUpdated: uint64(time.Now().UnixMicro()),
	}
	topic := d.topic
	d.mu.Unlock()
	if topic != nil {
		d.publishPeerData(data)
	}
}

// Resolve returns the cached item for id, if present, and otherwise waits until
// ctx or the lookup timeout fires.
func (d *Discovery) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
	if d == nil {
		return nil
	}
	return func(yield func(iroh.Item, error) bool) {
		if item, ok := d.item(id); ok {
			yield(item, nil)
			return
		}
		timer := time.NewTimer(d.timeout)
		defer timer.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				yield(iroh.Item{}, ctx.Err())
				return
			case <-timer.C:
				return
			case <-tick.C:
				if item, ok := d.item(id); ok {
					yield(item, nil)
					return
				}
			}
		}
	}
}

func (d *Discovery) publishPeerData(data dns.EndpointData) {
	b, err := encodeDiscoveryPeerData(data)
	if err != nil {
		return
	}
	d.mu.Lock()
	g := d.gossip
	d.mu.Unlock()
	if g == nil {
		return
	}
	g.mu.Lock()
	out := g.handleLocked(gossipproto.InEvent{
		Kind: gossipproto.UpdatePeerData,
		Data: gossipproto.PeerData(b),
		Now:  time.Now(),
	})
	var peers []gossipproto.PeerID
	for peer := range g.neighbors[d.topicID] {
		peers = append(peers, peer)
	}
	if len(peers) > 0 {
		out = append(out, g.handleLocked(gossipproto.InEvent{
			Kind:  gossipproto.CommandEvent,
			Topic: d.topicID,
			Command: gossipproto.TopicCommand{
				Kind:  gossipproto.TopicCommandJoin,
				Peers: peers,
			},
			Now: time.Now(),
		})...)
	}
	g.mu.Unlock()
	g.dispatch(out)
}

func (d *Discovery) handlePeerData(id key.EndpointID, b []byte) error {
	data, err := decodeDiscoveryPeerData(b)
	if err != nil {
		return err
	}
	if id.Equal(d.id) {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.peers[id]
	if ok {
		unlinkPeer(p)
	} else {
		if oldest := d.updated.prev; len(d.peers) >= discoveryPeerCap && oldest != &d.updated {
			unlinkPeer(oldest)
			delete(d.peers, oldest.id)
		}
		p = &discoveryPeer{id: id}
		d.peers[id] = p
	}
	p.data = cloneEndpointData(data)
	p.lastUpdated = uint64(time.Now().UnixMicro())
	p.prev, p.next = &d.updated, d.updated.next
	p.next.prev = p
	d.updated.next = p
	return nil
}

// unlinkPeer removes p from the recency list. d.mu must be held.
func unlinkPeer(p *discoveryPeer) {
	p.prev.next, p.next.prev = p.next, p.prev
	p.prev, p.next = nil, nil
}

func (d *Discovery) item(id key.EndpointID) (iroh.Item, bool) {
	d.mu.Lock()
	peer, ok := d.peers[id]
	var data dns.EndpointData
	var lastUpdated uint64
	if ok {
		data, lastUpdated = cloneEndpointData(peer.data), peer.lastUpdated
	}
	d.mu.Unlock()
	if !ok {
		return iroh.Item{}, false
	}
	info := dns.EndpointInfo{ID: id, Data: data}
	return iroh.NewItem(info, Provenance, &lastUpdated), true
}

type discoveryAddrInfo struct {
	relayURL        *string
	directAddresses []netip.AddrPort
}

func encodeDiscoveryPeerData(data dns.EndpointData) ([]byte, error) {
	info := discoveryAddrInfo{}
	if relays := data.RelayURLs(); len(relays) > 0 {
		s := relays[0].String()
		info.relayURL = &s
	}
	info.directAddresses = data.IPAddrs()
	var e postcard.Encoder
	if err := info.EncodePostcard(&e); err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

func decodeDiscoveryPeerData(b []byte) (dns.EndpointData, error) {
	var info discoveryAddrInfo
	d := postcard.NewDecoder(b)
	if err := info.DecodePostcard(d); err != nil {
		return dns.EndpointData{}, fmt.Errorf("gossip: decode discovery peer data: %w", err)
	}
	if !d.Done() {
		return dns.EndpointData{}, postcard.ErrTrailingBytes
	}
	var addrs []netaddr.TransportAddr
	if info.relayURL != nil {
		relay, err := netaddr.ParseRelayURL(*info.relayURL)
		if err != nil {
			return dns.EndpointData{}, fmt.Errorf("gossip: decode discovery relay: %w", err)
		}
		addrs = append(addrs, netaddr.RelayAddr{URL: relay})
	}
	for _, addr := range info.directAddresses {
		addrs = append(addrs, netaddr.IPAddr{Addr: addr})
	}
	return dns.NewEndpointData(addrs...), nil
}

func (a discoveryAddrInfo) EncodePostcard(e *postcard.Encoder) error {
	if a.relayURL == nil {
		e.Uint(0)
	} else {
		e.Uint(1)
		e.String(*a.relayURL)
	}
	e.Uint(uint64(len(a.directAddresses)))
	for _, addr := range a.directAddresses {
		if err := encodeSocketAddr(e, addr); err != nil {
			return err
		}
	}
	return nil
}

func (a *discoveryAddrInfo) DecodePostcard(d *postcard.Decoder) error {
	ok, err := d.Uint()
	if err != nil {
		return err
	}
	switch ok {
	case 0:
		a.relayURL = nil
	case 1:
		s, err := d.String()
		if err != nil {
			return err
		}
		a.relayURL = &s
	default:
		return fmt.Errorf("gossip: invalid discovery relay option %d", ok)
	}
	n, err := d.Uint()
	if err != nil {
		return err
	}
	if n > 1024 {
		return fmt.Errorf("gossip: too many discovery addresses %d", n)
	}
	a.directAddresses = make([]netip.AddrPort, 0, n)
	for range int(n) {
		addr, err := decodeSocketAddr(d)
		if err != nil {
			return err
		}
		a.directAddresses = append(a.directAddresses, addr)
	}
	return nil
}

func encodeSocketAddr(e *postcard.Encoder, addr netip.AddrPort) error {
	a := addr.Addr()
	if a.Is4() {
		e.Uint(0)
		b := a.As4()
		e.RawBytes(b[:])
		e.Uint(uint64(addr.Port()))
		return nil
	}
	if a.Is6() {
		e.Uint(1)
		b := a.As16()
		e.RawBytes(b[:])
		e.Uint(uint64(addr.Port()))
		return nil
	}
	return fmt.Errorf("gossip: invalid discovery address %s", addr)
}

func decodeSocketAddr(d *postcard.Decoder) (netip.AddrPort, error) {
	kind, err := d.Uint()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var addr netip.Addr
	switch kind {
	case 0:
		b, err := d.RawBytes(4)
		if err != nil {
			return netip.AddrPort{}, err
		}
		addr = netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
	case 1:
		b, err := d.RawBytes(16)
		if err != nil {
			return netip.AddrPort{}, err
		}
		addr = netip.AddrFrom16([16]byte{
			b[0], b[1], b[2], b[3],
			b[4], b[5], b[6], b[7],
			b[8], b[9], b[10], b[11],
			b[12], b[13], b[14], b[15],
		})
	default:
		return netip.AddrPort{}, fmt.Errorf("gossip: invalid discovery address kind %d", kind)
	}
	port, err := d.Uint()
	if err != nil {
		return netip.AddrPort{}, err
	}
	if port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("gossip: invalid discovery port %d", port)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

func cloneEndpointDataPtr(data *dns.EndpointData) *dns.EndpointData {
	if data == nil {
		return nil
	}
	clone := cloneEndpointData(*data)
	return &clone
}

func cloneEndpointData(data dns.EndpointData) dns.EndpointData {
	clone := dns.NewEndpointData(data.Addrs()...)
	if u := data.UserData(); u != nil {
		uc := *u
		clone = clone.WithUserData(&uc)
	}
	return clone
}
