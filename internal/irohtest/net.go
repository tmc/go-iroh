package irohtest

import (
	"context"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

// DefaultDelay is the one-way delay of an unimpaired link. It is nonzero so
// that RTT-driven code (loss detection, PTO, pacing) sees a real round trip
// even on a virtual clock.
const DefaultDelay = time.Millisecond

// queueLen is how many datagrams a peer's receive queue holds before new
// arrivals are dropped, as a full socket buffer would.
const queueLen = 1024

// customID is the custom transport id irohtest addresses use.
const customID = 0x69726f6874657374 // "irohtest"

// An Impairment describes how one direction of a link mishandles datagrams.
// The zero value delivers everything after [DefaultDelay].
type Impairment struct {
	// Loss is the probability in [0, 1] that a datagram is dropped.
	Loss float64
	// Delay is the one-way delay. Zero means DefaultDelay; use a negative
	// value for none.
	Delay time.Duration
	// Jitter adds a uniformly random extra delay in [0, Jitter). Jitter
	// larger than the gap between datagrams reorders them.
	Jitter time.Duration
	// Duplicate is the probability in [0, 1] that a datagram is delivered
	// twice.
	Duplicate float64
	// Rate limits the link to this many bytes per second. Zero means
	// unlimited. Datagrams queue behind one another.
	Rate int
	// StallAfter, if positive, delivers only the first StallAfter datagrams
	// sent after the impairment is set and drops the rest.
	StallAfter int
	// Down drops every datagram.
	Down bool
}

// A Net is an in-memory network of iroh peers. Create one with [NewNet].
type Net struct {
	tb   testing.TB
	seed uint64

	mu      sync.Mutex
	peers   map[uint64]*Peer
	links   map[[2]uint64]*link
	egress  map[uint64]*link // per-sender impairment applied to every link
	nextID  uint64
	closing bool
}

// NewNet returns an empty network. Peers created on it are shut down when the
// test ends. Inside a synctest bubble, call NewNet inside the bubble.
func NewNet(tb testing.TB) *Net {
	n := &Net{
		tb:     tb,
		seed:   1,
		peers:  make(map[uint64]*Peer),
		links:  make(map[[2]uint64]*link),
		egress: make(map[uint64]*link),
	}
	tb.Cleanup(n.shutdown)
	return n
}

// Seed sets the seed from which each link's PRNG is derived. It affects only
// links first used after the call.
func (n *Net) Seed(seed uint64) {
	n.mu.Lock()
	n.seed = seed
	n.mu.Unlock()
}

// Peer binds a new endpoint on n with the given options added to the ones
// that confine it to n. It fails the test if the bind fails.
func (n *Net) Peer(opts ...iroh.Option) *Peer {
	n.tb.Helper()
	n.mu.Lock()
	n.nextID++
	id := n.nextID
	n.mu.Unlock()

	var b [8]byte
	binary.BigEndian.PutUint64(b[:], id)
	tr := &transport{
		net:  n,
		id:   id,
		addr: netaddr.NewCustomAddr(customID, b[:]),
		recv: make(chan iroh.CustomDatagram, queueLen),
	}
	base := []iroh.Option{
		iroh.WithoutIPTransports(),
		iroh.WithoutRelayTransports(),
		iroh.WithoutNetReport(),
		iroh.WithCustomTransport(tr),
	}
	ep, err := iroh.Bind(context.Background(), append(base, opts...)...)
	if err != nil {
		n.tb.Fatalf("irohtest: bind peer %d: %v", id, err)
	}
	p := &Peer{Endpoint: ep, net: n, tr: tr}
	n.mu.Lock()
	n.peers[id] = p
	n.mu.Unlock()
	return p
}

// Link returns the direction of the link that carries datagrams from src
// to dst, for impairing it.
func (n *Net) Link(src, dst *Peer) *Link {
	return &Link{n.link(src.tr.id, dst.tr.id)}
}

func (n *Net) link(src, dst uint64) *link {
	n.mu.Lock()
	defer n.mu.Unlock()
	k := [2]uint64{src, dst}
	l := n.links[k]
	if l == nil {
		l = newLink(n.seed ^ src<<32 ^ dst)
		n.links[k] = l
	}
	return l
}

func (n *Net) egressLink(src uint64) *link {
	n.mu.Lock()
	defer n.mu.Unlock()
	l := n.egress[src]
	if l == nil {
		l = newLink(n.seed ^ src<<32 ^ 0xffffffff)
		n.egress[src] = l
	}
	return l
}

func (n *Net) peer(id uint64) *Peer {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing {
		return nil
	}
	return n.peers[id]
}

func (n *Net) shutdown() {
	n.mu.Lock()
	n.closing = true
	peers := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	n.mu.Unlock()
	for _, p := range peers {
		p.Shutdown(context.Background())
	}
}

// A Peer is an endpoint on a [Net].
type Peer struct {
	*iroh.Endpoint
	net *Net
	tr  *transport
}

// Impair sets the impairment applied to every datagram p sends, on top of any
// per-link impairment. It is how a test makes one peer lossy, slow, or silent
// towards everyone.
func (p *Peer) Impair(imp Impairment) {
	p.net.egressLink(p.tr.id).set(imp)
}

// String returns a short name for p, for test logs.
func (p *Peer) String() string {
	return fmt.Sprintf("peer%d(%s)", p.tr.id, p.ID().Short())
}

// A Link is one direction of the path between two peers.
type Link struct{ l *link }

// Impair sets the impairment for this direction, replacing any earlier one.
// A StallAfter count starts from this call.
func (l *Link) Impair(imp Impairment) { l.l.set(imp) }

type link struct {
	mu   sync.Mutex
	imp  Impairment
	sent int
	busy time.Time // when a rate-limited link finishes its current datagram
	rng  *mrand.Rand
}

func newLink(seed uint64) *link {
	return &link{rng: mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

func (l *link) set(imp Impairment) {
	l.mu.Lock()
	l.imp = imp
	l.sent = 0
	l.mu.Unlock()
}

// plan decides the fate of one datagram of size bytes: how many copies to
// deliver (0, 1, or 2) and after what delay. A zero Impairment.Delay means
// base.
func (l *link) plan(size int, now time.Time, base time.Duration) (copies int, delay time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	imp := l.imp
	l.sent++
	if imp.Down || (imp.StallAfter > 0 && l.sent > imp.StallAfter) {
		return 0, 0
	}
	if imp.Loss > 0 && l.rng.Float64() < imp.Loss {
		return 0, 0
	}
	switch {
	case imp.Delay > 0:
		delay = imp.Delay
	case imp.Delay == 0:
		delay = base
	}
	if imp.Jitter > 0 {
		delay += time.Duration(l.rng.Int64N(int64(imp.Jitter)))
	}
	if imp.Rate > 0 {
		start := now
		if l.busy.After(start) {
			start = l.busy
		}
		l.busy = start.Add(time.Duration(size) * time.Second / time.Duration(imp.Rate))
		delay += l.busy.Sub(now)
	}
	copies = 1
	if imp.Duplicate > 0 && l.rng.Float64() < imp.Duplicate {
		copies = 2
	}
	return copies, delay
}

// transport is a peer's iroh.CustomTransport.
type transport struct {
	net  *Net
	id   uint64
	addr netaddr.CustomAddr
	recv chan iroh.CustomDatagram
}

func (t *transport) Serve(ctx context.Context, recv func(iroh.CustomDatagram) bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-t.recv:
			recv(d)
		}
	}
}

func (t *transport) Send(remote netaddr.CustomAddr, _ *netaddr.CustomAddr, p []byte) bool {
	data := remote.Data()
	if remote.ID() != customID || len(data) != 8 {
		return false
	}
	dstID := binary.BigEndian.Uint64(data)
	dst := t.net.peer(dstID)
	if dst == nil {
		return true // sent into the void, as UDP would be
	}
	now := time.Now()
	c1, d1 := t.net.egressLink(t.id).plan(len(p), now, 0)
	if c1 == 0 {
		return true
	}
	c2, d2 := t.net.link(t.id, dstID).plan(len(p), now, DefaultDelay)
	if c2 == 0 {
		return true
	}
	d := iroh.CustomDatagram{Remote: t.addr, Local: remote, HasLocal: true, Data: append([]byte(nil), p...)}
	for range max(c1, c2) {
		dst.tr.deliver(d, d1+d2)
	}
	return true
}

func (t *transport) LocalCustomAddrs(context.Context) ([]netaddr.CustomAddr, error) {
	return []netaddr.CustomAddr{t.addr}, nil
}

func (t *transport) deliver(d iroh.CustomDatagram, after time.Duration) {
	enqueue := func() {
		select {
		case t.recv <- d:
		default: // queue full: drop, as a full socket buffer would
		}
	}
	if after <= 0 {
		enqueue()
		return
	}
	time.AfterFunc(after, enqueue)
}
