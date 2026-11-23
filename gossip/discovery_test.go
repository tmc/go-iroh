package gossip

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestDiscoveryPeerDataRustVectors(t *testing.T) {
	relay, err := netaddr.ParseRelayURL("https://relay.example.com/")
	if err != nil {
		t.Fatalf("parse relay: %v", err)
	}
	v4 := netip.MustParseAddrPort("127.0.0.1:1234")
	v6 := netip.MustParseAddrPort("[::1]:5678")

	tests := []struct {
		name string
		data dns.EndpointData
		hex  string
	}{
		{
			name: "empty",
			data: dns.NewEndpointData(),
			hex:  "0000",
		},
		{
			name: "relay",
			data: dns.NewEndpointData(netaddr.RelayAddr{URL: relay}),
			hex:  "011a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f00",
		},
		{
			name: "direct",
			data: dns.NewEndpointData(netaddr.IPAddr{Addr: v4}, netaddr.IPAddr{Addr: v6}),
			hex:  "0002007f000001d2090100000000000000000000000000000001ae2c",
		},
		{
			name: "relay direct",
			data: dns.NewEndpointData(netaddr.RelayAddr{URL: relay}, netaddr.IPAddr{Addr: v4}, netaddr.IPAddr{Addr: v6}),
			hex:  "011a68747470733a2f2f72656c61792e6578616d706c652e636f6d2f02007f000001d2090100000000000000000000000000000001ae2c",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeDiscoveryPeerData(tt.data)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("encode = %x, want %s", got, tt.hex)
			}
			round, err := decodeDiscoveryPeerData(got)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got, want := round.Addrs(), tt.data.Addrs(); len(got) != len(want) {
				t.Fatalf("round-trip addrs = %v, want %v", got, want)
			}
		})
	}
}

// TestDiscoveryPeersBounded checks that a flood of peer data under distinct
// identities, which any topic member can send, cannot grow the discovery
// cache without bound or evict the local endpoint's own entry or a recently
// updated peer.
func TestDiscoveryPeersBounded(t *testing.T) {
	self := key.UncheckedEndpointID([32]byte{0xff})
	d := New(self)
	d.Publish(dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1")}))
	b, err := encodeDiscoveryPeerData(dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:2")}))
	if err != nil {
		t.Fatal(err)
	}
	// kept is updated as often as new identities arrive, so it is never
	// the least recently updated.
	kept := key.UncheckedEndpointID([32]byte{0xfe})
	const count = 4 * discoveryPeerCap
	var last key.EndpointID
	for i := range count {
		var id [32]byte
		binary.BigEndian.PutUint32(id[:], uint32(i))
		last = key.UncheckedEndpointID(id)
		if err := d.handlePeerData(last, b); err != nil {
			t.Fatal(err)
		}
		if err := d.handlePeerData(kept, b); err != nil {
			t.Fatal(err)
		}
	}
	d.mu.Lock()
	n := len(d.peers)
	d.mu.Unlock()
	if n > discoveryPeerCap {
		t.Errorf("discovery holds %d peers after %d distinct identities, want at most %d", n, count, discoveryPeerCap)
	}
	if _, ok := d.item(self); !ok {
		t.Error("local entry evicted")
	}
	if _, ok := d.item(last); !ok {
		t.Error("newest peer missing")
	}
	if _, ok := d.item(kept); !ok {
		t.Error("recently updated peer evicted")
	}
}

// TestDiscoveryPeerAddrsBounded checks that a peer whose addresses keep
// changing keeps its newest addresses first, capped at discoveryAddrCap.
func TestDiscoveryPeerAddrsBounded(t *testing.T) {
	self := key.UncheckedEndpointID([32]byte{0xff})
	peer := key.UncheckedEndpointID([32]byte{0x01})
	d := New(self)

	addr := func(port uint16) netip.AddrPort {
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, 1}), port)
	}
	for port := range uint16(1000) {
		b, err := encodeDiscoveryPeerData(dns.NewEndpointData(netaddr.IPAddr{Addr: addr(port)}))
		if err != nil {
			t.Fatal(err)
		}
		if err := d.handlePeerData(peer, b); err != nil {
			t.Fatal(err)
		}
	}

	item, ok := d.item(peer)
	if !ok {
		t.Fatal("peer missing")
	}
	got := item.EndpointInfo().Data.IPAddrs()
	if len(got) != discoveryAddrCap {
		t.Fatalf("stored addresses = %d, want %d", len(got), discoveryAddrCap)
	}
	if got[0] != addr(999) {
		t.Errorf("newest address = %v, want %v", got[0], addr(999))
	}
	if got[len(got)-1] != addr(1000-discoveryAddrCap) {
		t.Errorf("oldest kept address = %v, want %v", got[len(got)-1], addr(1000-discoveryAddrCap))
	}

	// A single update carrying more than discoveryAddrCap addresses is also capped.
	peer2 := key.UncheckedEndpointID([32]byte{0x02})
	many := make([]netaddr.TransportAddr, 0, discoveryAddrCap+10)
	for port := range uint16(discoveryAddrCap + 10) {
		many = append(many, netaddr.IPAddr{Addr: addr(port + 2000)})
	}
	b, err := encodeDiscoveryPeerData(dns.NewEndpointData(many...))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.handlePeerData(peer2, b); err != nil {
		t.Fatal(err)
	}
	item2, ok := d.item(peer2)
	if !ok {
		t.Fatal("peer2 missing")
	}
	if got := item2.EndpointInfo().Data.IPAddrs(); len(got) != discoveryAddrCap {
		t.Fatalf("single-update stored addresses = %d, want %d", len(got), discoveryAddrCap)
	}
}

// BenchmarkDiscoveryPeerChurn measures caching peer data for a new identity
// once the cache is full, so that every call evicts a peer.
func BenchmarkDiscoveryPeerChurn(b *testing.B) {
	d := New(key.UncheckedEndpointID([32]byte{0xff}))
	d.Publish(dns.NewEndpointData())
	data, err := encodeDiscoveryPeerData(dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:2")}))
	if err != nil {
		b.Fatal(err)
	}
	var id [32]byte
	for i := range discoveryPeerCap {
		binary.BigEndian.PutUint32(id[:], uint32(i))
		if err := d.handlePeerData(key.UncheckedEndpointID(id), data); err != nil {
			b.Fatal(err)
		}
	}
	i := discoveryPeerCap
	for b.Loop() {
		binary.BigEndian.PutUint32(id[:], uint32(i))
		i++
		if err := d.handlePeerData(key.UncheckedEndpointID(id), data); err != nil {
			b.Fatal(err)
		}
	}
}
