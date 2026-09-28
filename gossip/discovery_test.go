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
// cache without bound or evict the local endpoint's own entry.
func TestDiscoveryPeersBounded(t *testing.T) {
	self := key.UncheckedEndpointID([32]byte{0xff})
	d := New(self)
	d.Publish(dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1")}))
	b, err := encodeDiscoveryPeerData(dns.NewEndpointData(netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:2")}))
	if err != nil {
		t.Fatal(err)
	}
	const count = 4 * discoveryPeerCap
	var last key.EndpointID
	for i := range count {
		var id [32]byte
		binary.BigEndian.PutUint32(id[:], uint32(i))
		last = key.UncheckedEndpointID(id)
		if err := d.handlePeerData(last, b); err != nil {
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
}
