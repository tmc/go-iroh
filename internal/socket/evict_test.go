package socket

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestAddrMapRemove(t *testing.T) {
	m := NewAddrMap[string](
		NewRelayMappedAddr,
		func(v RelayMappedAddr) netip.Addr { return v.Addr() },
	)
	v := m.Get("a")
	m.Get("b")
	if m.Len() != 2 {
		t.Fatalf("Len = %d, want 2", m.Len())
	}

	m.Remove("a")
	if m.Len() != 1 {
		t.Errorf("Len after Remove = %d, want 1", m.Len())
	}
	if _, ok := m.Lookup(v.Addr()); ok {
		t.Error("Lookup(removed addr) = ok, want miss")
	}
	// Removing an absent key is a no-op.
	m.Remove("a")

	// A fresh Get regenerates a new mapped address.
	if m.Get("a") == v {
		t.Error("Get after Remove returned the old mapped address")
	}
}

func TestSocketEvictRemote(t *testing.T) {
	s := NewSocket()
	url, err := netaddr.ParseRelayURL("https://relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	eid := testEndpointID(t)
	other := testEndpointID(t)

	epMapped := s.EndpointIDMappedAddrFor(eid)
	relayMapped := s.RelayMappedAddrFor(url, eid)
	custom := netaddr.NewCustomAddr(7, []byte("peer"))
	customMapped := s.CustomMappedAddrFor(custom)

	otherMapped := s.EndpointIDMappedAddrFor(other)
	otherRelay := s.RelayMappedAddrFor(url, other)

	s.EvictRemote(eid, []Addr{CustomAddr(custom)})

	if _, ok := s.LookupEndpointID(epMapped); ok {
		t.Error("endpoint-id mapping survived eviction")
	}
	if _, ok := s.LookupRelay(relayMapped); ok {
		t.Error("relay mapping survived eviction")
	}
	if _, ok := s.LookupCustom(customMapped); ok {
		t.Error("custom mapping survived eviction")
	}

	// Mappings for other remotes are untouched.
	if _, ok := s.LookupEndpointID(otherMapped); !ok {
		t.Error("other remote's endpoint-id mapping was evicted")
	}
	if _, ok := s.LookupRelay(otherRelay); !ok {
		t.Error("other remote's relay mapping was evicted")
	}
}

// TestRemoteMapEvictsOnIdle exercises the leak fix end to end: a remote's
// mapped addresses are released when its actor idles out, and regenerated on
// the next reference.
func TestRemoteMapEvictsOnIdle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s := NewSocket()
	m := newRemoteMap(ctx, BiasedRttPathSelector{}, nil, 10*time.Millisecond, nil)
	m.SetOnEvict(s.EvictRemote)

	eid := testEndpointID(t)
	m.Actor(eid)
	epMapped := s.EndpointIDMappedAddrFor(eid)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := s.LookupEndpointID(epMapped); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mapped address not evicted after actor idle-out")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m.Len() != 0 {
		t.Errorf("actors registered after idle-out = %d, want 0", m.Len())
	}
	if s.endpointAddrs.Len() != 0 {
		t.Errorf("endpoint mappings after eviction = %d, want 0", s.endpointAddrs.Len())
	}

	// The next reference regenerates a fresh mapping.
	if got := s.EndpointIDMappedAddrFor(eid); got == epMapped {
		t.Error("regenerated mapping reused the evicted address")
	}
}

// TestSocketRelayMappingsAreBounded checks that a relay-side peer cycling
// endpoint ids cannot grow the relay mapped-address table without bound, and
// that a remote still exchanging datagrams keeps its mapped address.
func TestSocketRelayMappingsAreBounded(t *testing.T) {
	s := NewSocket()
	url, err := netaddr.ParseRelayURL("https://relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	live := testEndpointID(t)
	liveMapped := s.RelayMappedAddrFor(url, live)
	// Enough identities to fill the table several times over.
	for n := 1; n <= 3*maxRelayAddrs; n++ {
		var b [key.PublicKeySize]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		s.RelayMappedAddrFor(url, key.UncheckedEndpointID(b))
		if n%64 == 0 && s.RelayMappedAddrFor(url, live) != liveMapped {
			t.Fatalf("live remote's mapped address changed after %d identities", n)
		}
		if got := s.relayAddrs.Len(); got > maxRelayAddrs {
			t.Fatalf("table holds %d relay mappings after %d identities, want at most %d", got, n, maxRelayAddrs)
		}
	}
	if rk, ok := s.LookupRelay(liveMapped); !ok || rk.EID != live {
		t.Errorf("LookupRelay(live) = %v, %v; want %v", rk.EID, ok, live)
	}
}
