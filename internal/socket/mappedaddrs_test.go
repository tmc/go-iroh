package socket

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// TestMappedAddrBytes pins the mapped-address byte scheme to the Rust
// implementation (iroh/src/socket/mapped_addrs.rs): ULA prefix 0xfd, n0 global
// id 15 07 0a 51 0b, subnet ids 00 00 / 00 01 / 00 03, and a big-endian u64
// counter. These are a local indirection (never on the wire) but matching the
// scheme keeps the two implementations cross-referenceable.
func TestMappedAddrBytes(t *testing.T) {
	tests := []struct {
		name    string
		subnet  [2]byte
		counter uint64
		want    string
	}{
		{"endpoint id #1", subnetEndpointID, 1, "fd15:70a:510b::1"},
		{"relay #1", subnetRelay, 1, "fd15:70a:510b:1::1"},
		{"custom #1", subnetCustom, 1, "fd15:70a:510b:3::1"},
		{"endpoint id #2", subnetEndpointID, 2, "fd15:70a:510b::2"},
		{"relay #258", subnetRelay, 258, "fd15:70a:510b:1::102"},
	}
	for _, tt := range tests {
		got := mappedAddr(tt.subnet, tt.counter)
		want := netip.MustParseAddr(tt.want)
		if got != want {
			t.Errorf("%s: mappedAddr = %s, want %s (bytes %x)", tt.name, got, want, got.As16())
		}
	}
}

// TestMappedAddrGolden16 pins the full 16-byte address for each subnet against
// hand-computed golden vectors, the strongest cross-reference to the Rust
// scheme (iroh/src/socket/mapped_addrs.rs:20-26): 0xfd | 15 07 0a 51 0b | subnet
// | big-endian u64 counter.
func TestMappedAddrGolden16(t *testing.T) {
	tests := []struct {
		name    string
		subnet  [2]byte
		counter uint64
		want    [16]byte
	}{
		{
			"endpoint id #1", subnetEndpointID, 1,
			[16]byte{0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			"relay #1", subnetRelay, 1,
			[16]byte{0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			"custom #1", subnetCustom, 1,
			[16]byte{0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		{
			"relay #258 (0x102)", subnetRelay, 258,
			[16]byte{0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x01, 0x02},
		},
	}
	for _, tt := range tests {
		got := mappedAddr(tt.subnet, tt.counter).As16()
		if got != tt.want {
			t.Errorf("%s: bytes = %x, want %x", tt.name, got, tt.want)
		}
	}
}

func resetMappedAddrCountersForTest(t *testing.T) {
	t.Helper()
	oldEndpointID := endpointIDCounter.Load()
	oldRelay := relayCounter.Load()
	oldCustom := customCounter.Load()
	endpointIDCounter.Store(0)
	relayCounter.Store(0)
	customCounter.Store(0)
	t.Cleanup(func() {
		endpointIDCounter.Store(oldEndpointID)
		relayCounter.Store(oldRelay)
		customCounter.Store(oldCustom)
	})
}

// TestMappedAddrConstructorGoldens pins the allocating constructors to Rust's
// first counter value: AtomicU64::new(1) followed by fetch_add yields ::1. Go
// uses Add(1) on a zero-value atomic, so the first address must match exactly.
func TestMappedAddrConstructorGoldens(t *testing.T) {
	resetMappedAddrCountersForTest(t)

	tests := []struct {
		name string
		new  func() netip.AddrPort
		want string
		kind MappedKind
	}{
		{
			name: "endpoint id",
			new:  func() netip.AddrPort { return NewEndpointIDMappedAddr().AddrPort() },
			want: "[fd15:70a:510b::1]:12345",
			kind: KindEndpointID,
		},
		{
			name: "relay",
			new:  func() netip.AddrPort { return NewRelayMappedAddr().AddrPort() },
			want: "[fd15:70a:510b:1::1]:12345",
			kind: KindRelay,
		},
		{
			name: "custom",
			new:  func() netip.AddrPort { return NewCustomMappedAddr().AddrPort() },
			want: "[fd15:70a:510b:3::1]:12345",
			kind: KindCustom,
		},
	}
	for _, tt := range tests {
		got := tt.new()
		want := netip.MustParseAddrPort(tt.want)
		if got != want {
			t.Errorf("%s: AddrPort = %s, want %s", tt.name, got, want)
		}
		if got.Port() != mappedPort {
			t.Errorf("%s: port = %d, want %d", tt.name, got.Port(), mappedPort)
		}
		if kind := Classify(got.Addr()); kind != tt.kind {
			t.Errorf("%s: Classify = %v, want %v", tt.name, kind, tt.kind)
		}
	}
}

func TestIPAddrPreservesIPv6Zone(t *testing.T) {
	ap := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("en0"), 4242)
	addr := IPAddr(ap)
	got, ok := addr.IP()
	if !ok {
		t.Fatal("IPAddr did not produce an IP address")
	}
	if got != ap {
		t.Fatalf("IPAddr = %s, want %s", got, ap)
	}
}

func TestUDPAddrRoundTripPreservesIPv6Zone(t *testing.T) {
	ap := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("en0"), 4242)
	udp := udpAddrFromAddrPort(ap)
	if udp.Zone != "en0" {
		t.Fatalf("UDPAddr.Zone = %q, want en0", udp.Zone)
	}
	if got := addrPortFromUDPAddr(udp); got != ap {
		t.Fatalf("round trip = %s, want %s", got, ap)
	}
}

func TestMagicConnUDPAddrCacheKeysIPv6Zone(t *testing.T) {
	m := &MagicConn{recvAddrs: make(map[netip.AddrPort]*net.UDPAddr)}
	ap := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("en0"), 4242)
	got := m.udpAddr(ap)
	if got.Zone != "en0" {
		t.Fatalf("UDPAddr.Zone = %q, want en0", got.Zone)
	}
	if got.AddrPort() != ap {
		t.Fatalf("UDPAddr.AddrPort = %s, want %s", got.AddrPort(), ap)
	}
	if cached := m.udpAddr(ap); cached != got {
		t.Fatal("udpAddr did not reuse cached address")
	}
}

// TestMagicConnUDPAddrCacheConcurrent checks that concurrent receives may
// share the cache. It reports nothing on its own; run it under -race.
func TestMagicConnUDPAddrCacheConcurrent(t *testing.T) {
	m := &MagicConn{recvAddrs: make(map[netip.AddrPort]*net.UDPAddr)}
	// Enough peers that the readers keep meeting first sightings, which is
	// what puts a write next to a read.
	peers := make([]netip.AddrPort, 64)
	for i := range peers {
		peers[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i)}), 4242)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				for _, ap := range peers {
					if got := m.udpAddr(ap); got.AddrPort() != ap {
						t.Errorf("udpAddr(%s) = %s", ap, got.AddrPort())
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

// TestMappedAddrPrefixExact checks the literal first 8 bytes.
func TestMappedAddrPrefixExact(t *testing.T) {
	a := mappedAddr(subnetRelay, 1).As16()
	wantPrefix := []byte{0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0x00, 0x01}
	for i, b := range wantPrefix {
		if a[i] != b {
			t.Errorf("byte %d = 0x%02x, want 0x%02x", i, a[i], b)
		}
	}
	// Counter in the low 8 bytes, big-endian.
	for i := 8; i < 15; i++ {
		if a[i] != 0 {
			t.Errorf("byte %d = 0x%02x, want 0", i, a[i])
		}
	}
	if a[15] != 1 {
		t.Errorf("byte 15 = 0x%02x, want 1", a[15])
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		addr string
		want MappedKind
	}{
		{"fd15:70a:510b::1", KindEndpointID},
		{"fd15:70a:510b:1::1", KindRelay},
		{"fd15:70a:510b:3::1", KindCustom},
		{"fd15:70a:510b:2::1", KindIP}, // unused subnet -> treated as plain IP
		{"192.0.2.1", KindIP},          // real v4
		{"2001:db8::1", KindIP},        // real v6
		{"fd00::1", KindIP},            // ULA but not n0's
	}
	for _, tt := range tests {
		got := Classify(netip.MustParseAddr(tt.addr))
		if got != tt.want {
			t.Errorf("Classify(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestPathAddrMappedReverseLookup(t *testing.T) {
	s := NewSocket()
	url, err := netaddr.ParseRelayURL("https://relay.example.com")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	eid := sk.Public().EndpointID()

	relayMapped := s.RelayMappedAddrFor(url, eid)
	gotRelay := s.PathAddr(eid, net.UDPAddrFromAddrPort(relayMapped.AddrPort()))
	gotURL, gotEID, ok := gotRelay.Relay()
	if !ok {
		t.Fatalf("PathAddr(relay mapped) kind = %v, want relay", gotRelay.Kind())
	}
	if !gotURL.Equal(url) || !gotEID.Equal(eid) {
		t.Errorf("PathAddr(relay mapped) = (%s, %s), want (%s, %s)", gotURL, gotEID, url, eid)
	}

	custom := netaddr.NewCustomAddr(7, []byte("peer"))
	customMapped := s.CustomMappedAddrFor(custom)
	gotCustom := s.PathAddr(eid, net.UDPAddrFromAddrPort(customMapped.AddrPort()))
	got, ok := gotCustom.Custom()
	if !ok {
		t.Fatalf("PathAddr(custom mapped) kind = %v, want custom", gotCustom.Kind())
	}
	if got.String() != custom.String() {
		t.Errorf("PathAddr(custom mapped) = %s, want %s", got, custom)
	}
}

// TestClassifyRejectsMappedPort confirms the dummy port is 12345.
func TestMappedPort(t *testing.T) {
	if NewRelayMappedAddr().AddrPort().Port() != mappedPort || mappedPort != 12345 {
		t.Errorf("mapped port = %d, want 12345", mappedPort)
	}
}

func TestAddrMapRoundTrip(t *testing.T) {
	m := NewAddrMap[string, RelayMappedAddr](
		NewRelayMappedAddr,
		func(v RelayMappedAddr) netip.Addr { return v.Addr() },
	)
	a := m.Get("peer-a")
	b := m.Get("peer-b")
	if a == b {
		t.Fatal("distinct keys produced the same mapped addr")
	}
	if got := m.Get("peer-a"); got != a {
		t.Error("Get is not stable for the same key")
	}
	if k, ok := m.Lookup(a.Addr()); !ok || k != "peer-a" {
		t.Errorf("Lookup(a) = %q,%v, want peer-a,true", k, ok)
	}
	if _, ok := m.Lookup(netip.MustParseAddr("203.0.113.1")); ok {
		t.Error("Lookup of unknown addr should fail")
	}
}

// TestMagicConnUDPAddrCacheIsBounded checks that a peer varying its source
// address cannot make the cache grow without bound, and that an address
// returned after the cache was emptied is still the address that was asked
// for.
func TestMagicConnUDPAddrCacheIsBounded(t *testing.T) {
	tests := []struct {
		name string
		at   func(n int) netip.AddrPort
	}{
		{"ports", func(n int) netip.AddrPort {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, 1}), uint16(n))
		}},
		{"addrs", func(n int) netip.AddrPort {
			var a [16]byte
			a[0], a[1] = 0x20, 0x01
			binary.BigEndian.PutUint32(a[12:], uint32(n))
			return netip.AddrPortFrom(netip.AddrFrom16(a), 4242)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &MagicConn{recvAddrs: make(map[netip.AddrPort]*net.UDPAddr)}
			// Enough sightings to fill the cache several times over.
			for n := 1; n <= 3*maxRecvAddrs; n++ {
				ap := tc.at(n)
				if got := m.udpAddr(ap); got.AddrPort() != ap {
					t.Fatalf("udpAddr(%s) = %s", ap, got.AddrPort())
				}
				if len(m.recvAddrs) > maxRecvAddrs {
					t.Fatalf("cache holds %d addresses after %d sightings, want at most %d", len(m.recvAddrs), n, maxRecvAddrs)
				}
			}
		})
	}
}
