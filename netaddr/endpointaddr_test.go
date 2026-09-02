package netaddr

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/key"
)

func TestCustomAddrRoundTrip(t *testing.T) {
	// Mirrors iroh-base/src/endpoint_addr.rs test_custom_addr_roundtrip.
	cases := []struct {
		id   uint64
		data []byte
		want string
	}{
		{1, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6}, "1_a1b2c3d4e5f6"},
		{42, bytesRepeat(0xab, 32), "2a_" + hexRepeat("ab", 32)},
		{0, []byte{}, "0_"},
		{0xdeadbeef, []byte{0x01, 0x02}, "deadbeef_0102"},
	}
	for _, c := range cases {
		a := NewCustomAddr(c.id, c.data)
		if got := a.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
		parsed, err := ParseCustomAddr(c.want)
		if err != nil {
			t.Fatalf("ParseCustomAddr(%q): %v", c.want, err)
		}
		if parsed.ID() != c.id || string(parsed.Data()) != string(c.data) {
			t.Errorf("parsed = (%d,%x), want (%d,%x)", parsed.ID(), parsed.Data(), c.id, c.data)
		}
		prefixed, err := ParseCustomAddr("custom:" + c.want)
		if err != nil {
			t.Fatalf("ParseCustomAddr(custom:%s): %v", c.want, err)
		}
		if prefixed.Compare(a) != 0 {
			t.Errorf("prefixed parse = %s, want %s", prefixed, a)
		}
	}
}

func TestCustomAddrParseErrors(t *testing.T) {
	// Mirrors test_custom_addr_parse_errors.
	for _, s := range []string{"abc123", "xyz_0102", "1_ghij", "1_abc"} {
		if _, err := ParseCustomAddr(s); err == nil {
			t.Errorf("ParseCustomAddr(%q): expected error", s)
		}
	}
	if _, err := ParseCustomAddr("abc123"); !errors.Is(err, ErrCustomAddrMissingSeparator) {
		t.Errorf("missing separator: got %v", err)
	}
}

func TestCustomAddrBinary(t *testing.T) {
	a := NewCustomAddr(0xdeadbeef, []byte{0x01, 0x02, 0x03})
	b, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// 8-byte LE id + data.
	if len(b) != 11 {
		t.Fatalf("len = %d, want 11", len(b))
	}
	var a2 CustomAddr
	if err := a2.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if a2.ID() != a.ID() || string(a2.Data()) != string(a.Data()) {
		t.Errorf("binary round-trip mismatch")
	}
	if err := a2.UnmarshalBinary([]byte{1, 2, 3}); !errors.Is(err, ErrCustomAddrTooShort) {
		t.Errorf("short bytes: got %v", err)
	}
	text, err := a.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var a3 CustomAddr
	if err := a3.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if a3.Compare(a) != 0 {
		t.Errorf("text round-trip mismatch")
	}
}

func TestRelayURLNormalization(t *testing.T) {
	// Rust url crate adds a trailing slash; we match that.
	u, err := ParseRelayURL("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "https://example.com/"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if got := u.Host(); got != "example.com" {
		t.Errorf("Host() = %q, want example.com", got)
	}
}

func TestRelayURLEqualCompare(t *testing.T) {
	a, _ := ParseRelayURL("https://a.example.com")
	b, _ := ParseRelayURL("https://b.example.com")
	a2, _ := ParseRelayURL("https://a.example.com/")
	if !a.Equal(a2) {
		t.Error("expected a == a2 after normalization")
	}
	if a.Compare(b) >= 0 {
		t.Error("expected a < b")
	}
}

func TestTransportAddrStringRoundTrip(t *testing.T) {
	relay, _ := ParseRelayURL("https://relay.example.com")
	ip := netip.MustParseAddrPort("127.0.0.1:9")
	cases := []TransportAddr{
		RelayAddr{URL: relay},
		IPAddr{Addr: ip},
		NewCustomAddr(7, []byte{0xde, 0xad}),
	}
	for _, addr := range cases {
		s := addr.String()
		parsed, err := ParseTransportAddr(s)
		if err != nil {
			t.Fatalf("ParseTransportAddr(%q): %v", s, err)
		}
		if parsed.String() != s {
			t.Errorf("round-trip: %q != %q", parsed.String(), s)
		}
	}
}

// TestCustomAddrStringPrefix pins the documented divergence: a CustomAddr
// renders without the "kind:" prefix its siblings carry, because that is the
// form on the DNS TXT wire, and both spellings parse back to the same address.
func TestCustomAddrStringPrefix(t *testing.T) {
	a := NewCustomAddr(7, []byte{0xde, 0xad})
	if got, want := a.String(), "7_dead"; got != want {
		t.Errorf("CustomAddr.String() = %q, want %q", got, want)
	}
	if got, want := a.Network(), "custom"; got != want {
		t.Errorf("CustomAddr.Network() = %q, want %q", got, want)
	}
	for _, s := range []string{"7_dead", "custom:7_dead"} {
		parsed, err := ParseTransportAddr(s)
		if err != nil {
			t.Fatalf("ParseTransportAddr(%q): %v", s, err)
		}
		if parsed.Compare(a) != 0 {
			t.Errorf("ParseTransportAddr(%q) = %v, want %v", s, parsed, a)
		}
	}
}

func TestTransportAddrNetAddr(t *testing.T) {
	var (
		_ net.Addr = RelayAddr{}
		_ net.Addr = IPAddr{}
		_ net.Addr = CustomAddr{}
	)

	relay, _ := ParseRelayURL("https://relay.example.com")
	cases := []struct {
		name string
		addr TransportAddr
		want string
	}{
		{"relay", RelayAddr{URL: relay}, "relay"},
		{"ip", IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:9")}, "ip"},
		{"custom", NewCustomAddr(7, []byte{0xde, 0xad}), "custom"},
	}
	for _, tt := range cases {
		if got := tt.addr.Network(); got != tt.want {
			t.Errorf("%s Network() = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestTransportAddrTextRoundTrip(t *testing.T) {
	relay, _ := ParseRelayURL("https://relay.example.com")
	relayAddr := RelayAddr{URL: relay}
	relayText, err := relayAddr.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(relayText) != relayAddr.String() {
		t.Fatalf("RelayAddr.MarshalText = %q, want %q", relayText, relayAddr.String())
	}
	var relayOut RelayAddr
	if err := relayOut.UnmarshalText(relayText); err != nil {
		t.Fatal(err)
	}
	if relayOut.Compare(relayAddr) != 0 {
		t.Fatalf("RelayAddr text round-trip = %s, want %s", relayOut, relayAddr)
	}
	if err := relayOut.UnmarshalText([]byte("ip:127.0.0.1:9")); err == nil {
		t.Fatal("RelayAddr.UnmarshalText accepted IPAddr")
	}

	ipAddr := IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:9")}
	ipText, err := ipAddr.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(ipText) != ipAddr.String() {
		t.Fatalf("IPAddr.MarshalText = %q, want %q", ipText, ipAddr.String())
	}
	var ipOut IPAddr
	if err := ipOut.UnmarshalText(ipText); err != nil {
		t.Fatal(err)
	}
	if ipOut.Compare(ipAddr) != 0 {
		t.Fatalf("IPAddr text round-trip = %s, want %s", ipOut, ipAddr)
	}
	if err := ipOut.UnmarshalText([]byte("relay:https://relay.example.com/")); err == nil {
		t.Fatal("IPAddr.UnmarshalText accepted RelayAddr")
	}
}

func TestEndpointAddrSortDedup(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	ip1 := netip.MustParseAddrPort("127.0.0.1:1")
	ip2 := netip.MustParseAddrPort("127.0.0.1:2")
	a := NewEndpointAddr(id).
		WithIP(ip2).
		WithIP(ip1).
		WithIP(ip1) // duplicate
	addrs := a.Addrs()
	if len(addrs) != 2 {
		t.Fatalf("len = %d, want 2 (deduped)", len(addrs))
	}
	// Sorted by compareKey: ip:127.0.0.1:1 < ip:127.0.0.1:2.
	if addrs[0].String() != "ip:127.0.0.1:1" || addrs[1].String() != "ip:127.0.0.1:2" {
		t.Errorf("not sorted: %v", []string{addrs[0].String(), addrs[1].String()})
	}
	if a.IsEmpty() {
		t.Error("should not be empty")
	}
	if got := a.IPAddrs(); len(got) != 2 {
		t.Errorf("IPAddrs len = %d, want 2", len(got))
	}
}

func TestTransportAddrOrderingMatchesRustOrd(t *testing.T) {
	// Rust derives Ord on the enum: variant order Relay < Ip < Custom, then by
	// inner value. IP addresses compare numerically (not lexically) and custom
	// ids compare as u64 (not by hex string). This is a regression test for the
	// string-compare ordering bug.
	relay, _ := ParseRelayURL("https://relay.example.com")
	ipLow := IPAddr{Addr: netip.MustParseAddrPort("2.0.0.1:9")}
	ipHigh := IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:9")}
	custLow := NewCustomAddr(0x2, nil)
	custHigh := NewCustomAddr(0x10, nil)
	relayAddr := RelayAddr{URL: relay}

	// Numeric IP ordering: 2.0.0.1 < 127.0.0.1 (lexical string would reverse).
	if ipLow.Compare(ipHigh) >= 0 {
		t.Error("expected 2.0.0.1 < 127.0.0.1 numerically")
	}
	// Numeric custom-id ordering: 0x2 < 0x10 (lexical "10_" < "2_" would reverse).
	if custLow.Compare(custHigh) >= 0 {
		t.Error("expected custom id 0x2 < 0x10 numerically")
	}
	// Variant order: relay < ip < custom.
	if relayAddr.Compare(ipLow) >= 0 {
		t.Error("expected relay < ip")
	}
	if ipHigh.Compare(custLow) >= 0 {
		t.Error("expected ip < custom")
	}

	// Full sort of a mixed set must come out in Rust Ord order.
	got := sortDedupAddrs([]TransportAddr{custHigh, ipHigh, custLow, ipLow, relayAddr})
	want := []TransportAddr{relayAddr, ipLow, ipHigh, custLow, custHigh}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Compare(want[i]) != 0 {
			t.Errorf("sorted[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}

func TestEndpointAddrEmpty(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	a := NewEndpointAddr(sk.Public().EndpointID())
	if !a.IsEmpty() {
		t.Error("expected empty")
	}
	if len(a.RelayURLs()) != 0 || len(a.IPAddrs()) != 0 {
		t.Error("expected no addrs")
	}
}

func TestEndpointAddrString(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	empty := NewEndpointAddr(id)
	if got, want := empty.String(), "EndpointAddr{id:"+id.String()+", addrs:[]}"; got != want {
		t.Fatalf("empty String = %q, want %q", got, want)
	}

	relay, _ := ParseRelayURL("https://relay.example/")
	addr := NewEndpointAddr(id,
		IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1")},
		RelayAddr{URL: relay},
	)
	want := "EndpointAddr{id:" + id.String() + ", addrs:[relay:https://relay.example/, ip:127.0.0.1:1]}"
	if got := addr.String(); got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
}

func TestEndpointAddrAddrsReturnsCopy(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	ip1 := IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1")}
	ip2 := IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:2")}
	a := NewEndpointAddr(sk.Public().EndpointID()).WithAddrs(ip1)
	addrs := a.Addrs()
	addrs[0] = ip2
	got := a.Addrs()
	if len(got) != 1 || got[0].Compare(ip1) != 0 {
		t.Fatalf("Addrs exposed internal slice: %v", got)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func hexRepeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}
