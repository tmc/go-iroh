package endpointticket

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestGolden(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("http://derp.me./")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id,
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1024")},
	)
	wantBytes, err := hex.DecodeString(
		"00" +
			"ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" +
			"02" +
			"00" +
			"10" +
			"687474703a2f2f646572702e6d652e2f" +
			"01" +
			"00" +
			"7f0000018008")
	if err != nil {
		t.Fatal(err)
	}
	want := Kind + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(wantBytes))
	if got := Encode(addr); got != want {
		t.Fatalf("Encode = %q, want %q", got, want)
	}
	got, err := Decode(want)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertEndpointAddrEqual(t, got, addr)
}

func TestRoundTripCustomAddr(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id,
		netaddr.NewCustomAddr(1, []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6}),
		netaddr.NewCustomAddr(42, bytesRepeat(0xab, 32)),
	)
	got, err := Decode(Encode(addr))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertEndpointAddrEqual(t, got, addr)
}

func TestIPv6WireFormat(t *testing.T) {
	var seed [key.SeedSize]byte
	for i := range seed {
		seed[i] = 0x2a
	}
	id := key.NewSecretKey(seed).Public().EndpointID()
	addr := netaddr.NewEndpointAddr(id, netaddr.IPAddr{Addr: netip.MustParseAddrPort("[2001:db8::1]:4433")})

	// This is the Rust-generated one-ipv6 vector from the compat harness.
	want, err := hex.DecodeString("00197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d6101010120010db8000000000000000000000001d122")
	if err != nil {
		t.Fatal(err)
	}
	if got := New(addr).EncodeBytes(); !bytes.Equal(got, want) {
		t.Fatalf("EncodeBytes = %x, want Rust bytes %x", got, want)
	}
	got, err := DecodeBytes(want)
	if err != nil {
		t.Fatalf("DecodeBytes(Rust vector): %v", err)
	}
	if gotAddr := got.Addr().IPAddrs(); len(gotAddr) != 1 || gotAddr[0].String() != "[2001:db8::1]:4433" {
		t.Fatalf("decoded IPv6 addresses = %v, want [[2001:db8::1]:4433]", gotAddr)
	}
}

func TestIPv6ZoneIsNotEncoded(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id, netaddr.IPAddr{Addr: netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("123456789"), 1024)})
	got, err := Decode(Encode(addr))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	gotAddr := got.IPAddrs()
	if len(gotAddr) != 1 || gotAddr[0].String() != "[fe80::1]:1024" {
		t.Fatalf("decoded IPv6 address = %v, want zone-free address [fe80::1]:1024", gotAddr)
	}
}

func TestRoundTripIPv4In6(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.AddrPortFrom(netip.MustParseAddr("::ffff:192.0.2.1"), 1024)
	addr := netaddr.NewEndpointAddr(id, netaddr.IPAddr{Addr: ip})
	got, err := Decode(Encode(addr))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertEndpointAddrEqual(t, got, addr)
}

func TestParseTicket(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id)
	ticket, err := Parse(Encode(addr))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertEndpointAddrEqual(t, ticket.Addr(), addr)
	if ticket.String() != Encode(addr) {
		t.Fatalf("Ticket.String = %q, want %q", ticket.String(), Encode(addr))
	}
}

func TestTicketCodec(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id, netaddr.RelayAddr{URL: relay})
	ticket := New(addr)
	var _ TicketCodec = ticket

	if got := ticket.Kind(); got != Kind {
		t.Fatalf("Kind = %q, want %q", got, Kind)
	}
	if got := EncodeString(ticket); got != ticket.String() {
		t.Fatalf("EncodeString = %q, want %q", got, ticket.String())
	}
	decoded, err := DecodeBytes(ticket.EncodeBytes())
	if err != nil {
		t.Fatalf("DecodeBytes: %v", err)
	}
	assertEndpointAddrEqual(t, decoded.Addr(), addr)
	decoded, err = DecodeString(ticket.EncodeString())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	assertEndpointAddrEqual(t, decoded.Addr(), addr)
}

func TestTicketJSONRoundTrip(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	ticket := New(netaddr.NewEndpointAddr(id, netaddr.RelayAddr{URL: relay}))
	in := struct {
		Ticket Ticket `json:"ticket"`
	}{Ticket: ticket}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(data) != `{"ticket":"`+ticket.String()+`"}` {
		t.Fatalf("Marshal = %s, want ticket string", data)
	}
	var out struct {
		Ticket Ticket `json:"ticket"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	assertEndpointAddrEqual(t, out.Ticket.Addr(), ticket.Addr())
}

func TestShortTicket(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id,
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:1024")},
		netaddr.NewCustomAddr(7, []byte("local")),
	)
	short := Short(addr).Addr()
	want := netaddr.NewEndpointAddr(id, netaddr.RelayAddr{URL: relay})
	assertEndpointAddrEqual(t, short, want)
	assertEndpointAddrEqual(t, New(addr).Short().Addr(), want)
}

func TestTicketRoundTripManyAddrs(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addrs := make([]netaddr.TransportAddr, 2000)
	for i := range addrs {
		addrs[i] = netaddr.IPAddr{Addr: netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(10000+i))}
	}
	addr := netaddr.NewEndpointAddr(id, addrs...)
	got, err := Decode(Encode(addr))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertEndpointAddrEqual(t, got, addr)
}

func TestStructuredParseErrors(t *testing.T) {
	if _, err := DecodeString("nodeabc"); !errors.Is(err, ErrMissingPrefix) {
		t.Fatalf("DecodeString missing prefix error = %v, want %v", err, ErrMissingPrefix)
	}
	if _, err := DecodeString(Kind + "!"); !errors.Is(err, ErrEncoding) {
		t.Fatalf("DecodeString encoding error = %v, want %v", err, ErrEncoding)
	}
	if _, err := DecodeString(Kind + "aa"); !errors.Is(err, ErrDecode) {
		t.Fatalf("DecodeString decode error = %v, want %v", err, ErrDecode)
	}
}

func TestRegistry(t *testing.T) {
	id, err := key.ParseEndpointID("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")
	if err != nil {
		t.Fatal(err)
	}
	addr := netaddr.NewEndpointAddr(id)
	ticket := New(addr)

	r := NewRegistry()
	if err := RegisterEndpoint(r); err != nil {
		t.Fatal(err)
	}
	got, err := r.DecodeString(ticket.String())
	if err != nil {
		t.Fatalf("Registry.DecodeString: %v", err)
	}
	endpoint, ok := got.(Ticket)
	if !ok {
		t.Fatalf("Registry.DecodeString returned %T, want Ticket", got)
	}
	assertEndpointAddrEqual(t, endpoint.Addr(), addr)

	got, err = r.DecodeBytes(Kind, ticket.EncodeBytes())
	if err != nil {
		t.Fatalf("Registry.DecodeBytes: %v", err)
	}
	endpoint, ok = got.(Ticket)
	if !ok {
		t.Fatalf("Registry.DecodeBytes returned %T, want Ticket", got)
	}
	assertEndpointAddrEqual(t, endpoint.Addr(), addr)
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	if err := RegisterEndpoint(r); err != nil {
		t.Fatal(err)
	}
	if err := RegisterEndpoint(r); err == nil {
		t.Fatal("RegisterEndpoint duplicate succeeded")
	}
}

func TestRegistryRejectsInvalidSource(t *testing.T) {
	r := NewRegistry()
	if err := r.Register("", func([]byte) (TicketCodec, error) { return Ticket{}, nil }); err == nil {
		t.Fatal("Register accepted empty kind")
	}
	if err := r.Register("endpoint", nil); err == nil {
		t.Fatal("Register accepted nil decoder")
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{name: "missing prefix", in: "nodeabc", want: ErrMissingPrefix},
		{name: "truncated", in: Kind + "aa", want: ErrTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("Decode error = %v, want %v", err, tt.want)
			}
		})
	}
}

func assertEndpointAddrEqual(t *testing.T, got, want netaddr.EndpointAddr) {
	t.Helper()
	if !got.ID.Equal(want.ID) {
		t.Fatalf("id = %s, want %s", got.ID, want.ID)
	}
	gotAddrs := got.Addrs()
	wantAddrs := want.Addrs()
	if len(gotAddrs) != len(wantAddrs) {
		t.Fatalf("addrs = %v, want %v", gotAddrs, wantAddrs)
	}
	for i := range gotAddrs {
		if gotAddrs[i].Compare(wantAddrs[i]) != 0 {
			t.Fatalf("addr[%d] = %v, want %v", i, gotAddrs[i], wantAddrs[i])
		}
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
