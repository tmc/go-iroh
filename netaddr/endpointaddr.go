package netaddr

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/tmc/go-iroh/key"
)

// TransportAddr is a network-level address at which an endpoint may be reached.
// It is one of [RelayAddr], [IPAddr], or [CustomAddr].
//
// The interface is closed: only the implementations in this package satisfy it.
type TransportAddr interface {
	// Network returns the transport kind: "relay", "ip", or "custom".
	Network() string
	// String renders the address for display and for the text encodings in
	// this module. [RelayAddr] and [IPAddr] use the "kind:value" form, e.g.
	// "ip:127.0.0.1:9"; [CustomAddr] omits the prefix and renders as
	// "<id>_<data>", matching upstream iroh's CustomAddr Display and the DNS
	// TXT encoding in [github.com/tmc/go-iroh/dns]. [ParseTransportAddr]
	// accepts every form String produces, so String round-trips.
	String() string
	// Compare returns -1, 0, or +1 ordering this address against other. The
	// order matches the Rust reference's derived Ord on the TransportAddr enum:
	// by kind first (relay < ip < custom), then by value (relay URLs by their
	// normalized string, IP addresses numerically, custom by id then data).
	Compare(other TransportAddr) int
	isTransportAddr()
}

// transportKind is the kind ordinal used as the primary ordering key, matching
// the Rust enum variant order: Relay(0) < Ip(1) < Custom(2).
func transportKind(a TransportAddr) int {
	switch a.(type) {
	case RelayAddr:
		return 0
	case IPAddr:
		return 1
	case CustomAddr:
		return 2
	default:
		return 3
	}
}

// RelayAddr is a [TransportAddr] reachable via a relay server.
type RelayAddr struct{ URL RelayURL }

// IPAddr is a [TransportAddr] reachable at an IP socket address.
type IPAddr struct{ Addr netip.AddrPort }

// CustomAddr is a custom transport address: a freely-chosen u64 transport id
// plus opaque, unvalidated address data.
//
// A registry of well-known transport ids is at
// https://github.com/n0-computer/iroh/blob/main/TRANSPORTS.md.
//
// CustomAddr mirrors upstream iroh's experimental custom-transport address
// surface, which upstream excludes from its stability guarantees. The Go API
// below follows this module's normal compatibility policy, but the
// endpoint-ticket wire encoding of a CustomAddr may change to track upstream
// without a major go-iroh version bump.
//
// String encoding ([CustomAddr.String], [ParseCustomAddr]): "<id>_<data>" where
// <id> is the transport ID as lowercase hex (no "0x", no leading zeros) and
// <data> is the address bytes as lowercase hex. Unlike [RelayAddr] and
// [IPAddr], a CustomAddr carries no "custom:" kind prefix; see
// [CustomAddr.String].
//
// Binary encoding ([CustomAddr.MarshalBinary], [CustomAddr.UnmarshalBinary]):
// 8-byte little-endian u64 ID followed by the raw data bytes (minimum 8 bytes).
type CustomAddr struct {
	id   uint64
	data []byte
}

func (RelayAddr) isTransportAddr()  {}
func (IPAddr) isTransportAddr()     {}
func (CustomAddr) isTransportAddr() {}

func (RelayAddr) Network() string  { return "relay" }
func (IPAddr) Network() string     { return "ip" }
func (CustomAddr) Network() string { return "custom" }

func (a RelayAddr) String() string { return "relay:" + a.URL.String() }
func (a IPAddr) String() string    { return "ip:" + a.Addr.String() }

// String returns the address as "<id>_<data>": the transport ID in lowercase
// hex followed by the address data in lowercase hex.
//
// It deliberately omits the "custom:" prefix that [RelayAddr] and [IPAddr]
// carry. This is the form upstream iroh's CustomAddr Display produces and the
// form written to DNS TXT records by [github.com/tmc/go-iroh/dns], so adding a
// prefix here would change a wire encoding. [ParseCustomAddr] and
// [ParseTransportAddr] accept the address with or without the prefix, so
// String still round-trips through either.
func (a CustomAddr) String() string { return a.customString() }

// MarshalText implements encoding.TextMarshaler using the string encoding
// described on [TransportAddr].
func (a RelayAddr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler using the string encoding
// described on [TransportAddr].
func (a *RelayAddr) UnmarshalText(text []byte) error {
	parsed, err := ParseTransportAddr(string(text))
	if err != nil {
		return err
	}
	relay, ok := parsed.(RelayAddr)
	if !ok {
		return fmt.Errorf("transport address %q: got %T, want RelayAddr", text, parsed)
	}
	*a = relay
	return nil
}

// MarshalText implements encoding.TextMarshaler using the string encoding
// described on [TransportAddr].
func (a IPAddr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler using the string encoding
// described on [TransportAddr].
func (a *IPAddr) UnmarshalText(text []byte) error {
	parsed, err := ParseTransportAddr(string(text))
	if err != nil {
		return err
	}
	ip, ok := parsed.(IPAddr)
	if !ok {
		return fmt.Errorf("transport address %q: got %T, want IPAddr", text, parsed)
	}
	*a = ip
	return nil
}

// Compare orders relay addresses by their normalized URL string.
func (a RelayAddr) Compare(other TransportAddr) int {
	if b, ok := other.(RelayAddr); ok {
		return a.URL.Compare(b.URL)
	}
	return cmp.Compare(transportKind(a), transportKind(other))
}

// Compare orders IP addresses numerically (by [netip.AddrPort.Compare]).
func (a IPAddr) Compare(other TransportAddr) int {
	if b, ok := other.(IPAddr); ok {
		return a.Addr.Compare(b.Addr)
	}
	return cmp.Compare(transportKind(a), transportKind(other))
}

// Compare orders custom addresses by numeric transport id, then by data bytes.
func (a CustomAddr) Compare(other TransportAddr) int {
	if b, ok := other.(CustomAddr); ok {
		if c := cmp.Compare(a.id, b.id); c != 0 {
			return c
		}
		return bytes.Compare(a.data, b.data)
	}
	return cmp.Compare(transportKind(a), transportKind(other))
}

// NewCustomAddr creates a CustomAddr from a transport ID and raw address data.
// The data is copied.
func NewCustomAddr(id uint64, data []byte) CustomAddr {
	return CustomAddr{id: id, data: slices.Clone(data)}
}

// ID returns the transport ID.
func (a CustomAddr) ID() uint64 { return a.id }

// Data returns the opaque address data.
func (a CustomAddr) Data() []byte { return slices.Clone(a.data) }

func (a CustomAddr) customString() string {
	return strconv.FormatUint(a.id, 16) + "_" + hex.EncodeToString(a.data)
}

// CustomAddr parse/encode errors.
var (
	ErrCustomAddrMissingSeparator = errors.New("missing '_' separator")
	ErrCustomAddrInvalidID        = errors.New("invalid ID")
	ErrCustomAddrInvalidData      = errors.New("invalid data")
	ErrCustomAddrTooShort         = errors.New("data too short")
)

// ParseCustomAddr parses a CustomAddr from its "<id>_<data>" string form.
// It also accepts the "custom:" prefix used by [ParseTransportAddr].
func ParseCustomAddr(s string) (CustomAddr, error) {
	s = strings.TrimPrefix(s, "custom:")
	idStr, dataStr, ok := strings.Cut(s, "_")
	if !ok {
		return CustomAddr{}, ErrCustomAddrMissingSeparator
	}
	id, err := strconv.ParseUint(idStr, 16, 64)
	if err != nil {
		return CustomAddr{}, ErrCustomAddrInvalidID
	}
	data, err := hex.DecodeString(dataStr)
	if err != nil {
		return CustomAddr{}, ErrCustomAddrInvalidData
	}
	return NewCustomAddr(id, data), nil
}

// MarshalText implements encoding.TextMarshaler using the string encoding
// described on [CustomAddr].
func (a CustomAddr) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler using the string encoding
// described on [CustomAddr].
func (a *CustomAddr) UnmarshalText(text []byte) error {
	parsed, err := ParseCustomAddr(string(text))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler using the binary encoding
// described on [CustomAddr].
func (a CustomAddr) MarshalBinary() ([]byte, error) {
	out := make([]byte, 8+len(a.data))
	binary.LittleEndian.PutUint64(out[:8], a.id)
	copy(out[8:], a.data)
	return out, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler using the binary
// encoding described on [CustomAddr].
func (a *CustomAddr) UnmarshalBinary(data []byte) error {
	if len(data) < 8 {
		return ErrCustomAddrTooShort
	}
	a.id = binary.LittleEndian.Uint64(data[:8])
	a.data = slices.Clone(data[8:])
	return nil
}

// ParseTransportAddr parses a TransportAddr from its "kind:value" string form.
func ParseTransportAddr(s string) (TransportAddr, error) {
	kind, value, ok := strings.Cut(s, ":")
	if !ok {
		return ParseCustomAddr(s)
	}
	switch kind {
	case "relay":
		u, err := ParseRelayURL(value)
		if err != nil {
			return nil, err
		}
		return RelayAddr{URL: u}, nil
	case "ip":
		ap, err := netip.ParseAddrPort(value)
		if err != nil {
			return nil, fmt.Errorf("transport address %q: %w", s, err)
		}
		return IPAddr{Addr: ap}, nil
	case "custom":
		return ParseCustomAddr(value)
	default:
		return nil, fmt.Errorf("transport address %q: unknown kind %q", s, kind)
	}
}

// EndpointAddr combines an endpoint's [key.EndpointID] with the network-level
// addresses at which it may be reached.
//
// To establish a connection both the key.EndpointID and at least one path (a relay
// URL or a direct IP address) are needed; an EndpointAddr with no addresses is
// still usable together with an address-lookup service.
type EndpointAddr struct {
	// ID is the endpoint's identifier.
	ID key.EndpointID
	// addrs is the sorted, deduplicated set of transport addresses.
	addrs []TransportAddr
}

// NewEndpointAddr creates an EndpointAddr with the given id and transport
// addresses. Addresses are deduplicated and sorted.
func NewEndpointAddr(id key.EndpointID, addrs ...TransportAddr) EndpointAddr {
	a := EndpointAddr{ID: id}
	return a.WithAddrs(addrs...)
}

// WithRelayURL returns a copy of a with the given relay URL added.
func (a EndpointAddr) WithRelayURL(u RelayURL) EndpointAddr {
	return a.WithAddrs(RelayAddr{URL: u})
}

// WithIP returns a copy of a with the given IP address added.
func (a EndpointAddr) WithIP(ap netip.AddrPort) EndpointAddr {
	return a.WithAddrs(IPAddr{Addr: ap})
}

// WithAddrs returns a copy of a with the given addresses added. The result's
// address set is sorted and deduplicated.
func (a EndpointAddr) WithAddrs(addrs ...TransportAddr) EndpointAddr {
	merged := append(slices.Clone(a.addrs), addrs...)
	merged = sortDedupAddrs(merged)
	return EndpointAddr{ID: a.ID, addrs: merged}
}

// Addrs returns the sorted, deduplicated transport addresses.
func (a EndpointAddr) Addrs() []TransportAddr { return slices.Clone(a.addrs) }

// IsEmpty reports whether only the key.EndpointID is present.
func (a EndpointAddr) IsEmpty() bool { return len(a.addrs) == 0 }

// String returns a diagnostic string for a.
func (a EndpointAddr) String() string {
	var b strings.Builder
	b.WriteString("EndpointAddr{id:")
	b.WriteString(a.ID.String())
	b.WriteString(", addrs:[")
	for i, addr := range a.addrs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(addr.String())
	}
	b.WriteString("]}")
	return b.String()
}

// IPAddrs returns the IP socket addresses of this endpoint.
func (a EndpointAddr) IPAddrs() []netip.AddrPort {
	var out []netip.AddrPort
	for _, addr := range a.addrs {
		if ip, ok := addr.(IPAddr); ok {
			out = append(out, ip.Addr)
		}
	}
	return out
}

// RelayURLs returns the relay URLs of this endpoint. In practice this is
// expected to be zero or one home relay.
func (a EndpointAddr) RelayURLs() []RelayURL {
	var out []RelayURL
	for _, addr := range a.addrs {
		if r, ok := addr.(RelayAddr); ok {
			out = append(out, r.URL)
		}
	}
	return out
}

func sortDedupAddrs(addrs []TransportAddr) []TransportAddr {
	slices.SortFunc(addrs, TransportAddr.Compare)
	return slices.CompactFunc(addrs, func(x, y TransportAddr) bool {
		return x.Compare(y) == 0
	})
}
