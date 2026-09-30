package endpointticket

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const (
	// Kind is the string prefix for endpoint tickets.
	Kind         = "endpoint"
	wireVariant1 = 0

	// MaxAddrs is the maximum number of addresses accepted in a ticket.
	// It is a memory-exhaustion guard, not a wire-compatibility limit.
	MaxAddrs = 65536
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

var (
	// ErrTrailingBytes is returned when a ticket has extra data after the
	// endpoint address.
	ErrTrailingBytes = errors.New("endpoint ticket: trailing bytes")
	// ErrTruncated is returned when a ticket ends before a complete field.
	ErrTruncated = errors.New("endpoint ticket: truncated")
	// ErrVarintOverflow is returned when a varint field exceeds 64 bits.
	ErrVarintOverflow = errors.New("endpoint ticket: varint overflow")
)

// TicketCodec is the generic shape of an iroh ticket implementation.
//
// It mirrors Rust's iroh_tickets::Ticket trait: a ticket has a lowercase kind
// prefix, a byte representation, and a canonical string form of kind plus
// base32-without-padding bytes.
type TicketCodec interface {
	Kind() string
	EncodeBytes() []byte
	EncodeString() string
}

// Decoder decodes a ticket from its byte representation.
type Decoder func([]byte) (TicketCodec, error)

// Registry decodes tickets by kind.
type Registry struct {
	mu       sync.RWMutex
	decoders map[string]Decoder
}

// NewRegistry returns an empty ticket decoder registry.
func NewRegistry() *Registry {
	return &Registry{decoders: make(map[string]Decoder)}
}

// Register adds decoder for kind. Kind must be non-empty and unique.
func (r *Registry) Register(kind string, decoder Decoder) error {
	if r == nil {
		return errors.New("endpoint ticket: nil registry")
	}
	if kind == "" {
		return errors.New("endpoint ticket: empty kind")
	}
	if decoder == nil {
		return errors.New("endpoint ticket: nil decoder")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.decoders == nil {
		r.decoders = make(map[string]Decoder)
	}
	if _, ok := r.decoders[kind]; ok {
		return fmt.Errorf("endpoint ticket: duplicate kind %q", kind)
	}
	r.decoders[kind] = decoder
	return nil
}

// DecodeBytes decodes bytes as a ticket of kind.
func (r *Registry) DecodeBytes(kind string, b []byte) (TicketCodec, error) {
	if r == nil {
		return nil, errors.New("endpoint ticket: nil registry")
	}
	r.mu.RLock()
	decoder := r.decoders[kind]
	r.mu.RUnlock()
	if decoder == nil {
		return nil, &ParseError{Kind: ParseErrorKindKind, Expected: kind}
	}
	return decoder(b)
}

// DecodeString decodes s using the registered kind prefix.
func (r *Registry) DecodeString(s string) (TicketCodec, error) {
	if r == nil {
		return nil, errors.New("endpoint ticket: nil registry")
	}
	r.mu.RLock()
	var kind string
	var decoder Decoder
	for k, d := range r.decoders {
		if strings.HasPrefix(s, k) && len(k) > len(kind) {
			kind, decoder = k, d
		}
	}
	r.mu.RUnlock()
	if decoder == nil {
		return nil, &ParseError{Kind: ParseErrorKindKind}
	}
	rest := s[len(kind):]
	b, err := base32NoPad.DecodeString(strings.ToUpper(rest))
	if err != nil {
		return nil, &ParseError{Kind: ParseErrorKindEncoding, Err: err}
	}
	return decoder(b)
}

// RegisterEndpoint registers the endpoint ticket decoder in r.
func RegisterEndpoint(r *Registry) error {
	return r.Register(Kind, func(b []byte) (TicketCodec, error) {
		return DecodeBytes(b)
	})
}

// ParseErrorKind classifies ticket parse failures.
type ParseErrorKind string

const (
	// ParseErrorKindKind means the ticket string had the wrong kind prefix.
	ParseErrorKindKind ParseErrorKind = "kind"
	// ParseErrorKindEncoding means the ticket payload was not valid base32.
	ParseErrorKindEncoding ParseErrorKind = "encoding"
	// ParseErrorKindPostcard means the payload looked like this ticket kind but
	// did not decode as the ticket byte format.
	ParseErrorKindPostcard ParseErrorKind = "postcard"
	// ParseErrorKindVerify means decoded bytes failed semantic validation.
	ParseErrorKindVerify ParseErrorKind = "verify"
)

// ParseError reports a structured ticket parse failure.
type ParseError struct {
	Kind     ParseErrorKind
	Expected string
	Message  string
	Err      error
}

func (e *ParseError) Error() string {
	switch e.Kind {
	case ParseErrorKindKind:
		return fmt.Sprintf("endpoint ticket: wrong prefix, expected %s", e.Expected)
	case ParseErrorKindEncoding:
		if e.Err != nil {
			return "endpoint ticket: decode base32: " + e.Err.Error()
		}
		return "endpoint ticket: decode base32"
	case ParseErrorKindVerify:
		return "endpoint ticket: verification failed: " + e.Message
	default:
		if e.Err != nil {
			return "endpoint ticket: decode: " + e.Err.Error()
		}
		return "endpoint ticket: decode"
	}
}

func (e *ParseError) Unwrap() error { return e.Err }

func (e *ParseError) Is(target error) bool {
	t, ok := target.(*ParseError)
	if !ok {
		return false
	}
	return t.Kind == "" || e.Kind == t.Kind
}

var (
	// ErrMissingPrefix is returned when a ticket does not start with
	// "endpoint".
	ErrMissingPrefix = &ParseError{Kind: ParseErrorKindKind, Expected: Kind}
	// ErrEncoding is returned when the ticket payload is not valid base32.
	ErrEncoding = &ParseError{Kind: ParseErrorKindEncoding}
	// ErrDecode is returned when the decoded bytes are not a valid endpoint
	// ticket payload.
	ErrDecode = &ParseError{Kind: ParseErrorKindPostcard}
	// ErrVerify is returned when decoded bytes fail semantic validation.
	ErrVerify = &ParseError{Kind: ParseErrorKindVerify}
)

// Ticket is an endpoint ticket.
type Ticket struct {
	addr netaddr.EndpointAddr
}

// New returns a ticket for addr.
func New(addr netaddr.EndpointAddr) Ticket {
	return Ticket{addr: addr}
}

// Encode returns the ticket string for addr.
func Encode(addr netaddr.EndpointAddr) string {
	return New(addr).String()
}

// EncodeString returns t's canonical string form.
func EncodeString(t TicketCodec) string {
	return t.EncodeString()
}

// Parse parses s as an endpoint ticket.
func Parse(s string) (Ticket, error) {
	addr, err := Decode(s)
	if err != nil {
		return Ticket{}, err
	}
	return New(addr), nil
}

// Decode parses s as an endpoint ticket and returns its endpoint address.
func Decode(s string) (netaddr.EndpointAddr, error) {
	t, err := DecodeString(s)
	if err != nil {
		return netaddr.EndpointAddr{}, err
	}
	return t.Addr(), nil
}

// DecodeString parses s as an endpoint ticket.
func DecodeString(s string) (Ticket, error) {
	rest, ok := strings.CutPrefix(s, Kind)
	if !ok {
		return Ticket{}, ErrMissingPrefix
	}
	b, err := base32NoPad.DecodeString(strings.ToUpper(rest))
	if err != nil {
		return Ticket{}, &ParseError{Kind: ParseErrorKindEncoding, Err: err}
	}
	return DecodeBytes(b)
}

// DecodeBytes decodes an endpoint ticket from its byte representation.
func DecodeBytes(b []byte) (Ticket, error) {
	p := parser{b: b}
	variant, err := p.varint()
	if err != nil {
		return Ticket{}, wrapDecodeErr(err)
	}
	if variant != wireVariant1 {
		return Ticket{}, &ParseError{Kind: ParseErrorKindVerify, Message: fmt.Sprintf("unsupported variant %d", variant)}
	}
	idBytes, err := p.bytes(key.PublicKeySize)
	if err != nil {
		return Ticket{}, wrapDecodeErr(err)
	}
	id, err := key.EndpointIDFromSlice(idBytes)
	if err != nil {
		return Ticket{}, &ParseError{Kind: ParseErrorKindVerify, Message: "endpoint id", Err: err}
	}
	n, err := p.varint()
	if err != nil {
		return Ticket{}, wrapDecodeErr(err)
	}
	if n > MaxAddrs {
		return Ticket{}, &ParseError{Kind: ParseErrorKindVerify, Message: fmt.Sprintf("too many addresses %d", n)}
	}
	addrs := make([]netaddr.TransportAddr, 0, n)
	for range n {
		a, err := p.transportAddr()
		if err != nil {
			return Ticket{}, wrapDecodeErr(err)
		}
		addrs = append(addrs, a)
	}
	if !p.done() {
		return Ticket{}, wrapDecodeErr(ErrTrailingBytes)
	}
	return New(netaddr.NewEndpointAddr(id, addrs...)), nil
}

// Addr returns the endpoint address in t.
func (t Ticket) Addr() netaddr.EndpointAddr {
	return t.addr
}

// Kind returns the ticket kind prefix.
func (t Ticket) Kind() string { return Kind }

// EncodeBytes returns the ticket's byte representation.
func (t Ticket) EncodeBytes() []byte {
	var b []byte
	b = appendVarint(b, wireVariant1)
	id := t.addr.ID.Bytes()
	b = append(b, id[:]...)
	addrs := t.addr.Addrs()
	b = appendVarint(b, uint64(len(addrs)))
	for _, a := range addrs {
		b = appendTransportAddr(b, a)
	}
	return b
}

// EncodeString returns the encoded ticket string.
func (t Ticket) EncodeString() string {
	return Kind + strings.ToLower(base32NoPad.EncodeToString(t.EncodeBytes()))
}

// String returns the encoded ticket string.
func (t Ticket) String() string {
	return t.EncodeString()
}

// MarshalText implements encoding.TextMarshaler.
func (t Ticket) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *Ticket) UnmarshalText(text []byte) error {
	tt, err := Parse(string(text))
	if err != nil {
		return err
	}
	*t = tt
	return nil
}

// Short returns a ticket containing only the endpoint id and relay URLs.
func (t Ticket) Short() Ticket {
	return New(ShortAddr(t.addr))
}

// Short returns a ticket for addr containing only the endpoint id and relay
// URLs.
func Short(addr netaddr.EndpointAddr) Ticket {
	return New(ShortAddr(addr))
}

// ShortAddr returns addr with direct IP and custom addresses removed.
func ShortAddr(addr netaddr.EndpointAddr) netaddr.EndpointAddr {
	var addrs []netaddr.TransportAddr
	for _, a := range addr.Addrs() {
		if _, ok := a.(netaddr.RelayAddr); ok {
			addrs = append(addrs, a)
		}
	}
	return netaddr.NewEndpointAddr(addr.ID, addrs...)
}

func wrapDecodeErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrTrailingBytes) || errors.Is(err, ErrTruncated) || errors.Is(err, ErrVarintOverflow) {
		return &ParseError{Kind: ParseErrorKindPostcard, Err: err}
	}
	return err
}

func appendTransportAddr(b []byte, a netaddr.TransportAddr) []byte {
	switch a := a.(type) {
	case netaddr.RelayAddr:
		b = appendVarint(b, 0)
		s := []byte(a.URL.String())
		b = appendVarint(b, uint64(len(s)))
		return append(b, s...)
	case netaddr.IPAddr:
		b = appendVarint(b, 1)
		ap := a.Addr
		if ap.Addr().Is4() {
			ip4 := ap.Addr().As4()
			b = appendVarint(b, 0)
			b = append(b, ip4[:]...)
		} else {
			ip6 := ap.Addr().As16()
			b = appendVarint(b, 1)
			b = append(b, ip6[:]...)
		}
		b = appendVarint(b, uint64(ap.Port()))
		return b
	case netaddr.CustomAddr:
		b = appendVarint(b, 2)
		b = appendVarint(b, a.ID())
		data := a.Data()
		b = appendVarint(b, uint64(len(data)))
		return append(b, data...)
	default:
		panic("unreachable transport address")
	}
}

func appendVarint(b []byte, n uint64) []byte {
	for n >= 0x80 {
		b = append(b, byte(n)|0x80)
		n >>= 7
	}
	return append(b, byte(n))
}

type parser struct {
	b   []byte
	off int
}

func (p *parser) done() bool { return p.off == len(p.b) }

func (p *parser) bytes(n int) ([]byte, error) {
	if n < 0 || len(p.b)-p.off < n {
		return nil, ErrTruncated
	}
	out := p.b[p.off : p.off+n]
	p.off += n
	return out, nil
}

func (p *parser) varint() (uint64, error) {
	var n uint64
	for shift := uint(0); shift < 64; shift += 7 {
		b, err := p.bytes(1)
		if err != nil {
			return 0, err
		}
		n |= uint64(b[0]&0x7f) << shift
		if b[0]&0x80 == 0 {
			return n, nil
		}
	}
	return 0, ErrVarintOverflow
}

func (p *parser) transportAddr() (netaddr.TransportAddr, error) {
	kind, err := p.varint()
	if err != nil {
		return nil, err
	}
	switch kind {
	case 0:
		n, err := p.varint()
		if err != nil {
			return nil, err
		}
		s, err := p.bytes(int(n))
		if err != nil {
			return nil, err
		}
		u, err := netaddr.ParseRelayURL(string(s))
		if err != nil {
			return nil, err
		}
		return netaddr.RelayAddr{URL: u}, nil
	case 1:
		family, err := p.varint()
		if err != nil {
			return nil, err
		}
		var ip netip.Addr
		switch family {
		case 0:
			b, err := p.bytes(4)
			if err != nil {
				return nil, err
			}
			ip = netip.AddrFrom4([4]byte(b))
		case 1:
			b, err := p.bytes(16)
			if err != nil {
				return nil, err
			}
			ip = netip.AddrFrom16([16]byte(b))
		default:
			return nil, fmt.Errorf("endpoint ticket: unsupported IP family %d", family)
		}
		port, err := p.varint()
		if err != nil {
			return nil, err
		}
		if port > 65535 {
			return nil, fmt.Errorf("endpoint ticket: invalid port %d", port)
		}
		return netaddr.IPAddr{Addr: netip.AddrPortFrom(ip, uint16(port))}, nil
	case 2:
		id, err := p.varint()
		if err != nil {
			return nil, err
		}
		n, err := p.varint()
		if err != nil {
			return nil, err
		}
		data, err := p.bytes(int(n))
		if err != nil {
			return nil, err
		}
		return netaddr.NewCustomAddr(id, slices.Clone(data)), nil
	default:
		return nil, fmt.Errorf("endpoint ticket: unsupported transport kind %d", kind)
	}
}
