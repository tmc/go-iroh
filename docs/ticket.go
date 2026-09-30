package docs

import (
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const (
	// TicketKind is the string prefix for iroh-docs tickets.
	TicketKind = "doc"

	ticketWireVariant = 0
	capabilityWrite   = 0
	capabilityRead    = 1

	// maxTicketNodes bounds ticket node allocations. It is a DoS guard, not a
	// wire-compatibility limit.
	maxTicketNodes = endpointticket.MaxAddrs
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// DocTicket contains a document capability and bootstrap nodes.
type DocTicket struct {
	capability Capability
	nodes      []netaddr.EndpointAddr
}

// NewTicket returns a document ticket for capability and nodes.
func NewTicket(capability Capability, nodes []netaddr.EndpointAddr) DocTicket {
	return DocTicket{
		capability: capability,
		nodes:      append([]netaddr.EndpointAddr(nil), nodes...),
	}
}

// ParseTicket parses s as a document ticket.
func ParseTicket(s string) (DocTicket, error) { return DecodeString(s) }

// DecodeString parses s as a document ticket.
func DecodeString(s string) (DocTicket, error) {
	rest, ok := strings.CutPrefix(s, TicketKind)
	if !ok {
		return DocTicket{}, &endpointticket.ParseError{
			Kind:     endpointticket.ParseErrorKindKind,
			Expected: TicketKind,
		}
	}
	b, err := base32NoPad.DecodeString(strings.ToUpper(rest))
	if err != nil {
		return DocTicket{}, &endpointticket.ParseError{Kind: endpointticket.ParseErrorKindEncoding, Err: err}
	}
	return DecodeBytes(b)
}

// DecodeBytes decodes the postcard bytes of a document ticket.
func DecodeBytes(b []byte) (DocTicket, error) {
	p := parser{b: b}
	variant, err := p.varint()
	if err != nil {
		return DocTicket{}, wrapDecodeErr(err)
	}
	if variant != ticketWireVariant {
		return DocTicket{}, verifyErr(fmt.Sprintf("unsupported variant %d", variant), nil)
	}
	capability, err := p.capability()
	if err != nil {
		return DocTicket{}, err
	}
	n, err := p.varint()
	if err != nil {
		return DocTicket{}, wrapDecodeErr(err)
	}
	if n == 0 {
		return DocTicket{}, verifyErr("addressing info cannot be empty", nil)
	}
	if n > maxTicketNodes {
		return DocTicket{}, verifyErr(fmt.Sprintf("too many nodes %d", n), nil)
	}
	nodes := make([]netaddr.EndpointAddr, 0, n)
	for range n {
		addr, err := p.endpointAddr()
		if err != nil {
			return DocTicket{}, err
		}
		nodes = append(nodes, addr)
	}
	if !p.done() {
		return DocTicket{}, wrapDecodeErr(endpointticket.ErrTrailingBytes)
	}
	return NewTicket(capability, nodes), nil
}

// Register registers the document ticket decoder in r.
func Register(r *endpointticket.Registry) error {
	return r.Register(TicketKind, func(b []byte) (endpointticket.TicketCodec, error) {
		return DecodeBytes(b)
	})
}

// Capability returns the ticket's document capability.
func (t DocTicket) Capability() Capability { return t.capability }

// Nodes returns the ticket's bootstrap nodes.
func (t DocTicket) Nodes() []netaddr.EndpointAddr {
	return append([]netaddr.EndpointAddr(nil), t.nodes...)
}

// Short returns a ticket containing only endpoint ids and relay URLs.
func (t DocTicket) Short() DocTicket {
	nodes := make([]netaddr.EndpointAddr, len(t.nodes))
	for i, addr := range t.nodes {
		nodes[i] = endpointticket.ShortAddr(addr)
	}
	return NewTicket(t.capability, nodes)
}

// Kind returns the ticket kind prefix.
func (t DocTicket) Kind() string { return TicketKind }

// EncodeBytes returns the Rust-compatible postcard ticket payload.
func (t DocTicket) EncodeBytes() []byte {
	var b []byte
	b = appendVarint(b, ticketWireVariant)
	b = appendCapability(b, t.capability)
	b = appendVarint(b, uint64(len(t.nodes)))
	for _, addr := range t.nodes {
		encoded := endpointticket.New(addr).EncodeBytes()
		b = append(b, encoded[1:]...)
	}
	return b
}

// EncodeString returns the canonical ticket string.
func (t DocTicket) EncodeString() string {
	return TicketKind + strings.ToLower(base32NoPad.EncodeToString(t.EncodeBytes()))
}

// String returns the canonical ticket string.
func (t DocTicket) String() string { return t.EncodeString() }

// MarshalText implements encoding.TextMarshaler.
func (t DocTicket) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *DocTicket) UnmarshalText(text []byte) error {
	tt, err := ParseTicket(string(text))
	if err != nil {
		return err
	}
	*t = tt
	return nil
}

func appendCapability(b []byte, c Capability) []byte {
	switch c.Kind() {
	case CapabilityWrite:
		b = appendVarint(b, capabilityWrite)
		_, raw := c.Raw()
		return append(b, raw[:]...)
	case CapabilityRead:
		b = appendVarint(b, capabilityRead)
		_, raw := c.Raw()
		return append(b, raw[:]...)
	default:
		return appendVarint(b, 0xff)
	}
}

func appendVarint(b []byte, n uint64) []byte {
	for n >= 0x80 {
		b = append(b, byte(n)|0x80)
		n >>= 7
	}
	return append(b, byte(n))
}

func wrapDecodeErr(err error) error {
	if err == nil {
		return nil
	}
	return &endpointticket.ParseError{Kind: endpointticket.ParseErrorKindPostcard, Err: err}
}

func verifyErr(msg string, err error) error {
	return &endpointticket.ParseError{
		Kind:    endpointticket.ParseErrorKindVerify,
		Message: msg,
		Err:     err,
	}
}

type parser struct {
	b   []byte
	off int
}

func (p *parser) done() bool { return p.off == len(p.b) }

func (p *parser) bytes(n int) ([]byte, error) {
	if n < 0 || len(p.b)-p.off < n {
		return nil, endpointticket.ErrTruncated
	}
	out := p.b[p.off : p.off+n]
	p.off += n
	return out, nil
}

func (p *parser) varint() (uint64, error) {
	var x uint64
	var s uint
	for i := 0; ; i++ {
		if p.off >= len(p.b) {
			return 0, endpointticket.ErrTruncated
		}
		c := p.b[p.off]
		p.off++
		if c < 0x80 {
			if i > 9 || i == 9 && c > 1 {
				return 0, endpointticket.ErrVarintOverflow
			}
			return x | uint64(c)<<s, nil
		}
		x |= uint64(c&0x7f) << s
		s += 7
	}
}

func (p *parser) capability() (Capability, error) {
	kind, err := p.varint()
	if err != nil {
		return Capability{}, wrapDecodeErr(err)
	}
	raw, err := p.bytes(32)
	if err != nil {
		return Capability{}, wrapDecodeErr(err)
	}
	var b [32]byte
	copy(b[:], raw)
	switch kind {
	case capabilityWrite:
		return NewWriteCapability(NewNamespaceSecret(b)), nil
	case capabilityRead:
		id, err := NewNamespaceID(b)
		if err != nil {
			return Capability{}, verifyErr("namespace id", err)
		}
		return NewReadCapability(id), nil
	default:
		return Capability{}, verifyErr(fmt.Sprintf("unknown capability variant %d", kind), nil)
	}
}

func (p *parser) endpointAddr() (netaddr.EndpointAddr, error) {
	start := p.off
	if _, err := p.bytes(key.PublicKeySize); err != nil {
		return netaddr.EndpointAddr{}, wrapDecodeErr(err)
	}
	n, err := p.varint()
	if err != nil {
		return netaddr.EndpointAddr{}, wrapDecodeErr(err)
	}
	if n > maxTicketNodes {
		return netaddr.EndpointAddr{}, verifyErr(fmt.Sprintf("too many addresses %d", n), nil)
	}
	for range n {
		if err := p.skipTransportAddr(); err != nil {
			return netaddr.EndpointAddr{}, err
		}
	}
	payload := append([]byte{0}, p.b[start:p.off]...)
	t, err := endpointticket.DecodeBytes(payload)
	if err != nil {
		return netaddr.EndpointAddr{}, err
	}
	return t.Addr(), nil
}

func (p *parser) skipTransportAddr() error {
	kind, err := p.varint()
	if err != nil {
		return wrapDecodeErr(err)
	}
	switch kind {
	case 0:
		n, err := p.varint()
		if err != nil {
			return wrapDecodeErr(err)
		}
		_, err = p.bytes(int(n))
		return wrapDecodeErr(err)
	case 1:
		family, err := p.varint()
		if err != nil {
			return wrapDecodeErr(err)
		}
		switch family {
		case 0:
			if _, err := p.bytes(4); err != nil {
				return wrapDecodeErr(err)
			}
		case 1:
			if _, err := p.bytes(16); err != nil {
				return wrapDecodeErr(err)
			}
		default:
			return verifyErr(fmt.Sprintf("unknown ip address family %d", family), nil)
		}
		if _, err := p.varint(); err != nil { // port
			return wrapDecodeErr(err)
		}
		return nil
	case 2:
		if _, err := p.varint(); err != nil { // custom address id
			return wrapDecodeErr(err)
		}
		n, err := p.varint()
		if err != nil {
			return wrapDecodeErr(err)
		}
		_, err = p.bytes(int(n))
		return wrapDecodeErr(err)
	default:
		return verifyErr(fmt.Sprintf("unknown transport address kind %d", kind), nil)
	}
}
