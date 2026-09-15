package vectors

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/pkarr"
	"github.com/tmc/go-iroh/postcard"
)

//go:embed corpus.json
var corpusJSON []byte

//go:embed legacy_custom_addr.json
var legacyCustomAddrJSON []byte

type corpus struct {
	Schema         string               `json:"schema"`
	Iroh           string               `json:"iroh"`
	Keys           []keyVector          `json:"keys"`
	PostcardUint   []uintVector         `json:"postcard_uint"`
	PostcardU8     []u8Vector           `json:"postcard_u8"`
	PostcardI8     []i8Vector           `json:"postcard_i8"`
	NonCanonical   []nonCanonicalVector `json:"postcard_non_canonical"`
	EndpointTicket struct {
		Encoded string `json:"encoded"`
		Bytes   string `json:"bytes"`
	} `json:"endpoint_ticket"`
	CustomAddrTickets []customAddrTicketVector `json:"custom_addr_tickets"`
	Pkarr             struct {
		Bytes  string   `json:"bytes"`
		Name   string   `json:"name"`
		Values []string `json:"values"`
		TTL    uint32   `json:"ttl"`
	} `json:"pkarr"`
}

type keyVector struct {
	Seed      string `json:"seed"`
	Public    string `json:"public"`
	Z32       string `json:"z32"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type uintVector struct {
	Value    uint64 `json:"value"`
	Postcard string `json:"postcard"`
}

type u8Vector struct {
	Value    uint8  `json:"value"`
	Postcard string `json:"postcard"`
}

type i8Vector struct {
	Value    int8   `json:"value"`
	Postcard string `json:"postcard"`
}

type nonCanonicalVector struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Hex          string `json:"hex"`
	CanonicalHex string `json:"canonical_hex"`
	RustAccepted bool   `json:"rust_accepted"`
}

type customAddrTicketVector struct {
	Length  int    `json:"length"`
	Encoded string `json:"encoded"`
	Bytes   string `json:"bytes"`
}

func load(t *testing.T) corpus {
	t.Helper()
	var c corpus
	if err := json.Unmarshal(corpusJSON, &c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != "go-iroh-l0/2" || c.Iroh != "1.2.0" {
		t.Fatalf("corpus identity = %q, %q", c.Schema, c.Iroh)
	}
	return c
}

func TestKeyVectors(t *testing.T) {
	for _, v := range load(t).Keys {
		t.Run(v.Seed[:8], func(t *testing.T) {
			seed := mustHex(t, v.Seed)
			sk, err := key.SecretKeyFromSlice(seed)
			if err != nil {
				t.Fatal(err)
			}
			if got := sk.Public().String(); got != v.Public {
				t.Fatalf("public = %s, want %s", got, v.Public)
			}
			if got := sk.Public().EndpointID().Z32(); got != v.Z32 {
				t.Fatalf("z32 = %s, want %s", got, v.Z32)
			}
			if got := sk.Sign([]byte(v.Message)).String(); got != v.Signature {
				t.Fatalf("signature = %s, want %s", got, v.Signature)
			}
		})
	}
}

func TestPostcardUintVectors(t *testing.T) {
	for _, v := range load(t).PostcardUint {
		got, err := postcard.Marshal(v.Value)
		if err != nil {
			t.Fatal(err)
		}
		_, got = mutate("postcard-varint", "", got)
		if want := mustHex(t, v.Postcard); !slices.Equal(got, want) {
			t.Errorf("postcard(%d) = %x, want %x", v.Value, got, want)
		}
	}
}

// TestPostcard8BitVectors pins the 8-bit encodings, which postcard writes as a
// single raw byte rather than as a varint: u8 verbatim and i8 in two's
// complement. Values below 128 encode identically either way, so they are the
// boundary that makes the raw encoding safe for records signed before it, and
// the vectors carry them for that reason.
func TestPostcard8BitVectors(t *testing.T) {
	c := load(t)
	if len(c.PostcardU8) != 6 || len(c.PostcardI8) != 5 {
		t.Fatalf("8-bit vector counts = %d, %d, want 6, 5", len(c.PostcardU8), len(c.PostcardI8))
	}
	for _, v := range c.PostcardU8 {
		got, err := postcard.Marshal(v.Value)
		if err != nil {
			t.Fatal(err)
		}
		_, got = mutate("postcard-8bit", "", got)
		if want := mustHex(t, v.Postcard); !slices.Equal(got, want) {
			t.Errorf("postcard(uint8(%d)) = %x, want %x", v.Value, got, want)
		}
	}
	for _, v := range c.PostcardI8 {
		got, err := postcard.Marshal(v.Value)
		if err != nil {
			t.Fatal(err)
		}
		_, got = mutate("postcard-8bit", "", got)
		if want := mustHex(t, v.Postcard); !slices.Equal(got, want) {
			t.Errorf("postcard(int8(%d)) = %x, want %x", v.Value, got, want)
		}
	}
}

func TestEndpointTicketVector(t *testing.T) {
	v := load(t).EndpointTicket
	encoded, _ := mutate("ticket-prefix", v.Encoded, nil)
	ticket, err := endpointticket.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ticket.EncodeBytes(), mustHex(t, v.Bytes); !slices.Equal(got, want) {
		t.Fatalf("ticket bytes = %x, want %x", got, want)
	}
	if got := ticket.String(); got != v.Encoded {
		t.Fatalf("ticket re-encode = %s, want %s", got, v.Encoded)
	}
}

// TestCustomAddrTicketVectors checks that the CustomAddr endpoint tickets the
// Rust driver emits at iroh 1.2.0 both decode in go-iroh and re-encode to the
// same bytes Go produces for the same address. At iroh 1.0.3 neither held; see
// TestLegacyCustomAddrTicketsStillRejected for the encoding that replaced.
func TestCustomAddrTicketVectors(t *testing.T) {
	wantLengths := []int{0, 1, 29, 30, 31, 255}
	vectors := load(t).CustomAddrTickets
	if len(vectors) != len(wantLengths) {
		t.Fatalf("custom ticket count = %d, want %d", len(vectors), len(wantLengths))
	}
	for i, v := range vectors {
		if v.Length != wantLengths[i] {
			t.Fatalf("vector %d length = %d, want %d", i, v.Length, wantLengths[i])
		}
		ticket, err := endpointticket.Parse(v.Encoded)
		if err != nil {
			t.Errorf("CustomAddr ticket length %d: %v", v.Length, err)
			continue
		}
		want := mustHex(t, v.Bytes)
		if got := ticket.EncodeBytes(); !slices.Equal(got, want) {
			t.Errorf("CustomAddr ticket length %d bytes = %x, want %x", v.Length, got, want)
		}
		if got := customAddrTicket(t, v.Length); !slices.Equal(got.EncodeBytes(), want) {
			t.Errorf("Go CustomAddr ticket length %d = %x, want %x", v.Length, got.EncodeBytes(), want)
		}
	}
}

// TestLegacyCustomAddrTicketsStillRejected is the null control for the test
// above. The iroh 1.0.3 CustomAddr encoding is frozen in
// legacy_custom_addr.json, and go-iroh must keep rejecting it. If both the
// 1.0.3 and the 1.2.0 vectors decoded, the acceptance check would be measuring
// nothing about the version change.
func TestLegacyCustomAddrTicketsStillRejected(t *testing.T) {
	var legacy struct {
		Iroh    string                   `json:"iroh"`
		Tickets []customAddrTicketVector `json:"custom_addr_tickets"`
	}
	if err := json.Unmarshal(legacyCustomAddrJSON, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Iroh != "1.0.3" || len(legacy.Tickets) != 6 {
		t.Fatalf("legacy fixture identity = %q, %d tickets", legacy.Iroh, len(legacy.Tickets))
	}
	for _, v := range legacy.Tickets {
		if _, err := endpointticket.Parse(v.Encoded); err == nil {
			t.Errorf("iroh 1.0.3 CustomAddr ticket length %d unexpectedly decoded", v.Length)
		}
		if got := customAddrTicket(t, v.Length); slices.Equal(got.EncodeBytes(), mustHex(t, v.Bytes)) {
			t.Errorf("iroh 1.0.3 and Go CustomAddr ticket length %d unexpectedly matched", v.Length)
		}
	}
}

// customAddrTicket builds the ticket the corpus driver encodes for a CustomAddr
// of the given length: seed 0x2a repeated, address type 42, payload 0,1,2,....
func customAddrTicket(t *testing.T, length int) endpointticket.Ticket {
	t.Helper()
	var seed [key.SeedSize]byte
	for i := range seed {
		seed[i] = 0x2a
	}
	id := key.NewSecretKey(seed).Public().EndpointID()
	data := make([]byte, length)
	for i := range data {
		data[i] = byte(i)
	}
	return endpointticket.New(netaddr.NewEndpointAddr(id, netaddr.NewCustomAddr(42, data)))
}

// TestPostcardVarintStrictness pins a measured divergence rather than a
// parity claim: go-iroh rejects padded varint encodings that postcard 1.1.3
// accepts, so it is strictly stricter than upstream. Upstream's serializer
// emits only canonical forms, so this affects no upstream-generated traffic.
//
// The corpus records what Rust actually did with each byte string. If a future
// postcard adds a canonicality check, rust_accepted flips and this test fails,
// which is the point: the divergence should not change unnoticed.
func TestPostcardVarintStrictness(t *testing.T) {
	vectors := load(t).NonCanonical
	if len(vectors) == 0 {
		t.Fatal("corpus has no postcard_non_canonical vectors")
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			if !v.RustAccepted {
				t.Errorf("corpus records Rust rejecting %s; upstream converged and the divergence needs re-recording", v.Hex)
			}
			if err := unmarshalAs(v.Type, mustHex(t, v.Hex)); err == nil {
				t.Errorf("Go accepted non-canonical %s", v.Hex)
			}
			if err := unmarshalAs(v.Type, mustHex(t, v.CanonicalHex)); err != nil {
				t.Errorf("Go rejected canonical %s: %v", v.CanonicalHex, err)
			}
		})
	}
}

func unmarshalAs(kind string, data []byte) error {
	switch kind {
	case "u64":
		var v uint64
		return postcard.Unmarshal(data, &v)
	case "bytes":
		var v []byte
		return postcard.Unmarshal(data, &v)
	default:
		return fmt.Errorf("unknown vector type %q", kind)
	}
}

func TestPkarrVector(t *testing.T) {
	v := load(t).Pkarr
	_, packetBytes := mutate("pkarr-signer", "", mustHex(t, v.Bytes))
	packet, err := pkarr.FromBytes(packetBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := packet.TxtRecords(v.Name); !slices.Equal(got, v.Values) {
		t.Fatalf("TXT records = %q, want %q", got, v.Values)
	}
}

func TestTamperedTicketRejected(t *testing.T) {
	s := load(t).EndpointTicket.Encoded
	if _, err := endpointticket.Parse(s[:len(s)-1]); err == nil {
		t.Fatal("tampered ticket was accepted")
	}
}

func TestBadPkarrSignatureRejected(t *testing.T) {
	b := mustHex(t, load(t).Pkarr.Bytes)
	b[32] ^= 1
	if _, err := pkarr.FromBytes(b); err == nil {
		t.Fatal("bad pkarr signature was accepted")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
