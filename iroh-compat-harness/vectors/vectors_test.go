package vectors

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"slices"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/pkarr"
	"github.com/tmc/go-iroh/postcard"
)

//go:embed corpus/*.json
var corpora embed.FS

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
	IPTickets         []ipTicketVector         `json:"ip_tickets"`
	Bao               []baoVector              `json:"bao"`
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

type ipTicketVector struct {
	Name    string   `json:"name"`
	Addrs   []string `json:"addrs"`
	Relay   string   `json:"relay"`
	Encoded string   `json:"encoded"`
	Bytes   string   `json:"bytes"`
}

type baoVector struct {
	Size    uint64   `json:"size"`
	Name    string   `json:"name"`
	Ranges  []uint64 `json:"ranges"`
	Hash    string   `json:"hash"`
	Encoded string   `json:"encoded"`
}

// eachCorpus runs f as a subtest against the corpus of every pinned upstream
// release. The runner reports a release's vector cells as passing only when
// its driver reproduces a corpus these tests verified.
func eachCorpus(t *testing.T, f func(*testing.T, corpus)) {
	t.Helper()
	paths, err := fs.Glob(corpora, "corpus/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no vector corpora")
	}
	for _, p := range paths {
		release := strings.TrimSuffix(path.Base(p), ".json")
		b, err := corpora.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var c corpus
		if err := json.Unmarshal(b, &c); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if c.Schema != "go-iroh-l0/4" || c.Iroh != release {
			t.Fatalf("%s: corpus identity = %q, %q", p, c.Schema, c.Iroh)
		}
		t.Run(release, func(t *testing.T) { f(t, c) })
	}
}

func TestKeyVectors(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		for _, v := range c.Keys {
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
	})
}

func TestPostcardUintVectors(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		for _, v := range c.PostcardUint {
			got, err := postcard.Marshal(v.Value)
			if err != nil {
				t.Fatal(err)
			}
			_, got = mutate("postcard-varint", "", got)
			if want := mustHex(t, v.Postcard); !slices.Equal(got, want) {
				t.Errorf("postcard(%d) = %x, want %x", v.Value, got, want)
			}
		}
	})
}

// TestPostcard8BitVectors pins the 8-bit encodings, which postcard writes as a
// single raw byte rather than as a varint: u8 verbatim and i8 in two's
// complement. Values below 128 encode identically either way, so they are the
// boundary that makes the raw encoding safe for records signed before it, and
// the vectors carry them for that reason.
func TestPostcard8BitVectors(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
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
	})
}

func TestEndpointTicketVector(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		v := c.EndpointTicket
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
	})
}

// TestIPTicketVectors checks endpoint tickets whose addresses include IPv6.
// Each Rust ticket must decode in go-iroh to the same addresses and relay, and
// the same address set built in Go must encode to Rust's bytes.
func TestIPTicketVectors(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		wantNames := []string{"one-ipv6", "two-ipv6", "ipv4-and-ipv6", "ipv6-and-relay", "ipv4-mapped-ipv6"}
		vectors := c.IPTickets
		if len(vectors) != len(wantNames) {
			t.Fatalf("IP ticket count = %d, want %d", len(vectors), len(wantNames))
		}
		for i, v := range vectors {
			if v.Name != wantNames[i] {
				t.Fatalf("vector %d name = %q, want %q", i, v.Name, wantNames[i])
			}
			t.Run(v.Name, func(t *testing.T) {
				want := mustHex(t, v.Bytes)
				if got := ipTicket(t, v).EncodeBytes(); !slices.Equal(got, want) {
					t.Errorf("Go encoding = %x, want %x", got, want)
				}
				ticket, err := endpointticket.Parse(v.Encoded)
				if err != nil {
					t.Fatalf("parse Rust ticket: %v", err)
				}
				addr := ticket.Addr()
				var addrs []string
				for _, ap := range addr.IPAddrs() {
					addrs = append(addrs, ap.String())
				}
				if want := slices.Sorted(slices.Values(v.Addrs)); !slices.Equal(slices.Sorted(slices.Values(addrs)), want) {
					t.Errorf("decoded addrs = %v, want %v", addrs, want)
				}
				var relays []string
				for _, u := range addr.RelayURLs() {
					relays = append(relays, u.String())
				}
				var wantRelays []string
				if v.Relay != "" {
					wantRelays = []string{v.Relay}
				}
				if !slices.Equal(relays, wantRelays) {
					t.Errorf("decoded relays = %v, want %v", relays, wantRelays)
				}
			})
		}
	})
}

// ipTicket builds in Go the ticket that v describes, keyed like the Rust driver.
func ipTicket(t *testing.T, v ipTicketVector) endpointticket.Ticket {
	t.Helper()
	var seed [key.SeedSize]byte
	for i := range seed {
		seed[i] = 0x2a
	}
	addr := netaddr.NewEndpointAddr(key.NewSecretKey(seed).Public().EndpointID())
	for _, s := range v.Addrs {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			t.Fatal(err)
		}
		addr = addr.WithIP(ap)
	}
	if v.Relay != "" {
		u, err := netaddr.ParseRelayURL(v.Relay)
		if err != nil {
			t.Fatal(err)
		}
		addr = addr.WithRelayURL(u)
	}
	return endpointticket.New(addr)
}

// TestBaoVectors checks go-iroh's range proofs against bao-tree's. For each
// blob size and chunk range, the Go encoding must equal Rust's bytes, and Go
// must decode Rust's bytes. A range go-iroh's byte-offset API cannot express
// fails: more than one span, or a start past the end of the blob, which
// bao-tree answers with a proof of the last chunk.
func TestBaoVectors(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		vectors := c.Bao
		if len(vectors) == 0 {
			t.Fatal("no bao vectors")
		}
		for _, v := range vectors {
			t.Run(fmt.Sprintf("%d/%s", v.Size, v.Name), func(t *testing.T) {
				data := make([]byte, v.Size)
				for i := range data {
					data[i] = byte(i % 251)
				}
				offset, length, ok := baoByteRange(v.Ranges, v.Size)
				if !ok {
					t.Fatalf("chunk ranges %v of a %d-byte blob have no byte-range form", v.Ranges, v.Size)
				}
				hash, got, err := blobs.EncodeBlobRange(data, offset, length)
				if err != nil {
					t.Fatal(err)
				}
				if h := hex.EncodeToString(hash[:]); h != v.Hash {
					t.Fatalf("hash = %s, want %s", h, v.Hash)
				}
				want := mustHex(t, v.Encoded)
				if !slices.Equal(got, want) {
					t.Errorf("Go encoding (%d bytes) differs from Rust's (%d bytes)", len(got), len(want))
				}
				decoded, err := blobs.DecodeBlobRange(hash, want, offset, length)
				if err != nil {
					t.Fatalf("decode Rust encoding: %v", err)
				}
				if !slices.Equal(decoded, data[offset:offset+length]) {
					t.Errorf("decoded Rust encoding to the wrong %d bytes", len(decoded))
				}
			})
		}
	})
}

// baoByteRange returns the byte range that chunk range boundaries select in a
// blob of size bytes, if they form one span that starts inside the blob.
func baoByteRange(boundaries []uint64, size uint64) (offset, length uint64, ok bool) {
	const chunkSize = 1024
	if len(boundaries) == 0 || len(boundaries) > 2 {
		return 0, 0, false
	}
	start := boundaries[0]
	if start > (size-min(size, 1))/chunkSize {
		return 0, 0, false
	}
	end := size
	if len(boundaries) == 2 {
		end = min(boundaries[1]*chunkSize, size)
	}
	return start * chunkSize, end - start*chunkSize, true
}

// TestCustomAddrTicketVectors checks that the CustomAddr endpoint tickets the
// Rust driver emits at each pinned release both decode in go-iroh and
// re-encode to the same bytes Go produces for the same address. At iroh 1.0.3
// neither held; see TestLegacyCustomAddrTicketsStillRejected for the encoding
// that replaced.
func TestCustomAddrTicketVectors(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		wantLengths := []int{0, 1, 29, 30, 31, 255}
		vectors := c.CustomAddrTickets
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
	})
}

// TestLegacyCustomAddrTicketsStillRejected is the null control for the test
// above. The iroh 1.0.3 CustomAddr encoding is frozen in
// legacy_custom_addr.json, and go-iroh must keep rejecting it. If both the
// 1.0.3 and the current vectors decoded, the acceptance check would be measuring
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
	eachCorpus(t, func(t *testing.T, c corpus) {
		vectors := c.NonCanonical
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
	})
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
	eachCorpus(t, func(t *testing.T, c corpus) {
		v := c.Pkarr
		_, packetBytes := mutate("pkarr-signer", "", mustHex(t, v.Bytes))
		packet, err := pkarr.FromBytes(packetBytes)
		if err != nil {
			t.Fatal(err)
		}
		if got := packet.TxtRecords(v.Name); !slices.Equal(got, v.Values) {
			t.Fatalf("TXT records = %q, want %q", got, v.Values)
		}
	})
}

func TestTamperedTicketRejected(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		s := c.EndpointTicket.Encoded
		if _, err := endpointticket.Parse(s[:len(s)-1]); err == nil {
			t.Fatal("tampered ticket was accepted")
		}
	})
}

func TestBadPkarrSignatureRejected(t *testing.T) {
	eachCorpus(t, func(t *testing.T, c corpus) {
		b := mustHex(t, c.Pkarr.Bytes)
		b[32] ^= 1
		if _, err := pkarr.FromBytes(b); err == nil {
			t.Fatal("bad pkarr signature was accepted")
		}
	})
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
