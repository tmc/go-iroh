package vectors

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"

	"github.com/tmc/go-iroh/endpointticket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/pkarr"
	"github.com/tmc/go-iroh/postcard"
)

//go:embed corpus.json
var corpusJSON []byte

type corpus struct {
	Schema         string       `json:"schema"`
	Iroh           string       `json:"iroh"`
	Keys           []keyVector  `json:"keys"`
	PostcardUint   []uintVector `json:"postcard_uint"`
	EndpointTicket struct {
		Encoded string `json:"encoded"`
		Bytes   string `json:"bytes"`
	} `json:"endpoint_ticket"`
	Pkarr struct {
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

func load(t *testing.T) corpus {
	t.Helper()
	var c corpus
	if err := json.Unmarshal(corpusJSON, &c); err != nil {
		t.Fatal(err)
	}
	if c.Schema != "go-iroh-l0/1" || c.Iroh != "1.0.3" {
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
