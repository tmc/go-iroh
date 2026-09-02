package key

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestPublicKeyFromStringHex(t *testing.T) {
	// A known-valid key from the Rust iroh-base test suite.
	const s = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6"
	k, err := ParsePublicKey(s)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if got := k.String(); got != s {
		t.Errorf("String() = %q, want %q", got, s)
	}
	want, _ := hex.DecodeString(s)
	b := k.Bytes()
	if !bytes.Equal(b[:], want) {
		t.Errorf("Bytes() = %x, want %x", b, want)
	}
}

func TestPublicKeyAllZeroIsValid(t *testing.T) {
	// The all-zero point is a valid (small-order) Ed25519 point and iroh
	// accepts it; from_bytes(&[0;32]) succeeds in the Rust impl.
	var zero [PublicKeySize]byte
	if _, err := NewPublicKey(zero); err != nil {
		t.Fatalf("NewPublicKey(zero): %v", err)
	}
}

func TestParseEndpointIDRejectsGarbage(t *testing.T) {
	// Regression: "foobarbaz" must not panic and must error.
	if _, err := ParsePublicKey("foobarbaz"); err == nil {
		t.Fatal("expected error parsing garbage")
	}
}

func TestPublicKeyInvalidCurvePoint(t *testing.T) {
	// y = 2 does not lie on the Edwards curve, so it cannot be decompressed to
	// a valid point; this matches ed25519-dalek's VerifyingKey::from_bytes
	// rejecting it.
	var b [PublicKeySize]byte
	b[0] = 2
	_, err := NewPublicKey(b)
	if !errors.Is(err, ErrInvalidKeyData) {
		t.Fatalf("err = %v, want ErrInvalidKeyData", err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	sk, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.Public()
	msg := []byte("hello world")
	sig := sk.Sign(msg)
	if err := pk.Verify(msg, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
	if err := pk.Verify([]byte("tampered"), sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Verify(tampered) = %v, want ErrInvalidSignature", err)
	}
}

func TestSignatureEncoding(t *testing.T) {
	sk, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	sig := sk.Sign([]byte("hello world"))

	text, err := sig.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(text) != sig.String() {
		t.Fatalf("MarshalText = %q, want %q", text, sig.String())
	}
	var textSig Signature
	if err := textSig.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if !textSig.Equal(sig) {
		t.Fatal("text round-trip mismatch")
	}
	if err := textSig.UnmarshalText([]byte("not hex")); !errors.Is(err, ErrDecodeHex) {
		t.Fatalf("UnmarshalText invalid = %v, want ErrDecodeHex", err)
	}

	data, err := sig.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != SignatureSize {
		t.Fatalf("MarshalBinary len = %d, want %d", len(data), SignatureSize)
	}
	var binSig Signature
	if err := binSig.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	if !binSig.Equal(sig) {
		t.Fatal("binary round-trip mismatch")
	}
	if err := binSig.UnmarshalBinary(data[:SignatureSize-1]); !errors.Is(err, ErrInvalidSignatureParse) {
		t.Fatalf("UnmarshalBinary short = %v, want ErrInvalidSignatureParse", err)
	}
}

func TestEd25519Conversions(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := PublicKeyFromEd25519(pub)
	if err != nil {
		t.Fatalf("PublicKeyFromEd25519: %v", err)
	}
	if !bytes.Equal(pk.Ed25519(), pub) {
		t.Fatal("public key conversion mismatch")
	}
	pubCopy := pk.Ed25519()
	pubCopy[0] ^= 0xff
	if bytes.Equal(pk.Ed25519(), pubCopy) {
		t.Fatal("public key Ed25519 aliases key storage")
	}
	sk, err := SecretKeyFromEd25519(priv)
	if err != nil {
		t.Fatalf("SecretKeyFromEd25519: %v", err)
	}
	priv[0] ^= 0xff
	if bytes.Equal(sk.Ed25519(), priv) {
		t.Fatal("secret key aliases caller storage")
	}

	msg := []byte("hello world")
	sig, err := SignatureFromEd25519(ed25519.Sign(sk.Ed25519(), msg))
	if err != nil {
		t.Fatalf("SignatureFromEd25519: %v", err)
	}
	if err := sk.Public().Verify(msg, sig); err != nil {
		t.Fatalf("verify converted signature: %v", err)
	}
	sigCopy := sig.Ed25519()
	sigCopy[0] ^= 0xff
	if bytes.Equal(sig.Ed25519(), sigCopy) {
		t.Fatal("signature Ed25519 aliases signature storage")
	}
}

func TestSecretKeyEd25519IsCryptoSigner(t *testing.T) {
	sk, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	var signer crypto.Signer = sk.Ed25519()

	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("signer public key type = %T, want ed25519.PublicKey", signer.Public())
	}
	if !bytes.Equal(pub, sk.Public().Ed25519()) {
		t.Fatal("signer public key mismatch")
	}

	msg := []byte("hello world")
	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := SignatureFromEd25519(sig)
	if err != nil {
		t.Fatalf("SignatureFromEd25519: %v", err)
	}
	if err := sk.Public().Verify(msg, parsed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSecretKeyStringRoundTrip(t *testing.T) {
	sk, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	// hex form
	skBytes := sk.Bytes()
	hexForm := hex.EncodeToString(skBytes[:])
	sk2, err := ParseSecretKey(hexForm)
	if err != nil {
		t.Fatalf("ParseSecretKey(hex): %v", err)
	}
	if sk2.Bytes() != sk.Bytes() {
		t.Error("hex round-trip mismatch")
	}
	// public key string round-trips
	pk := sk.Public()
	pk2, err := ParsePublicKey(pk.String())
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !pk2.Equal(pk) {
		t.Error("public key string round-trip mismatch")
	}
}

func TestSecretKeyClear(t *testing.T) {
	sk, err := GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	priv := sk.signing
	if len(priv) != PrivateKeySize {
		t.Fatalf("private key len = %d, want %d", len(priv), PrivateKeySize)
	}
	sk.Clear()
	if !sk.IsZero() {
		t.Fatal("SecretKey.Clear did not reset key to zero value")
	}
	for i, b := range priv {
		if b != 0 {
			t.Fatalf("private key byte %d = %d, want 0", i, b)
		}
	}
}

func TestPublicKeyJSON(t *testing.T) {
	var zero [PublicKeySize]byte
	k, _ := NewPublicKey(zero)
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var k2 PublicKey
	if err := json.Unmarshal(data, &k2); err != nil {
		t.Fatal(err)
	}
	if !k2.Equal(k) {
		t.Errorf("JSON round-trip mismatch: %v != %v", k2, k)
	}
}

func TestPublicKeyBinary(t *testing.T) {
	sk, _ := GenerateSecretKey()
	k := sk.Public()
	data, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != PublicKeySize {
		t.Errorf("MarshalBinary len = %d, want %d", len(data), PublicKeySize)
	}
	var k2 PublicKey
	if err := k2.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	if !k2.Equal(k) {
		t.Error("binary round-trip mismatch")
	}
}

// TestParseEndpointIDRejectsZ32 pins the reason ParseEndpointID must not learn
// to accept z-base-32: both encodings render 32 bytes in 52 characters and
// share 29 of 32 symbols, so the two cannot be distinguished. A z-base-32 id
// usually fails to decode as RFC 4648 base32, and occasionally decodes to a
// different, equally well-formed endpoint id.
func TestParseEndpointIDRejectsZ32(t *testing.T) {
	// Uses a symbol ("8") that exists only in the z-base-32 alphabet.
	const rejected = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo"
	want, err := ParseEndpointIDZ32(rejected)
	if err != nil {
		t.Fatalf("ParseEndpointIDZ32(%q): %v", rejected, err)
	}
	if _, err := ParseEndpointID(rejected); !errors.Is(err, ErrDecodeBase32) {
		t.Errorf("ParseEndpointID(z32) error = %v, want ErrDecodeBase32", err)
	}
	if _, err := ParseEndpointID(want.String()); err != nil {
		t.Errorf("ParseEndpointID(hex): %v", err)
	}

	// Drawn from the ~1-in-170 z-base-32 ids whose symbols all exist in the
	// RFC 4648 alphabet too. These decode without error to the wrong id, which
	// is why auto-detection cannot be added.
	const ambiguous = "bf4nc56yxomts6n7whnrmotaqs7pgro36xdgeenscw4fdd3gexgy"
	z32ID, err := ParseEndpointIDZ32(ambiguous)
	if err != nil {
		t.Fatalf("ParseEndpointIDZ32(%q): %v", ambiguous, err)
	}
	rfcID, err := ParseEndpointID(ambiguous)
	if err != nil {
		t.Fatalf("ParseEndpointID(%q): %v", ambiguous, err)
	}
	if rfcID.Equal(z32ID) {
		t.Fatal("fixture is no longer ambiguous between the two base32 alphabets")
	}
}

func TestEndpointIDEncoding(t *testing.T) {
	sk, _ := GenerateSecretKey()
	id := sk.Public().EndpointID()

	text, err := id.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEndpointID(string(text))
	if err != nil {
		t.Fatalf("ParseEndpointID: %v", err)
	}
	if !parsed.Equal(id) {
		t.Fatal("text round-trip mismatch")
	}

	zid, err := ParseEndpointIDZ32(id.Z32())
	if err != nil {
		t.Fatalf("ParseEndpointIDZ32: %v", err)
	}
	if !zid.Equal(id) {
		t.Fatal("z32 round-trip mismatch")
	}

	data, err := id.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var bin EndpointID
	if err := bin.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	if !bin.Equal(id) {
		t.Fatal("binary round-trip mismatch")
	}
	if !id.PublicKey().Equal(sk.Public()) {
		t.Fatal("public key conversion mismatch")
	}
}

func TestPublicKeyShort(t *testing.T) {
	const s = "ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6"
	k, _ := ParsePublicKey(s)
	if got, want := k.Short(), "ae58ff8833"; got != want {
		t.Errorf("Short() = %q, want %q", got, want)
	}
}

func TestPublicKeyCompareOrders(t *testing.T) {
	// Use valid keys (derived from seeds) and order them by raw bytes.
	k1 := NewSecretKey([SeedSize]byte{0: 1}).Public()
	k2 := NewSecretKey([SeedSize]byte{0: 2}).Public()
	lo, hi := k1, k2
	if lo.Compare(hi) > 0 {
		lo, hi = hi, lo
	}
	if lo.Compare(hi) >= 0 {
		t.Error("expected lo < hi")
	}
	if hi.Compare(lo) <= 0 {
		t.Error("expected hi > lo")
	}
	if lo.Compare(lo) != 0 {
		t.Error("expected lo == lo")
	}
}

func TestParseBase32UpperAndLower(t *testing.T) {
	sk, _ := GenerateSecretKey()
	k := sk.Public()
	// Build base32 form via stdBase32NoPad (uppercase). ParsePublicKey should
	// accept it (and its lowercase variant) since it is not 64 chars.
	b := k.Bytes()
	upper := stdBase32NoPad.EncodeToString(b[:])
	if len(upper) == PublicKeySize*2 {
		t.Skip("base32 form collides with hex length")
	}
	k2, err := ParsePublicKey(upper)
	if err != nil {
		t.Fatalf("ParsePublicKey(base32 upper): %v", err)
	}
	if !k2.Equal(k) {
		t.Error("base32 upper round-trip mismatch")
	}
	k3, err := ParsePublicKey(strings.ToLower(upper))
	if err != nil {
		t.Fatalf("ParsePublicKey(base32 lower): %v", err)
	}
	if !k3.Equal(k) {
		t.Error("base32 lower round-trip mismatch")
	}
}
