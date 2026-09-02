package key

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"filippo.io/edwards25519"
)

const (
	// PublicKeySize is the size of an Ed25519 public key, in bytes.
	PublicKeySize = ed25519.PublicKeySize
	// PrivateKeySize is the size of an Ed25519 private key, in bytes.
	PrivateKeySize = ed25519.PrivateKeySize
	// SeedSize is the size of an Ed25519 private key seed, in bytes.
	SeedSize = ed25519.SeedSize
	// SignatureSize is the size of an Ed25519 signature, in bytes.
	SignatureSize = ed25519.SignatureSize
)

// zBase32 is the z-base-32 encoding used by pkarr (https://pkarr.org) for
// endpoint-id domain names. Its alphabet differs from RFC 4648 base32.
const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

// Errors returned when parsing keys.
var (
	// ErrInvalidKeyData is returned when bytes do not represent a valid
	// Ed25519 curve point.
	ErrInvalidKeyData = errors.New("data is not a valid public key")
	// ErrInvalidKeyLength is returned when key bytes have the wrong length.
	ErrInvalidKeyLength = errors.New("invalid length")
	// ErrDecodeHex is returned when a string cannot be decoded as hex.
	ErrDecodeHex = errors.New("failed to decode hex string")
	// ErrDecodeBase32 is returned when a string cannot be decoded as base32.
	ErrDecodeBase32 = errors.New("failed to decode base32 string")
)

// PublicKey is a public Ed25519 key. It is verified to be a valid curve point
// when created.
//
// The zero value is not usable; construct a PublicKey with [NewPublicKey],
// [ParsePublicKey], or [SecretKey.Public].
type PublicKey struct {
	bytes [PublicKeySize]byte
}

// EndpointID is a network-facing identifier for an endpoint.
//
// Use EndpointID in network-facing APIs and [PublicKey] when performing
// cryptographic operations.
type EndpointID PublicKey

// NewPublicKey constructs a PublicKey from a 32-byte array. It returns
// [ErrInvalidKeyData] if the bytes do not decompress to a valid Ed25519 curve
// point. It never fails for bytes returned from [PublicKey.Bytes].
func NewPublicKey(b [PublicKeySize]byte) (PublicKey, error) {
	if _, err := new(edwards25519.Point).SetBytes(b[:]); err != nil {
		return PublicKey{}, ErrInvalidKeyData
	}
	return PublicKey{bytes: b}, nil
}

// UncheckedEndpointID skips curve-point validation; b must have passed
// [NewEndpointID] before.
func UncheckedEndpointID(b [PublicKeySize]byte) EndpointID {
	return EndpointID(PublicKey{bytes: b})
}

// NewEndpointID constructs an EndpointID from a 32-byte array.
func NewEndpointID(b [PublicKeySize]byte) (EndpointID, error) {
	k, err := NewPublicKey(b)
	if err != nil {
		return EndpointID{}, err
	}
	return k.EndpointID(), nil
}

// PublicKeyFromEd25519 constructs a PublicKey from a crypto/ed25519 public key.
func PublicKeyFromEd25519(k ed25519.PublicKey) (PublicKey, error) {
	return PublicKeyFromSlice(k)
}

// PublicKeyFromSlice constructs a PublicKey from a byte slice. It returns
// [ErrInvalidKeyLength] if the slice is not 32 bytes and [ErrInvalidKeyData] if
// the bytes are not a valid curve point.
func PublicKeyFromSlice(b []byte) (PublicKey, error) {
	if len(b) != PublicKeySize {
		return PublicKey{}, ErrInvalidKeyLength
	}
	var arr [PublicKeySize]byte
	copy(arr[:], b)
	return NewPublicKey(arr)
}

// EndpointIDFromSlice constructs an EndpointID from a byte slice.
func EndpointIDFromSlice(b []byte) (EndpointID, error) {
	k, err := PublicKeyFromSlice(b)
	if err != nil {
		return EndpointID{}, err
	}
	return k.EndpointID(), nil
}

// EndpointID returns the endpoint identifier for k.
func (k PublicKey) EndpointID() EndpointID { return EndpointID(k) }

// Bytes returns the public key as a 32-byte array.
func (k PublicKey) Bytes() [PublicKeySize]byte { return k.bytes }

// Ed25519 returns the key as a crypto/ed25519 public key. The returned slice is
// a copy and may be modified by the caller.
func (k PublicKey) Ed25519() ed25519.PublicKey {
	out := make(ed25519.PublicKey, PublicKeySize)
	copy(out, k.bytes[:])
	return out
}

// Verify reports whether sig is a valid signature of message by k. It returns
// nil on success and [ErrInvalidSignature] otherwise.
//
// Verification uses crypto/ed25519 (cofactored, RFC 8032). The Rust reference
// uses ed25519-dalek's verify_strict (cofactorless). The two agree for every
// signature an honest iroh peer produces; they differ only for adversarially
// malleable signatures, which iroh drops anyway. This divergence is benign for
// iroh's drop-on-failure model (relay handshake, TLS raw-key, and pkarr packet
// verification all reject on failure).
func (k PublicKey) Verify(message []byte, sig Signature) error {
	return k.verify(message, sig)
}

// IsZero reports whether k is the unusable zero value.
func (k PublicKey) IsZero() bool { return k == PublicKey{} }

// Equal reports whether k and other are the same key.
func (k PublicKey) Equal(other PublicKey) bool { return k.bytes == other.bytes }

// Compare returns -1, 0, or +1 comparing k and other by their raw bytes. It
// gives PublicKey a total order suitable for sorting and map-free ordered use.
func (k PublicKey) Compare(other PublicKey) int {
	return bytes.Compare(k.bytes[:], other.bytes[:])
}

// String returns the lowercase-hex encoding of the key. It is the canonical
// human-readable form and round-trips through [ParsePublicKey].
func (k PublicKey) String() string {
	return hex.EncodeToString(k.bytes[:])
}

// Short returns a short, friendly hex string of the first 5 bytes of the key,
// for logging. It is not a complete or parseable representation.
func (k PublicKey) Short() string {
	return hex.EncodeToString(k.bytes[:5])
}

// PublicKey returns id as a public key for cryptographic operations.
func (id EndpointID) PublicKey() PublicKey { return PublicKey(id) }

// Bytes returns the endpoint id as a 32-byte array.
func (id EndpointID) Bytes() [PublicKeySize]byte { return id.PublicKey().Bytes() }

// IsZero reports whether id is the unusable zero value.
func (id EndpointID) IsZero() bool { return id == EndpointID{} }

// Equal reports whether id and other are the same endpoint id.
func (id EndpointID) Equal(other EndpointID) bool {
	return id.PublicKey().Equal(other.PublicKey())
}

// Compare returns -1, 0, or +1 comparing id and other by their raw bytes. It
// gives EndpointID a total order suitable for sorting and map-free ordered use.
func (id EndpointID) Compare(other EndpointID) int {
	return id.PublicKey().Compare(other.PublicKey())
}

// String returns the lowercase-hex encoding of the endpoint id. It is the
// canonical human-readable form and round-trips through [ParseEndpointID].
func (id EndpointID) String() string { return id.PublicKey().String() }

// Short returns a short, friendly hex string of the first 5 bytes of the
// endpoint id, for logging. It is not a complete or parseable representation.
func (id EndpointID) Short() string { return id.PublicKey().Short() }

// Z32 encodes the endpoint id in z-base-32, the encoding used by pkarr domain
// names. It uses a different alphabet from the RFC 4648 base32 accepted by
// [ParseEndpointID] and is the same length, so the two cannot be told apart:
// parse the result with [ParseEndpointIDZ32], not [ParseEndpointID].
func (id EndpointID) Z32() string {
	k := id.PublicKey()
	return encodeZBase32(k.bytes[:])
}

// ParseEndpointIDZ32 parses an endpoint id from the z-base-32 encoding produced
// by [EndpointID.Z32].
func ParseEndpointIDZ32(s string) (EndpointID, error) {
	b, err := decodeZBase32(s)
	if err != nil {
		return EndpointID{}, ErrDecodeBase32
	}
	return EndpointIDFromSlice(b)
}

// ParsePublicKey parses a PublicKey from its hex or base32 string form. A string
// of exactly 64 characters is decoded as lowercase hex; otherwise it is decoded
// as RFC 4648 base32 (no padding, case-insensitive). [PublicKey.String] always
// produces the hex form. The z-base-32 form is not accepted; see
// [ParseEndpointID].
func ParsePublicKey(s string) (PublicKey, error) {
	b, err := decodeBase32OrHex(s)
	if err != nil {
		return PublicKey{}, err
	}
	return NewPublicKey(b)
}

// ParseEndpointID parses an EndpointID from its hex or RFC 4648 base32 string
// form: the forms [EndpointID.String] and upstream iroh produce.
//
// It does not accept the z-base-32 form produced by [EndpointID.Z32]. Both
// base32 flavours encode an endpoint id in 52 characters but with different
// alphabets, so a z-base-32 id cannot be recognized reliably — some decode
// under RFC 4648 to a different, equally valid-looking id. Use
// [ParseEndpointIDZ32] for that form. When the input fails to parse but is
// well-formed z-base-32, the returned error says so.
func ParseEndpointID(s string) (EndpointID, error) {
	k, err := ParsePublicKey(s)
	if err != nil {
		if b, zerr := decodeZBase32(s); zerr == nil && len(b) == PublicKeySize {
			return EndpointID{}, fmt.Errorf("%w: input is z-base-32, use ParseEndpointIDZ32", err)
		}
		return EndpointID{}, err
	}
	return k.EndpointID(), nil
}

// MarshalText implements encoding.TextMarshaler, producing the hex form.
func (k PublicKey) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, parsing the hex or base32
// form.
func (k *PublicKey) UnmarshalText(text []byte) error {
	parsed, err := ParsePublicKey(string(text))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler, producing the hex form.
func (id EndpointID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, parsing the hex or base32
// form.
func (id *EndpointID) UnmarshalText(text []byte) error {
	parsed, err := ParseEndpointID(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler, producing the 32 raw bytes.
func (k PublicKey) MarshalBinary() ([]byte, error) {
	b := k.bytes
	return b[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler from 32 raw bytes.
func (k *PublicKey) UnmarshalBinary(data []byte) error {
	parsed, err := PublicKeyFromSlice(data)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler, producing the 32 raw bytes.
func (id EndpointID) MarshalBinary() ([]byte, error) {
	return id.PublicKey().MarshalBinary()
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler from 32 raw bytes.
func (id *EndpointID) UnmarshalBinary(data []byte) error {
	parsed, err := EndpointIDFromSlice(data)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// SecretKey is a secret endpoint identity key. Its public part can always be
// recovered.
//
// Go has no destructors, so unlike the Rust original this type is not cleared
// automatically. Call [SecretKey.Clear] to overwrite the key material when a
// long-lived secret is no longer needed.
//
// The zero value is not usable; construct with [GenerateSecretKey],
// [NewSecretKey], or [ParseSecretKey].
type SecretKey struct {
	signing ed25519.PrivateKey // 64 bytes: seed||public
}

// GenerateSecretKey generates a new SecretKey using crypto/ed25519.
func GenerateSecretKey() (SecretKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SecretKey{}, fmt.Errorf("generate secret key: %w", err)
	}
	return SecretKey{signing: priv}, nil
}

// NewSecretKey constructs a SecretKey from its 32-byte seed.
func NewSecretKey(seed [SeedSize]byte) SecretKey {
	return SecretKey{signing: ed25519.NewKeyFromSeed(seed[:])}
}

// SecretKeyFromEd25519 constructs a SecretKey from a crypto/ed25519 private key.
// The private key is copied.
func SecretKeyFromEd25519(k ed25519.PrivateKey) (SecretKey, error) {
	if len(k) != PrivateKeySize {
		return SecretKey{}, ErrInvalidKeyLength
	}
	return SecretKey{signing: append(ed25519.PrivateKey(nil), k...)}, nil
}

// SecretKeyFromSlice constructs a SecretKey from a 32-byte seed slice. It
// returns [ErrInvalidKeyLength] if the slice is not 32 bytes.
func SecretKeyFromSlice(b []byte) (SecretKey, error) {
	if len(b) != SeedSize {
		return SecretKey{}, ErrInvalidKeyLength
	}
	var seed [SeedSize]byte
	copy(seed[:], b)
	return NewSecretKey(seed), nil
}

// ParseSecretKey parses a SecretKey from its hex or base32 string form, matching
// the rules of [ParsePublicKey].
func ParseSecretKey(s string) (SecretKey, error) {
	b, err := decodeBase32OrHex(s)
	if err != nil {
		return SecretKey{}, err
	}
	return NewSecretKey(b), nil
}

// Public returns the public key of this secret key.
func (k SecretKey) Public() PublicKey {
	pub, _ := PublicKeyFromEd25519(k.signing.Public().(ed25519.PublicKey))
	return pub
}

// Sign signs msg and returns the signature.
func (k SecretKey) Sign(msg []byte) Signature {
	return k.sign(msg)
}

// Ed25519 returns the key as a crypto/ed25519 private key. The returned key is
// a copy and satisfies crypto.Signer.
func (k SecretKey) Ed25519() ed25519.PrivateKey {
	return append(ed25519.PrivateKey(nil), k.signing...)
}

// Bytes returns the 32-byte seed of the secret key. The public part can be
// recovered from it.
func (k SecretKey) Bytes() [SeedSize]byte {
	var seed [SeedSize]byte
	copy(seed[:], k.signing.Seed())
	return seed
}

// Clear overwrites k's key material and resets k to the zero value. It does not
// clear copies already made by value or by [SecretKey.Bytes], [SecretKey.Ed25519],
// or [SecretKey.MarshalBinary].
func (k *SecretKey) Clear() {
	if k == nil {
		return
	}
	clear(k.signing)
	k.signing = nil
}

// IsZero reports whether k is the unusable zero value.
func (k SecretKey) IsZero() bool { return k.signing == nil }

// MarshalBinary implements encoding.BinaryMarshaler, producing the 32-byte seed.
func (k SecretKey) MarshalBinary() ([]byte, error) {
	seed := k.Bytes()
	return seed[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler from a 32-byte seed.
func (k *SecretKey) UnmarshalBinary(data []byte) error {
	parsed, err := SecretKeyFromSlice(data)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// Signature is a signature produced by a [SecretKey].
type Signature struct {
	bytes [SignatureSize]byte
}

// NewSignature constructs a Signature from its 64 raw bytes.
func NewSignature(b [SignatureSize]byte) Signature {
	return Signature{bytes: b}
}

// SignatureFromEd25519 constructs a Signature from a crypto/ed25519 signature.
func SignatureFromEd25519(sig []byte) (Signature, error) {
	return SignatureFromSlice(sig)
}

// SignatureFromSlice constructs a Signature from a byte slice. It returns
// [ErrInvalidSignatureParse] if the slice is not 64 bytes.
func SignatureFromSlice(b []byte) (Signature, error) {
	if len(b) != SignatureSize {
		return Signature{}, ErrInvalidSignatureParse
	}
	var arr [SignatureSize]byte
	copy(arr[:], b)
	return Signature{bytes: arr}, nil
}

// Bytes returns the signature as a 64-byte array.
func (s Signature) Bytes() [SignatureSize]byte { return s.bytes }

// Ed25519 returns the signature bytes used by crypto/ed25519. The returned
// slice is a copy and may be modified by the caller.
func (s Signature) Ed25519() []byte {
	out := make([]byte, SignatureSize)
	copy(out, s.bytes[:])
	return out
}

// String returns the lowercase-hex encoding of the signature.
func (s Signature) String() string { return hex.EncodeToString(s.bytes[:]) }

// MarshalText implements encoding.TextMarshaler, producing the hex form.
func (s Signature) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, parsing the hex form.
func (s *Signature) UnmarshalText(text []byte) error {
	b, err := hex.DecodeString(string(text))
	if err != nil {
		return ErrDecodeHex
	}
	parsed, err := SignatureFromSlice(b)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler, producing the 64 raw
// signature bytes.
func (s Signature) MarshalBinary() ([]byte, error) {
	b := s.bytes
	return b[:], nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler from 64 raw bytes.
func (s *Signature) UnmarshalBinary(data []byte) error {
	parsed, err := SignatureFromSlice(data)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Equal reports whether s and other are the same signature.
func (s Signature) Equal(other Signature) bool { return s.bytes == other.bytes }

// Signature parsing and verification errors.
var (
	// ErrInvalidSignatureParse is returned when bytes cannot be parsed as an
	// Ed25519 signature.
	ErrInvalidSignatureParse = errors.New("could not parse ed25519 signature")
	// ErrInvalidSignature is returned when signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")
)

// decodeBase32OrHex decodes a 32-byte value from a key's string form: 64-char
// strings are lowercase hex, others are RFC 4648 base32 (no padding).
func decodeBase32OrHex(s string) ([32]byte, error) {
	var out [32]byte
	if len(s) == PublicKeySize*2 {
		b, err := hex.DecodeString(s)
		if err != nil {
			return out, ErrDecodeHex
		}
		copy(out[:], b)
		return out, nil
	}
	b, err := decodeStdBase32NoPad(strings.ToUpper(s))
	if err != nil {
		return out, ErrDecodeBase32
	}
	if len(b) != PublicKeySize {
		return out, ErrInvalidKeyLength
	}
	copy(out[:], b)
	return out, nil
}
