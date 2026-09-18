package docs

import (
	"bytes"
	"fmt"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/key"
	"lukechampine.com/blake3"
)

// MaxTimestampFutureShift is the maximum accepted future timestamp in
// microseconds. It bounds entries arriving from a peer only: conflicts are
// resolved by timestamp, so an entry dated arbitrarily far ahead would win
// every later write to its key and that key's subtree. Entries already in a
// store are left as they are.
const MaxTimestampFutureShift = 10 * 60 * uint64(time.Second/time.Microsecond)

// acceptTimestamp reports whether entry is dated within
// [MaxTimestampFutureShift] of now, as a remote entry must be.
func acceptTimestamp(entry Entry) bool {
	return entry.Timestamp() <= uint64(time.Now().UnixMicro())+MaxTimestampFutureShift
}

// ContentStatus reports whether entry content is locally available.
type ContentStatus uint64

const (
	// ContentComplete means the content is fully available.
	ContentComplete ContentStatus = iota
	// ContentIncomplete means the content is partially available.
	ContentIncomplete
	// ContentMissing means the content is missing.
	ContentMissing
)

// RecordIdentifier identifies an entry by namespace, author, and key.
type RecordIdentifier struct {
	namespace NamespaceID
	author    AuthorID
	key       []byte
}

// NewRecordIdentifier returns an entry identifier.
func NewRecordIdentifier(namespace NamespaceID, author AuthorID, k []byte) RecordIdentifier {
	return RecordIdentifier{
		namespace: namespace,
		author:    author,
		key:       append([]byte(nil), k...),
	}
}

// Namespace returns the namespace id.
func (id RecordIdentifier) Namespace() NamespaceID { return id.namespace }

// Author returns the author id.
func (id RecordIdentifier) Author() AuthorID { return id.author }

// Key returns the entry key.
func (id RecordIdentifier) Key() []byte { return append([]byte(nil), id.key...) }

// Compare compares id and other by namespace, author, and key.
func (id RecordIdentifier) Compare(other RecordIdentifier) int {
	return bytes.Compare(id.bytes(), other.bytes())
}

func (id RecordIdentifier) bytes() []byte {
	b := make([]byte, 0, 64+len(id.key))
	ns := id.namespace.Bytes()
	author := id.author.Bytes()
	b = append(b, ns[:]...)
	b = append(b, author[:]...)
	return append(b, id.key...)
}

// EncodePostcard encodes id as Rust RecordIdentifier.
func (id RecordIdentifier) EncodePostcard(e *postcard.Encoder) error {
	e.BytesValue(id.bytes())
	return nil
}

// DecodePostcard decodes id as Rust RecordIdentifier.
func (id *RecordIdentifier) DecodePostcard(d *postcard.Decoder) error {
	b, err := d.BytesValue()
	if err != nil {
		return err
	}
	if len(b) < 64 {
		return fmt.Errorf("docs: record identifier too short")
	}
	var nsBytes, authorBytes [32]byte
	copy(nsBytes[:], b[:32])
	copy(authorBytes[:], b[32:64])
	ns, err := NewNamespaceID(nsBytes)
	if err != nil {
		return err
	}
	author, err := NewAuthorID(authorBytes)
	if err != nil {
		return err
	}
	*id = NewRecordIdentifier(ns, author, b[64:])
	return nil
}

// Record is the value part of an entry.
type Record struct {
	Len       uint64
	Hash      blobs.Hash
	Timestamp uint64
}

// NewRecord returns a content record.
func NewRecord(hash blobs.Hash, length uint64, timestamp uint64) Record {
	return Record{Hash: hash, Len: length, Timestamp: timestamp}
}

// EmptyRecord returns a tombstone record.
func EmptyRecord(timestamp uint64) Record {
	return NewRecord(blobs.EmptyHash, 0, timestamp)
}

// IsEmpty reports whether r is a tombstone.
func (r Record) IsEmpty() bool { return r.Hash == blobs.EmptyHash }

// Compare compares r and other by timestamp and content hash.
func (r Record) Compare(other Record) int {
	if r.Timestamp < other.Timestamp {
		return -1
	}
	if r.Timestamp > other.Timestamp {
		return 1
	}
	return bytes.Compare(r.Hash[:], other.Hash[:])
}

func (r Record) encode(out []byte) []byte {
	out = appendUint64BE(out, r.Len)
	out = append(out, r.Hash[:]...)
	return appendUint64BE(out, r.Timestamp)
}

// Entry is a single document entry.
type Entry struct {
	ID     RecordIdentifier
	Record Record
}

// NewEntry returns an entry from id and record.
func NewEntry(id RecordIdentifier, record Record) Entry {
	return Entry{ID: id, Record: record}
}

// Namespace returns the entry namespace.
func (e Entry) Namespace() NamespaceID { return e.ID.Namespace() }

// Author returns the entry author.
func (e Entry) Author() AuthorID { return e.ID.Author() }

// Key returns the entry key.
func (e Entry) Key() []byte { return e.ID.Key() }

// ContentHash returns the content hash.
func (e Entry) ContentHash() blobs.Hash { return e.Record.Hash }

// ContentLen returns the content length.
func (e Entry) ContentLen() uint64 { return e.Record.Len }

// Timestamp returns the entry timestamp.
func (e Entry) Timestamp() uint64 { return e.Record.Timestamp }

// Compare compares e and other by identifier and record.
func (e Entry) Compare(other Entry) int {
	if c := e.ID.Compare(other.ID); c != 0 {
		return c
	}
	return e.Record.Compare(other.Record)
}

// ValidateEmpty validates the empty-record invariant.
func (e Entry) ValidateEmpty() error {
	switch {
	case e.Record.Hash == blobs.EmptyHash && e.Record.Len == 0:
		return nil
	case e.Record.Hash != blobs.EmptyHash && e.Record.Len != 0:
		return nil
	default:
		return fmt.Errorf("docs: invalid empty entry")
	}
}

// Encode returns the canonical entry bytes used for signatures.
func (e Entry) Encode() []byte {
	out := e.ID.bytes()
	return e.Record.encode(out)
}

// EncodePostcard encodes e as Rust Entry.
func (e Entry) EncodePostcard(enc *postcard.Encoder) error {
	if err := enc.Encode(e.ID); err != nil {
		return err
	}
	return enc.Encode(e.Record)
}

// DecodePostcard decodes e as Rust Entry.
func (e *Entry) DecodePostcard(dec *postcard.Decoder) error {
	if err := dec.Decode(&e.ID); err != nil {
		return err
	}
	return dec.Decode(&e.Record)
}

// EntrySignature is the namespace and author signatures for an entry.
type EntrySignature struct {
	Author    key.Signature
	Namespace key.Signature
}

// SignEntry returns the Rust-compatible signatures for entry.
func SignEntry(entry Entry, namespace NamespaceSecret, author Author) EntrySignature {
	b := entry.Encode()
	return EntrySignature{
		Author:    author.Sign(b),
		Namespace: namespace.Sign(b),
	}
}

// Verify verifies sig over entry.
func (sig EntrySignature) Verify(entry Entry, namespace NamespaceID, author AuthorID) error {
	b := entry.Encode()
	if err := namespace.Verify(b, sig.Namespace); err != nil {
		return err
	}
	return author.Verify(b, sig.Author)
}

// EncodePostcard encodes sig as Rust EntrySignature.
func (sig EntrySignature) EncodePostcard(e *postcard.Encoder) error {
	author := sig.Author.Bytes()
	namespace := sig.Namespace.Bytes()
	e.RawBytes(author[:])
	e.RawBytes(namespace[:])
	return nil
}

// DecodePostcard decodes sig as Rust EntrySignature.
func (sig *EntrySignature) DecodePostcard(d *postcard.Decoder) error {
	author, err := d.RawBytes(key.SignatureSize)
	if err != nil {
		return err
	}
	namespace, err := d.RawBytes(key.SignatureSize)
	if err != nil {
		return err
	}
	sig.Author, err = key.SignatureFromSlice(author)
	if err != nil {
		return err
	}
	sig.Namespace, err = key.SignatureFromSlice(namespace)
	return err
}

// SignedEntry is an entry with namespace and author signatures.
type SignedEntry struct {
	Signature EntrySignature
	Entry     Entry
}

// NewSignedEntry signs entry with namespace and author.
func NewSignedEntry(entry Entry, namespace NamespaceSecret, author Author) SignedEntry {
	return SignedEntry{Signature: SignEntry(entry, namespace, author), Entry: entry}
}

// Verify verifies the entry signatures.
func (s SignedEntry) Verify() error {
	return s.Signature.Verify(s.Entry, s.Entry.Namespace(), s.Entry.Author())
}

// Fingerprint returns the range-reconciliation fingerprint for s.
func (s SignedEntry) Fingerprint() [32]byte {
	h := blake3.New(32, nil)
	ns := s.Entry.Namespace().Bytes()
	author := s.Entry.Author().Bytes()
	h.Write(ns[:])
	h.Write(author[:])
	h.Write(s.Entry.Key())
	var ts [8]byte
	putUint64BE(ts[:], s.Entry.Timestamp())
	h.Write(ts[:])
	hash := s.Entry.ContentHash()
	h.Write(hash[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Equal reports whether s and other are identical.
func (s SignedEntry) Equal(other SignedEntry) bool {
	sb, _ := postcard.Marshal(s)
	ob, _ := postcard.Marshal(other)
	return bytes.Equal(sb, ob)
}

// Compare compares s and other by entry.
func (s SignedEntry) Compare(other SignedEntry) int {
	return s.Entry.Compare(other.Entry)
}

func appendUint64BE(b []byte, x uint64) []byte {
	var tmp [8]byte
	putUint64BE(tmp[:], x)
	return append(b, tmp[:]...)
}

func putUint64BE(b []byte, x uint64) {
	_ = b[7]
	b[0] = byte(x >> 56)
	b[1] = byte(x >> 48)
	b[2] = byte(x >> 40)
	b[3] = byte(x >> 32)
	b[4] = byte(x >> 24)
	b[5] = byte(x >> 16)
	b[6] = byte(x >> 8)
	b[7] = byte(x)
}
