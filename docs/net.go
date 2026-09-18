package docs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// maxSyncMessageSize bounds one sync frame. A frame carries the entries of a
// single reconciliation round, and a SignedEntry is at least 170 bytes, so
// 16 MiB is roughly 100k entries in one round: past anything a real document
// exchanges, and small enough that a peer's length claim is not worth acting
// on before the bytes arrive.
const maxSyncMessageSize = 16 * 1024 * 1024

// AbortReason is the reason an accepting peer declined a sync request.
type AbortReason uint64

const (
	// AbortNotFound means the namespace is not available.
	AbortNotFound AbortReason = iota
	// AbortAlreadySyncing means the namespace is already syncing.
	AbortAlreadySyncing
	// AbortInternalServerError means the accepting peer hit an internal error.
	AbortInternalServerError
)

// SyncOutcome counts entries exchanged during one sync stream.
type SyncOutcome struct {
	NumSent int
	NumRecv int
}

// Handler handles incoming iroh-docs sync streams.
type Handler struct {
	Store     *MemoryStore
	BlobStore blobs.Store
	Config    SyncConfig
	// Allow reports whether peer may sync namespace. A nil Allow authorizes
	// every peer for every namespace.
	Allow         func(NamespaceID, key.EndpointID) bool
	Validate      func(SignedEntry, ContentStatus) bool
	OnInsert      func(SignedEntry, ContentStatus)
	ContentStatus func(SignedEntry) ContentStatus
}

// Accept handles one incoming iroh-docs connection.
func (h *Handler) Accept(ctx context.Context, conn *iroh.Conn) error {
	if h.Store == nil {
		return fmt.Errorf("docs: nil store")
	}
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("docs: accept stream: %w", err)
	}
	defer s.Close()
	ok := false
	defer func() {
		if !ok {
			s.CancelRead(0)
		}
	}()

	msg, err := readSyncFrame(s)
	if err != nil {
		return fmt.Errorf("docs: read init: %w", err)
	}
	if msg.Kind == syncMessageReport {
		if h.Allow != nil && !h.Allow(msg.Namespace, conn.RemoteID()) {
			if err := writeSyncFrame(s, syncWireMessage{Kind: syncMessageAbort, Reason: AbortNotFound}); err != nil {
				return fmt.Errorf("docs: write abort: %w", err)
			}
			ok = true
			return nil
		}
		local := h.Store.encodeSyncHeads(msg.Namespace)
		if err := writeSyncFrame(s, syncWireMessage{Kind: syncMessageReport, Namespace: msg.Namespace, Report: liveSyncReport{
			Namespace: msg.Namespace,
			Heads:     local,
		}}); err != nil {
			return fmt.Errorf("docs: write sync report: %w", err)
		}
		if msg.Report.Namespace == msg.Namespace && bytes.Equal(msg.Report.Heads, local) {
			ok = true
			return nil
		}
		msg, err = readSyncFrame(s)
		if err != nil {
			return fmt.Errorf("docs: read init: %w", err)
		}
	}
	if msg.Kind != syncMessageInit {
		return fmt.Errorf("docs: expected init message")
	}
	if h.Allow != nil && !h.Allow(msg.Namespace, conn.RemoteID()) {
		if err := writeSyncFrame(s, syncWireMessage{Kind: syncMessageAbort, Reason: AbortNotFound}); err != nil {
			return fmt.Errorf("docs: write abort: %w", err)
		}
		ok = true
		return nil
	}
	_, err = h.run(ctx, s, msg.Namespace, msg.Message, true)
	if err == nil {
		ok = true
	}
	return err
}

// Sync connects to addr and syncs store with the remote peer.
func Sync(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, namespace NamespaceID, store *MemoryStore, blobStore blobs.Store, config SyncConfig) (SyncOutcome, error) {
	if store == nil {
		return SyncOutcome{}, fmt.Errorf("docs: nil store")
	}
	conn, err := ep.Connect(ctx, addr, ALPN)
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("docs: connect: %w", err)
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("docs: open stream: %w", err)
	}
	defer s.Close()
	ok := false
	defer func() {
		if !ok {
			s.CancelRead(0)
		}
	}()

	h := Handler{Store: store, BlobStore: blobStore, Config: config}
	heads := store.encodeSyncHeads(namespace)
	if err := writeSyncFrame(s, syncWireMessage{Kind: syncMessageReport, Namespace: namespace, Report: liveSyncReport{
		Namespace: namespace,
		Heads:     heads,
	}}); err != nil {
		return SyncOutcome{}, fmt.Errorf("docs: write sync report: %w", err)
	}
	report, err := readSyncFrame(s)
	if err != nil {
		return SyncOutcome{}, fmt.Errorf("docs: read sync report: %w", err)
	}
	if report.Kind == syncMessageAbort {
		return SyncOutcome{}, fmt.Errorf("docs: sync aborted: %v", report.Reason)
	}
	if report.Kind != syncMessageReport || report.Report.Namespace != namespace {
		return SyncOutcome{}, fmt.Errorf("docs: expected sync report")
	}
	if bytes.Equal(report.Report.Heads, heads) {
		ok = true
		return SyncOutcome{}, nil
	}
	init := store.InitialMessageInNamespace(namespace)
	if err := writeSyncFrame(s, syncWireMessage{Kind: syncMessageInit, Namespace: namespace, Message: init}); err != nil {
		return SyncOutcome{}, fmt.Errorf("docs: write init: %w", err)
	}
	out, err := h.run(ctx, s, namespace, Message{}, false)
	if err == nil {
		ok = true
	}
	return out, err
}

func (h *Handler) run(ctx context.Context, rw io.ReadWriter, namespace NamespaceID, initial Message, acceptSide bool) (SyncOutcome, error) {
	if h.Store == nil {
		return SyncOutcome{}, fmt.Errorf("docs: nil store")
	}
	contentStatus := h.contentStatus()
	validate := h.Validate
	if validate == nil {
		validate = func(entry SignedEntry, _ ContentStatus) bool { return entry.Verify() == nil }
	}
	var out SyncOutcome
	next := initial
	haveNext := acceptSide
	for {
		if haveNext {
			reply, ok := h.Store.ProcessMessageInNamespace(namespace, h.Config, next, validate, h.OnInsert, contentStatus)
			out.NumRecv += next.ValueCount()
			if !ok {
				return out, nil
			}
			out.NumSent += reply.ValueCount()
			if err := writeSyncFrame(rw, syncWireMessage{Kind: syncMessageSync, Message: reply}); err != nil {
				return out, fmt.Errorf("docs: write sync: %w", err)
			}
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		msg, err := readSyncFrame(rw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, fmt.Errorf("docs: read sync: %w", err)
		}
		switch msg.Kind {
		case syncMessageSync:
			next, haveNext = msg.Message, true
		case syncMessageAbort:
			return out, fmt.Errorf("docs: sync aborted: %v", msg.Reason)
		case syncMessageInit:
			return out, fmt.Errorf("docs: unexpected init message")
		default:
			return out, fmt.Errorf("docs: unknown sync message %d", msg.Kind)
		}
	}
}

func (h *Handler) contentStatus() func(SignedEntry) ContentStatus {
	if h.ContentStatus != nil {
		return h.ContentStatus
	}
	return func(entry SignedEntry) ContentStatus {
		// ContentStatus carries no context of its own, so this is the boundary
		// where one has to be supplied. Threading a caller's context through
		// the callback is a docs API change worth making on its own.
		status, err := blobs.Status(context.Background(), h.BlobStore, entry.Entry.ContentHash())
		if err != nil {
			return ContentMissing
		}
		switch status.State {
		case blobs.BlobComplete:
			return ContentComplete
		case blobs.BlobPartial:
			return ContentIncomplete
		default:
			return ContentMissing
		}
	}
}

type syncMessageKind uint64

const (
	syncMessageInit syncMessageKind = iota
	syncMessageSync
	syncMessageAbort
	syncMessageReport
)

type syncWireMessage struct {
	Kind      syncMessageKind
	Namespace NamespaceID
	Message   Message
	Reason    AbortReason
	Report    liveSyncReport
}

func (m syncWireMessage) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(m.Kind))
	switch m.Kind {
	case syncMessageInit:
		if err := e.Encode(m.Namespace); err != nil {
			return err
		}
		return e.Encode(m.Message)
	case syncMessageSync:
		return e.Encode(m.Message)
	case syncMessageAbort:
		return e.Encode(m.Reason)
	case syncMessageReport:
		if err := e.Encode(m.Namespace); err != nil {
			return err
		}
		return e.Encode(m.Report)
	default:
		return fmt.Errorf("docs: unknown sync message %d", m.Kind)
	}
}

func (m *syncWireMessage) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	m.Kind = syncMessageKind(kind)
	switch m.Kind {
	case syncMessageInit:
		if err := d.Decode(&m.Namespace); err != nil {
			return err
		}
		return d.Decode(&m.Message)
	case syncMessageSync:
		return d.Decode(&m.Message)
	case syncMessageAbort:
		return d.Decode(&m.Reason)
	case syncMessageReport:
		if err := d.Decode(&m.Namespace); err != nil {
			return err
		}
		return d.Decode(&m.Report)
	default:
		return fmt.Errorf("docs: unknown sync message %d", m.Kind)
	}
}

func writeSyncFrame(w io.Writer, msg syncWireMessage) error {
	b, err := postcard.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal frame: %w", err)
	}
	if len(b) > maxSyncMessageSize {
		return fmt.Errorf("frame too large: %d > %d", len(b), maxSyncMessageSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame length: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

func readSyncFrame(r io.Reader) (syncWireMessage, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return syncWireMessage{}, err
	}
	// n is negative when a length above 2^31-1 is decoded on a 32-bit int.
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 0 || n > maxSyncMessageSize {
		return syncWireMessage{}, fmt.Errorf("frame too large: %d > %d", uint32(n), maxSyncMessageSize)
	}
	// Copy rather than allocate n up front: the buffer then grows with the
	// bytes the peer actually sends, not with the length it claims.
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(r, int64(n))); err != nil {
		return syncWireMessage{}, err
	}
	if buf.Len() != n {
		return syncWireMessage{}, io.ErrUnexpectedEOF
	}
	var msg syncWireMessage
	if err := postcard.Unmarshal(buf.Bytes(), &msg); err != nil {
		return syncWireMessage{}, err
	}
	return msg, nil
}
