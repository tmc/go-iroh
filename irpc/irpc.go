// Package irpc provides small postcard-framed RPC helpers for iroh streams.
//
// The Go API is not stable before v1 and may change in any v0 release.
package irpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/postcard"
)

const defaultMaxMessageSize = 16 * 1024 * 1024

// Handler handles typed requests on an iroh connection.
type Handler[Req, Resp any] struct {
	// MaxMessageSize limits one postcard frame body. The zero value uses 16 MiB.
	MaxMessageSize int
	// Handle handles one request and may send zero or more responses.
	// Each request runs in its own goroutine. A panic in Handle is
	// recovered and logged, and the caller receives an error; the
	// connection and its other requests are unaffected.
	Handle func(context.Context, Req, *Responder[Resp]) error
}

// Accept handles streams opened on conn until ctx is cancelled or conn closes.
func (h Handler[Req, Resp]) Accept(ctx context.Context, conn *iroh.Conn) error {
	if h.Handle == nil {
		return errors.New("irpc: nil handler")
	}
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		go h.handleStream(ctx, s)
	}
}

func (h Handler[Req, Resp]) handleStream(ctx context.Context, s *iroh.Stream) {
	defer s.Close()
	var req Req
	if err := readValue(ctx, s, h.maxMessageSize(), &req); err != nil {
		_ = writeValue(s, h.maxMessageSize(), response[Resp]{Kind: responseError, Error: err.Error()})
		return
	}
	r := &Responder[Resp]{w: s, max: h.maxMessageSize()}
	defer func() {
		if v := recover(); v != nil {
			slog.Error("irpc: handler panicked", "panic", v)
			_ = r.Error(errors.New("irpc: handler panicked"))
		}
	}()
	if err := h.Handle(ctx, req, r); err != nil {
		_ = r.Error(err)
	}
}

func (h Handler[Req, Resp]) maxMessageSize() int {
	if h.MaxMessageSize <= 0 {
		return defaultMaxMessageSize
	}
	return h.MaxMessageSize
}

// Responder sends typed responses for one request.
type Responder[Resp any] struct {
	w   io.Writer
	max int
}

// Send sends resp to the caller.
func (r *Responder[Resp]) Send(resp Resp) error {
	if r == nil {
		return errors.New("irpc: nil responder")
	}
	return writeValue(r.w, r.max, response[Resp]{Kind: responseValue, Value: resp})
}

// Error sends err to the caller.
func (r *Responder[Resp]) Error(err error) error {
	if err == nil {
		return nil
	}
	return writeValue(r.w, r.max, response[Resp]{Kind: responseError, Error: err.Error()})
}

// Call opens one stream on conn, sends req, and yields the response stream.
func Call[Req, Resp any](ctx context.Context, conn *iroh.Conn, req Req, maxMessageSize int) (iter.Seq2[Resp, error], error) {
	if conn == nil {
		return nil, errors.New("irpc: nil connection")
	}
	if maxMessageSize <= 0 {
		maxMessageSize = defaultMaxMessageSize
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("irpc: open stream: %w", err)
	}
	if err := writeValue(s, maxMessageSize, req); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("irpc: write request: %w", err)
	}
	if err := s.Close(); err != nil {
		return nil, fmt.Errorf("irpc: close request: %w", err)
	}
	return func(yield func(Resp, error) bool) {
		defer s.CancelRead(0)
		for {
			var resp response[Resp]
			if err := readValue(ctx, s, maxMessageSize, &resp); err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				var zero Resp
				yield(zero, err)
				return
			}
			switch resp.Kind {
			case responseValue:
				if !yield(resp.Value, nil) {
					return
				}
			case responseError:
				var zero Resp
				yield(zero, errors.New(resp.Error))
				return
			default:
				var zero Resp
				yield(zero, fmt.Errorf("irpc: unknown response %d", resp.Kind))
				return
			}
		}
	}, nil
}

type responseKind uint64

const (
	responseValue responseKind = iota
	responseError
)

type response[T any] struct {
	Kind  responseKind
	Value T
	Error string
}

func writeValue(w io.Writer, max int, v any) error {
	b, err := postcard.Marshal(v)
	if err != nil {
		return fmt.Errorf("irpc: marshal: %w", err)
	}
	if len(b) > max {
		return fmt.Errorf("irpc: message too large: %d > %d", len(b), max)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("irpc: write frame length: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("irpc: write frame body: %w", err)
	}
	return nil
}

func readValue(ctx context.Context, r io.Reader, max int, v any) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	// n is negative if the length does not fit in an int, as on a 32-bit
	// platform, which would otherwise slip past the cap check.
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 0 || n > max {
		return fmt.Errorf("irpc: message too large: %d > %d", uint32(n), max)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	if err := postcard.Unmarshal(b, v); err != nil {
		return fmt.Errorf("irpc: unmarshal: %w", err)
	}
	return ctxErr(ctx)
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
