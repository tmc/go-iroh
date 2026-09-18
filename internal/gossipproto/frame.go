package gossipproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tmc/go-iroh/internal/postcard"
)

const (
	// DefaultMaxMessageSize is the Rust iroh-gossip default max message size.
	DefaultMaxMessageSize = 4096
	// MinMaxMessageSize is the Rust iroh-gossip minimum max message size.
	MinMaxMessageSize = 512
)

// ErrFrameTooLarge reports a frame that exceeds the configured maximum size.
var ErrFrameTooLarge = errors.New("gossipproto: frame too large")

// NormalizeMaxMessageSize returns the configured gossip frame size, enforcing
// the Rust minimum. A non-positive value selects the Rust default.
func NormalizeMaxMessageSize(n int) int {
	if n <= 0 {
		return DefaultMaxMessageSize
	}
	if n < MinMaxMessageSize {
		return MinMaxMessageSize
	}
	return n
}

// StreamHeader is the first frame written on each gossip unidirectional stream.
type StreamHeader struct {
	Topic TopicID
}

// WriteFrame writes v as one Rust-compatible gossip frame.
func WriteFrame(w io.Writer, v any, maxSize int) error {
	maxSize = NormalizeMaxMessageSize(maxSize)
	b, err := postcard.Marshal(v)
	if err != nil {
		return fmt.Errorf("gossipproto: marshal frame: %w", err)
	}
	if len(b) >= maxSize {
		return fmt.Errorf("%w: %d >= %d", ErrFrameTooLarge, len(b), maxSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("gossipproto: write frame length: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("gossipproto: write frame body: %w", err)
	}
	return nil
}

// ReadFrame reads one Rust-compatible gossip frame into v.
func ReadFrame(r io.Reader, v any, maxSize int) error {
	maxSize = NormalizeMaxMessageSize(maxSize)
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return fmt.Errorf("gossipproto: read frame length: %w", err)
	}
	// n is negative if the length does not fit in an int, as on a 32-bit
	// platform, which would otherwise slip past the cap check.
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 0 || n > maxSize {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, uint32(n), maxSize)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return fmt.Errorf("gossipproto: read frame body: %w", err)
	}
	if err := postcard.Unmarshal(b, v); err != nil {
		return fmt.Errorf("gossipproto: unmarshal frame: %w", err)
	}
	return nil
}
