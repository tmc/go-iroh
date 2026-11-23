package gossip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

// ALPN is the Rust iroh-gossip application protocol name.
const ALPN = gossipproto.ALPN

// TopicID identifies one gossip topic.
type TopicID = gossipproto.TopicID

// PeerID identifies one peer on the wire.
type PeerID = gossipproto.PeerID

// Message is one topic-scoped gossip protocol message.
type Message = gossipproto.Message

// TopicMessage is either a membership or broadcast message.
type TopicMessage = gossipproto.TopicMessage

// Handler receives gossip messages from accepted iroh connections.
type Handler struct {
	// MaxMessageSize limits postcard frame bodies. The zero value uses the Rust
	// default.
	MaxMessageSize int
	// Handle is called for each received message. A nil Handle discards
	// messages after validating their frames.
	Handle func(context.Context, key.EndpointID, Message) error
}

// Accept handles one incoming iroh-gossip connection.
func (h *Handler) Accept(ctx context.Context, conn *iroh.Conn) error {
	maxSize := h.maxMessageSize()
	errc := make(chan error, 1)
	for {
		select {
		case err := <-errc:
			return err
		default:
		}

		s, err := conn.AcceptUniStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if conn.Context().Err() != nil {
				return nil
			}
			return fmt.Errorf("gossip: accept uni stream: %w", err)
		}
		go func() {
			if err := h.readStream(ctx, conn.RemoteID(), s, maxSize); err != nil {
				select {
				case errc <- err:
					_ = conn.CloseWithError(0, "gossip handler error")
				default:
				}
			}
		}()
	}
}

func (h *Handler) readStream(ctx context.Context, from key.EndpointID, r io.Reader, maxSize int) error {
	var header gossipproto.StreamHeader
	if err := gossipproto.ReadFrame(r, &header, maxSize); err != nil {
		return fmt.Errorf("gossip: read stream header: %w", err)
	}
	for {
		var msg TopicMessage
		err := gossipproto.ReadFrame(r, &msg, maxSize)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("gossip: read message: %w", err)
		}
		if h.Handle == nil {
			continue
		}
		if err := h.Handle(ctx, from, Message{Topic: header.Topic, Message: msg}); err != nil {
			return fmt.Errorf("gossip: handle message: %w", err)
		}
	}
}

func (h *Handler) maxMessageSize() int {
	return gossipproto.NormalizeMaxMessageSize(h.MaxMessageSize)
}

// Sender writes gossip messages to an iroh connection.
type Sender struct {
	conn    *iroh.Conn
	maxSize int
	topic   *Topic

	mu      sync.Mutex
	streams map[TopicID]*iroh.SendStream
}

// NewSender returns a sender for conn.
func NewSender(conn *iroh.Conn, maxMessageSize int) *Sender {
	return &Sender{
		conn:    conn,
		maxSize: gossipproto.NormalizeMaxMessageSize(maxMessageSize),
		streams: map[TopicID]*iroh.SendStream{},
	}
}

// Send writes msg on the topic stream for msg.Topic.
func (s *Sender) Send(ctx context.Context, msg Message) error {
	if s.topic != nil {
		return errors.New("gossip: topic sender cannot send wire messages")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	w := s.streams[msg.Topic]
	if w == nil {
		var err error
		w, err = s.conn.OpenUniStreamSync(ctx)
		if err != nil {
			return fmt.Errorf("gossip: open uni stream: %w", err)
		}
		if err := gossipproto.WriteFrame(w, gossipproto.StreamHeader{Topic: msg.Topic}, s.maxSize); err != nil {
			_ = w.Close()
			return fmt.Errorf("gossip: write stream header: %w", err)
		}
		s.streams[msg.Topic] = w
	}
	if err := gossipproto.WriteFrame(w, msg.Message, s.maxSize); err != nil {
		return fmt.Errorf("gossip: write message: %w", err)
	}
	if isDisconnect(msg.Message) {
		delete(s.streams, msg.Topic)
		if err := w.Close(); err != nil {
			return fmt.Errorf("gossip: close topic stream: %w", err)
		}
	}
	return nil
}

// FinishTopic closes the send stream for topic, if one is open.
func (s *Sender) FinishTopic(topic TopicID) error {
	if s == nil || s.topic != nil {
		return nil
	}
	s.mu.Lock()
	w := s.streams[topic]
	delete(s.streams, topic)
	s.mu.Unlock()
	if w == nil {
		return nil
	}
	return w.Close()
}

func (s *Sender) hasOpenStream(topic TopicID) bool {
	if s == nil || s.topic != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[topic] != nil
}

// Close closes all open topic streams.
func (s *Sender) Close() error {
	if s.topic != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var errs []error
	for topic, w := range s.streams {
		delete(s.streams, topic)
		if err := w.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isDisconnect(msg TopicMessage) bool {
	return msg.Kind == gossipproto.TopicMessageSwarm && msg.Swarm.Kind == gossipproto.HyparviewDisconnect
}
