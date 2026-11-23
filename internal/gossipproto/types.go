package gossipproto

import (
	"fmt"

	"github.com/tmc/go-iroh/internal/postcard"
)

// ALPN is the Rust iroh-gossip application protocol name.
const ALPN = "/iroh-gossip/1"

// TopicID identifies one gossip topic.
type TopicID [32]byte

// PeerID identifies one peer on the wire.
type PeerID [32]byte

// PeerData is opaque peer metadata carried by membership messages.
type PeerData []byte

// PeerInfo is a peer ID and optional opaque peer metadata.
type PeerInfo struct {
	ID   PeerID
	Data *PeerData
}

// Message is one topic-scoped gossip protocol message.
type Message struct {
	Topic   TopicID
	Message TopicMessage
}

// TopicMessage is either a membership or broadcast message.
type TopicMessage struct {
	Kind   TopicMessageKind
	Swarm  HyparviewMessage
	Gossip PlumtreeMessage
}

// TopicMessageKind identifies a topic message variant.
type TopicMessageKind uint64

const (
	TopicMessageSwarm TopicMessageKind = iota
	TopicMessageGossip
)

// EncodePostcard encodes m as Rust topic::Message.
func (m TopicMessage) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(m.Kind))
	switch m.Kind {
	case TopicMessageSwarm:
		return e.Encode(m.Swarm)
	case TopicMessageGossip:
		return e.Encode(m.Gossip)
	default:
		return fmt.Errorf("gossipproto: unknown topic message %d", m.Kind)
	}
}

// DecodePostcard decodes m as Rust topic::Message.
func (m *TopicMessage) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	m.Kind = TopicMessageKind(kind)
	switch m.Kind {
	case TopicMessageSwarm:
		return d.Decode(&m.Swarm)
	case TopicMessageGossip:
		return d.Decode(&m.Gossip)
	default:
		return fmt.Errorf("gossipproto: unknown topic message %d", m.Kind)
	}
}

// HyparviewMessage is one membership-layer message.
type HyparviewMessage struct {
	Kind         HyparviewMessageKind
	Join         *PeerData
	ForwardJoin  ForwardJoin
	Shuffle      Shuffle
	ShuffleReply ShuffleReply
	Neighbor     Neighbor
	Disconnect   Disconnect
}

// HyparviewMessageKind identifies a membership-layer message variant.
type HyparviewMessageKind uint64

const (
	HyparviewJoin HyparviewMessageKind = iota
	HyparviewForwardJoin
	HyparviewShuffle
	HyparviewShuffleReply
	HyparviewNeighbor
	HyparviewDisconnect
)

// EncodePostcard encodes m as Rust hyparview::Message.
func (m HyparviewMessage) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(m.Kind))
	switch m.Kind {
	case HyparviewJoin:
		return e.Encode(m.Join)
	case HyparviewForwardJoin:
		return e.Encode(m.ForwardJoin)
	case HyparviewShuffle:
		return e.Encode(m.Shuffle)
	case HyparviewShuffleReply:
		return e.Encode(m.ShuffleReply)
	case HyparviewNeighbor:
		return e.Encode(m.Neighbor)
	case HyparviewDisconnect:
		return e.Encode(m.Disconnect)
	default:
		return fmt.Errorf("gossipproto: unknown hyparview message %d", m.Kind)
	}
}

// DecodePostcard decodes m as Rust hyparview::Message.
func (m *HyparviewMessage) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	m.Kind = HyparviewMessageKind(kind)
	switch m.Kind {
	case HyparviewJoin:
		return d.Decode(&m.Join)
	case HyparviewForwardJoin:
		return d.Decode(&m.ForwardJoin)
	case HyparviewShuffle:
		return d.Decode(&m.Shuffle)
	case HyparviewShuffleReply:
		return d.Decode(&m.ShuffleReply)
	case HyparviewNeighbor:
		return d.Decode(&m.Neighbor)
	case HyparviewDisconnect:
		return d.Decode(&m.Disconnect)
	default:
		return fmt.Errorf("gossipproto: unknown hyparview message %d", m.Kind)
	}
}

// Ttl is a HyParView message time-to-live.
type Ttl uint16

// ForwardJoin introduces a newly joined peer.
type ForwardJoin struct {
	Peer PeerInfo
	Ttl  Ttl
}

// Shuffle requests a passive-view shuffle.
type Shuffle struct {
	Origin PeerID
	Nodes  []PeerInfo
	Ttl    Ttl
}

// ShuffleReply replies to a shuffle request.
type ShuffleReply struct {
	Nodes []PeerInfo
}

// Priority identifies a neighbor request priority.
type Priority uint64

const (
	PriorityHigh Priority = iota
	PriorityLow
)

// Neighbor asks to add the sender to the active view.
type Neighbor struct {
	Priority Priority
	Data     *PeerData
}

// Disconnect announces a membership disconnect.
type Disconnect struct {
	Alive   bool
	Respond bool
}

// PlumtreeMessage is one broadcast-layer message.
type PlumtreeMessage struct {
	Kind   PlumtreeMessageKind
	Gossip Gossip
	Graft  Graft
	IHave  []IHave
}

// PlumtreeMessageKind identifies a broadcast-layer message variant.
type PlumtreeMessageKind uint64

const (
	PlumtreeGossip PlumtreeMessageKind = iota
	PlumtreePrune
	PlumtreeGraft
	PlumtreeIHave
)

// EncodePostcard encodes m as Rust plumtree::Message.
func (m PlumtreeMessage) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(m.Kind))
	switch m.Kind {
	case PlumtreeGossip:
		return e.Encode(m.Gossip)
	case PlumtreePrune:
		return nil
	case PlumtreeGraft:
		return e.Encode(m.Graft)
	case PlumtreeIHave:
		return e.Encode(m.IHave)
	default:
		return fmt.Errorf("gossipproto: unknown plumtree message %d", m.Kind)
	}
}

// DecodePostcard decodes m as Rust plumtree::Message.
func (m *PlumtreeMessage) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	m.Kind = PlumtreeMessageKind(kind)
	switch m.Kind {
	case PlumtreeGossip:
		return d.Decode(&m.Gossip)
	case PlumtreePrune:
		return nil
	case PlumtreeGraft:
		return d.Decode(&m.Graft)
	case PlumtreeIHave:
		return d.Decode(&m.IHave)
	default:
		return fmt.Errorf("gossipproto: unknown plumtree message %d", m.Kind)
	}
}

// MessageID identifies a gossip payload.
type MessageID [32]byte

// Round is a gossip delivery round.
type Round uint16

// Gossip is a full PlumTree payload message.
type Gossip struct {
	ID      MessageID
	Content []byte
	Scope   DeliveryScope
}

// DeliveryScope identifies how a received gossip message was delivered.
type DeliveryScope struct {
	Kind  DeliveryScopeKind
	Round Round
}

// DeliveryScopeKind identifies a delivery scope variant.
type DeliveryScopeKind uint64

const (
	DeliveryScopeSwarm DeliveryScopeKind = iota
	DeliveryScopeNeighbors
)

// EncodePostcard encodes s as Rust plumtree::DeliveryScope.
func (s DeliveryScope) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(s.Kind))
	switch s.Kind {
	case DeliveryScopeSwarm:
		return e.Encode(s.Round)
	case DeliveryScopeNeighbors:
		return nil
	default:
		return fmt.Errorf("gossipproto: unknown delivery scope %d", s.Kind)
	}
}

// DecodePostcard decodes s as Rust plumtree::DeliveryScope.
func (s *DeliveryScope) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	s.Kind = DeliveryScopeKind(kind)
	switch s.Kind {
	case DeliveryScopeSwarm:
		return d.Decode(&s.Round)
	case DeliveryScopeNeighbors:
		return nil
	default:
		return fmt.Errorf("gossipproto: unknown delivery scope %d", s.Kind)
	}
}

// IHave advertises a message without sending its payload.
type IHave struct {
	ID    MessageID
	Round Round
}

const iHavePostcardMaxSize = 32 + 3

// Graft asks an eager peer to send a payload.
type Graft struct {
	ID    *MessageID
	Round Round
}
