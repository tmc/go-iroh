package gossipproto

import (
	"bytes"
	"math/rand"
	"slices"
	"time"
)

// Config configures the gossip protocol state machine.
type Config struct {
	Topic          TopicConfig
	MaxMessageSize int
}

// DefaultConfig returns Rust iroh-gossip protocol defaults.
func DefaultConfig() Config {
	return Config{
		Topic:          DefaultTopicConfig(),
		MaxMessageSize: DefaultMaxMessageSize,
	}
}

// InEvent is an input to the top-level gossip protocol state machine.
type InEvent struct {
	Kind    InEventKind
	From    PeerID
	Message Message
	Topic   TopicID
	Command TopicCommand
	Timer   Timer
	Peer    PeerID
	Data    PeerData
	Now     time.Time
}

// InEventKind identifies a top-level gossip input.
type InEventKind uint8

const (
	RecvMessage InEventKind = iota
	CommandEvent
	TimerExpired
	PeerDisconnected
	UpdatePeerData
)

// OutEvent is an output from the top-level gossip protocol state machine.
type OutEvent struct {
	Kind OutEventKind
	// Generation is set by the gossip adapter when it queues an output.
	// It is not part of the protocol message.
	Generation uint64
	To         PeerID
	Message    Message
	Topic      TopicID
	After      time.Duration
	Timer      Timer
	Event      TopicEvent
	Data       *PeerData
}

// OutEventKind identifies a top-level gossip output.
type OutEventKind uint8

const (
	SendMessage OutEventKind = iota
	EmitEvent
	ScheduleTimer
	DisconnectPeer
	PeerDataEvent
)

// Timer is an opaque top-level timer value emitted by State.
type Timer struct {
	Topic TopicID
	Timer TopicTimer
}

// State is the IO-less top-level gossip protocol state machine.
type State struct {
	me         PeerID
	meData     PeerData
	config     Config
	rand       *rand.Rand
	topics     map[TopicID]*TopicState
	peerTopics map[PeerID]map[TopicID]struct{}
}

// NewState returns a gossip protocol state machine.
func NewState(me PeerID, data PeerData, config Config) *State {
	return NewStateWithRand(me, data, config, nil)
}

// NewStateWithRand returns a gossip protocol state machine using r to seed
// per-topic HyParView peer selection.
func NewStateWithRand(me PeerID, data PeerData, config Config, r *rand.Rand) *State {
	if config == (Config{}) {
		config = DefaultConfig()
	}
	if r == nil {
		r = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	config.MaxMessageSize = NormalizeMaxMessageSize(config.MaxMessageSize)
	config.Topic.Broadcast.MaxPayloadSize = MaxPayloadSize(config.MaxMessageSize)
	return &State{
		me:         me,
		meData:     clonePeerData(data),
		config:     config,
		rand:       r,
		topics:     map[TopicID]*TopicState{},
		peerTopics: map[PeerID]map[TopicID]struct{}{},
	}
}

// Topics returns a snapshot of joined topic IDs, sorted.
func (s *State) Topics() []TopicID {
	out := make([]TopicID, 0, len(s.topics))
	for topic := range s.topics {
		out = append(out, topic)
	}
	slices.SortFunc(out, func(a, b TopicID) int {
		return bytes.Compare(a[:], b[:])
	})
	return out
}

// HasActivePeers reports whether topic has active peers.
func (s *State) HasActivePeers(topic TopicID) bool {
	st := s.topics[topic]
	return st != nil && st.HasActivePeers()
}

// Handle applies ev and returns protocol outputs for the caller to process.
func (s *State) Handle(ev InEvent) []OutEvent {
	switch ev.Kind {
	case RecvMessage:
		return s.handleTopicEvent(ev.Message.Topic, TopicInEvent{
			Kind:    TopicRecvMessage,
			From:    ev.From,
			Message: ev.Message.Message,
			Now:     ev.Now,
		}, true)
	case CommandEvent:
		if ev.Command.Kind == TopicCommandJoin {
			if _, ok := s.topics[ev.Topic]; !ok {
				data := clonePeerData(s.meData)
				s.topics[ev.Topic] = NewTopicStateWithRand(s.me, &data, s.config.Topic, rand.New(rand.NewSource(s.rand.Int63())))
			}
		}
		quit := ev.Command.Kind == TopicCommandQuit
		out := s.handleTopicEvent(ev.Topic, TopicInEvent{
			Kind:    TopicCommandEvent,
			Command: ev.Command,
			Now:     ev.Now,
		}, false)
		if quit {
			delete(s.topics, ev.Topic)
		}
		return out
	case TimerExpired:
		return s.handleTopicEvent(ev.Timer.Topic, TopicInEvent{
			Kind:  TopicTimerExpired,
			Timer: ev.Timer.Timer,
			Now:   ev.Now,
		}, false)
	case PeerDisconnected:
		var out []OutEvent
		for _, topic := range s.Topics() {
			st := s.topics[topic]
			for _, ev := range st.Handle(TopicInEvent{Kind: TopicPeerDisconnected, Peer: ev.Peer, Now: ev.Now}) {
				s.handleTopicOut(topic, ev, &out)
			}
		}
		delete(s.peerTopics, ev.Peer)
		return out
	case UpdatePeerData:
		s.meData = clonePeerData(ev.Data)
		var out []OutEvent
		for _, topic := range s.Topics() {
			st := s.topics[topic]
			for _, ev := range st.Handle(TopicInEvent{Kind: TopicUpdatePeerData, Data: s.meData, Now: ev.Now}) {
				s.handleTopicOut(topic, ev, &out)
			}
		}
		return out
	default:
		return nil
	}
}

func (s *State) handleTopicEvent(topic TopicID, ev TopicInEvent, received bool) []OutEvent {
	st := s.topics[topic]
	if st == nil {
		return nil
	}
	if received {
		if s.peerTopics[ev.From] == nil {
			s.peerTopics[ev.From] = map[TopicID]struct{}{}
		}
		s.peerTopics[ev.From][topic] = struct{}{}
	}
	var out []OutEvent
	for _, ev := range st.Handle(ev) {
		s.handleTopicOut(topic, ev, &out)
	}
	return out
}

func (s *State) handleTopicOut(topic TopicID, ev TopicOutEvent, out *[]OutEvent) {
	switch ev.Kind {
	case TopicSendMessage:
		*out = append(*out, OutEvent{
			Kind: SendMessage,
			To:   ev.To,
			Message: Message{
				Topic:   topic,
				Message: ev.Message,
			},
		})
	case TopicEmitEvent:
		*out = append(*out, OutEvent{Kind: EmitEvent, Topic: topic, Event: ev.Event})
	case TopicScheduleTimer:
		*out = append(*out, OutEvent{
			Kind:  ScheduleTimer,
			Topic: topic,
			After: ev.After,
			Timer: Timer{Topic: topic, Timer: ev.Timer},
		})
	case TopicDisconnectPeer:
		if s.dropPeerTopic(ev.To, topic) {
			*out = append(*out, OutEvent{Kind: DisconnectPeer, To: ev.To})
		}
	case TopicPeerData:
		*out = append(*out, OutEvent{Kind: PeerDataEvent, Topic: topic, To: ev.To, Data: clonePeerDataPtr(ev.Data)})
	}
}

func (s *State) dropPeerTopic(peer PeerID, topic TopicID) bool {
	topics := s.peerTopics[peer]
	if len(topics) == 0 {
		return false
	}
	delete(topics, topic)
	if len(topics) != 0 {
		return false
	}
	delete(s.peerTopics, peer)
	return true
}
