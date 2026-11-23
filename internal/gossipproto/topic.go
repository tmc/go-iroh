package gossipproto

import (
	"math/rand"
	"time"
)

// TopicConfig configures one gossip topic state machine.
type TopicConfig struct {
	Membership HyparviewConfig
	Broadcast  PlumtreeConfig
}

// DefaultTopicConfig returns Rust iroh-gossip topic defaults.
func DefaultTopicConfig() TopicConfig {
	return TopicConfig{
		Membership: DefaultHyparviewConfig(),
		Broadcast:  DefaultPlumtreeConfig(),
	}
}

// TopicCommand is an application command for one topic.
type TopicCommand struct {
	Kind    TopicCommandKind
	Peers   []PeerID
	Content []byte
	Scope   Scope
}

// TopicCommandKind identifies a topic command.
type TopicCommandKind uint8

const (
	TopicCommandJoin TopicCommandKind = iota
	TopicCommandBroadcast
	TopicCommandQuit
)

// TopicInEvent is an input to one topic state machine.
type TopicInEvent struct {
	Kind    TopicInEventKind
	From    PeerID
	Message TopicMessage
	Command TopicCommand
	Timer   TopicTimer
	Peer    PeerID
	Data    PeerData
	Now     time.Time
}

// TopicInEventKind identifies a topic input.
type TopicInEventKind uint8

const (
	TopicRecvMessage TopicInEventKind = iota
	TopicCommandEvent
	TopicTimerExpired
	TopicPeerDisconnected
	TopicUpdatePeerData
)

// TopicOutEvent is an output from one topic state machine.
type TopicOutEvent struct {
	Kind    TopicOutEventKind
	To      PeerID
	Message TopicMessage
	After   time.Duration
	Timer   TopicTimer
	Event   TopicEvent
	Data    *PeerData
}

// TopicOutEventKind identifies a topic output.
type TopicOutEventKind uint8

const (
	TopicSendMessage TopicOutEventKind = iota
	TopicEmitEvent
	TopicScheduleTimer
	TopicDisconnectPeer
	TopicPeerData
)

// TopicEvent is an application event emitted by TopicState.
type TopicEvent struct {
	Kind          TopicEventKind
	Peer          PeerID
	Content       []byte
	DeliveredFrom PeerID
	Scope         DeliveryScope
}

// TopicEventKind identifies a topic application event.
type TopicEventKind uint8

const (
	TopicNeighborUp TopicEventKind = iota
	TopicNeighborDown
	TopicReceived
)

// TopicTimer is an opaque timer value emitted by TopicState.
type TopicTimer struct {
	Kind      TopicTimerKind
	Hyparview HyparviewTimer
	Plumtree  PlumtreeTimer
}

// TopicTimerKind identifies a topic timer.
type TopicTimerKind uint8

const (
	TopicTimerHyparview TopicTimerKind = iota
	TopicTimerPlumtree
)

// TopicStats counts messages sent and received by a topic.
type TopicStats struct {
	MessagesSent     int
	MessagesReceived int
}

// TopicState coordinates HyParView membership and PlumTree broadcast for one topic.
type TopicState struct {
	me     PeerID
	swarm  *HyparviewState
	gossip *PlumtreeState
	stats  TopicStats
}

// NewTopicState returns a state machine for one topic.
func NewTopicState(me PeerID, data *PeerData, config TopicConfig) *TopicState {
	return NewTopicStateWithRand(me, data, config, nil)
}

// NewTopicStateWithRand returns a state machine for one topic using r for
// HyParView peer selection.
func NewTopicStateWithRand(me PeerID, data *PeerData, config TopicConfig, r *rand.Rand) *TopicState {
	if config == (TopicConfig{}) {
		config = DefaultTopicConfig()
	}
	return &TopicState{
		me:     me,
		swarm:  NewHyparviewStateWithRand(me, data, config.Membership, r),
		gossip: NewPlumtreeState(me, config.Broadcast),
	}
}

// Stats returns the current topic counters.
func (s *TopicState) Stats() TopicStats {
	return s.stats
}

// HasActivePeers reports whether the topic has active HyParView neighbors.
func (s *TopicState) HasActivePeers() bool {
	return len(s.swarm.ActivePeers()) > 0
}

// WantsConnection reports whether the topic wants to keep a connection to peer.
func (s *TopicState) WantsConnection(peer PeerID) bool {
	return s.swarm.WantsConnection(peer)
}

// Handle applies ev and returns protocol outputs for the caller to process.
func (s *TopicState) Handle(ev TopicInEvent) []TopicOutEvent {
	var out []TopicOutEvent
	switch ev.Kind {
	case TopicCommandEvent:
		switch ev.Command.Kind {
		case TopicCommandJoin:
			for _, peer := range ev.Command.Peers {
				out = append(out, s.fromHyparview(s.swarm.Handle(HyparviewInEvent{
					Kind: HyparviewRequestJoin,
					Peer: peer,
				}))...)
			}
		case TopicCommandBroadcast:
			out = append(out, s.fromPlumtree(s.gossip.Handle(PlumtreeInEvent{
				Kind:    PlumtreeBroadcast,
				Content: ev.Command.Content,
				Scope:   ev.Command.Scope,
				Now:     ev.Now,
			}))...)
		case TopicCommandQuit:
			out = append(out, s.fromHyparview(s.swarm.Handle(HyparviewInEvent{Kind: HyparviewQuit}))...)
		}
	case TopicRecvMessage:
		s.stats.MessagesReceived++
		switch ev.Message.Kind {
		case TopicMessageSwarm:
			out = append(out, s.fromHyparview(s.swarm.Handle(HyparviewInEvent{
				Kind:    HyparviewRecvMessage,
				From:    ev.From,
				Message: ev.Message.Swarm,
			}))...)
		case TopicMessageGossip:
			out = append(out, s.fromPlumtree(s.gossip.Handle(PlumtreeInEvent{
				Kind:    PlumtreeRecvMessage,
				From:    ev.From,
				Message: ev.Message.Gossip,
				Now:     ev.Now,
			}))...)
		}
	case TopicTimerExpired:
		switch ev.Timer.Kind {
		case TopicTimerHyparview:
			out = append(out, s.fromHyparview(s.swarm.Handle(HyparviewInEvent{
				Kind:  HyparviewTimerExpired,
				Timer: ev.Timer.Hyparview,
			}))...)
		case TopicTimerPlumtree:
			out = append(out, s.fromPlumtree(s.gossip.Handle(PlumtreeInEvent{
				Kind:  PlumtreeTimerExpired,
				Timer: ev.Timer.Plumtree,
				Now:   ev.Now,
			}))...)
		}
	case TopicPeerDisconnected:
		out = append(out, s.fromHyparview(s.swarm.Handle(HyparviewInEvent{
			Kind: HyparviewPeerDisconnected,
			Peer: ev.Peer,
		}))...)
		out = append(out, s.fromPlumtree(s.gossip.Handle(PlumtreeInEvent{
			Kind:     PlumtreeNeighborDown,
			Neighbor: ev.Peer,
			Now:      ev.Now,
		}))...)
	case TopicUpdatePeerData:
		data := clonePeerData(ev.Data)
		out = append(out, s.fromHyparview(s.swarm.Handle(HyparviewInEvent{
			Kind: HyparviewUpdatePeerData,
			Data: &data,
		}))...)
	}
	for _, event := range out {
		if event.Kind == TopicSendMessage {
			s.stats.MessagesSent++
		}
	}
	return out
}

func (s *TopicState) fromHyparview(events []HyparviewOutEvent) []TopicOutEvent {
	var out []TopicOutEvent
	for _, ev := range events {
		switch ev.Kind {
		case HyparviewSendMessage:
			out = append(out, TopicOutEvent{
				Kind:    TopicSendMessage,
				To:      ev.To,
				Message: TopicMessage{Kind: TopicMessageSwarm, Swarm: ev.Message},
			})
		case HyparviewScheduleTimer:
			out = append(out, TopicOutEvent{
				Kind:  TopicScheduleTimer,
				After: ev.After,
				Timer: TopicTimer{Kind: TopicTimerHyparview, Hyparview: ev.Timer},
			})
		case HyparviewDisconnectPeer:
			out = append(out, TopicOutEvent{Kind: TopicDisconnectPeer, To: ev.To})
		case HyparviewEmitEvent:
			switch ev.Event.Kind {
			case HyparviewNeighborUp:
				out = append(out, TopicOutEvent{
					Kind:  TopicEmitEvent,
					Event: TopicEvent{Kind: TopicNeighborUp, Peer: ev.Event.Peer},
				})
				out = append(out, s.fromPlumtree(s.gossip.Handle(PlumtreeInEvent{
					Kind:     PlumtreeNeighborUp,
					Neighbor: ev.Event.Peer,
				}))...)
			case HyparviewNeighborDown:
				out = append(out, TopicOutEvent{
					Kind:  TopicEmitEvent,
					Event: TopicEvent{Kind: TopicNeighborDown, Peer: ev.Event.Peer},
				})
				out = append(out, s.fromPlumtree(s.gossip.Handle(PlumtreeInEvent{
					Kind:     PlumtreeNeighborDown,
					Neighbor: ev.Event.Peer,
				}))...)
			}
		case HyparviewPeerData:
			out = append(out, TopicOutEvent{Kind: TopicPeerData, To: ev.To, Data: clonePeerDataPtr(ev.Data)})
		}
	}
	return out
}

func (s *TopicState) fromPlumtree(events []PlumtreeOutEvent) []TopicOutEvent {
	var out []TopicOutEvent
	for _, ev := range events {
		switch ev.Kind {
		case PlumtreeSendMessage:
			out = append(out, TopicOutEvent{
				Kind:    TopicSendMessage,
				To:      ev.To,
				Message: TopicMessage{Kind: TopicMessageGossip, Gossip: ev.Message},
			})
		case PlumtreeScheduleTimer:
			out = append(out, TopicOutEvent{
				Kind:  TopicScheduleTimer,
				After: ev.After,
				Timer: TopicTimer{Kind: TopicTimerPlumtree, Plumtree: ev.Timer},
			})
		case PlumtreeEmitEvent:
			out = append(out, TopicOutEvent{
				Kind: TopicEmitEvent,
				Event: TopicEvent{
					Kind:          TopicReceived,
					Content:       cloneBytes(ev.Event.Content),
					DeliveredFrom: ev.Event.DeliveredFrom,
					Scope:         ev.Event.Scope,
				},
			})
		}
	}
	return out
}
