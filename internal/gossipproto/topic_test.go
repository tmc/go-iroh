package gossipproto

import (
	"reflect"
	"testing"
	"time"
)

func TestTopicStateJoinAndBroadcast(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	state := NewTopicStateWithRand(me, nil, DefaultTopicConfig(), testRand(t))

	got := state.Handle(TopicInEvent{
		Kind: TopicCommandEvent,
		Command: TopicCommand{
			Kind:  TopicCommandJoin,
			Peers: []PeerID{peer},
		},
	})
	if len(got) != 3 {
		t.Fatalf("join len = %d, want 3: %#v", len(got), got)
	}
	wantJoin := TopicOutEvent{
		Kind: TopicSendMessage,
		To:   peer,
		Message: TopicMessage{
			Kind:  TopicMessageSwarm,
			Swarm: HyparviewMessage{Kind: HyparviewJoin},
		},
	}
	if !reflect.DeepEqual(got[0], wantJoin) {
		t.Fatalf("join[0] = %#v, want %#v", got[0], wantJoin)
	}
	if got[1].Kind != TopicScheduleTimer || got[1].Timer.Kind != TopicTimerHyparview || got[1].Timer.Hyparview.Kind != HyparviewTimerDoShuffle {
		t.Fatalf("join[1] = %#v, want DoShuffle timer", got[1])
	}
	if got[2].Kind != TopicScheduleTimer || got[2].Timer.Kind != TopicTimerHyparview || got[2].Timer.Hyparview.Kind != HyparviewTimerDoMaintenance || got[2].After != maintenanceInterval {
		t.Fatalf("join[2] = %#v, want DoMaintenance timer", got[2])
	}

	got = state.Handle(TopicInEvent{
		Kind: TopicRecvMessage,
		From: peer,
		Message: TopicMessage{
			Kind: TopicMessageSwarm,
			Swarm: HyparviewMessage{
				Kind:     HyparviewNeighbor,
				Neighbor: Neighbor{Priority: PriorityHigh},
			},
		},
	})
	if !hasTopicEvent(got, TopicNeighborUp, peer) {
		t.Fatalf("neighbor missing NeighborUp: %#v", got)
	}
	if !hasTopicTimer(got, TopicTimerPlumtree) {
		t.Fatalf("neighbor did not initialize plumtree timer: %#v", got)
	}

	content := []byte("hello")
	id := MessageIDFromContent(content)
	got = state.Handle(TopicInEvent{
		Kind: TopicCommandEvent,
		Now:  time.Unix(1, 0),
		Command: TopicCommand{
			Kind:    TopicCommandBroadcast,
			Content: content,
			Scope:   ScopeSwarm,
		},
	})
	if !hasTopicGossipSend(got, peer, id, content) {
		t.Fatalf("broadcast missing eager gossip send: %#v", got)
	}
	if !hasTopicPlumtreeTimer(got, PlumtreeTimerDispatchLazyPush) {
		t.Fatalf("broadcast missing lazy dispatch timer: %#v", got)
	}
}

func TestStateJoinQuitAndRoute(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	topic := TopicID(seq32(3))
	state := NewStateWithRand(me, nil, DefaultConfig(), testRand(t))

	got := state.Handle(InEvent{
		Kind:  CommandEvent,
		Topic: topic,
		Command: TopicCommand{
			Kind:  TopicCommandJoin,
			Peers: []PeerID{peer},
		},
	})
	if !hasStateSend(got, peer, topic, TopicMessageSwarm) {
		t.Fatalf("join missing swarm send: %#v", got)
	}
	if !hasStateTimer(got, topic, TopicTimerHyparview) {
		t.Fatalf("join missing hyparview timer: %#v", got)
	}
	if !reflect.DeepEqual(state.Topics(), []TopicID{topic}) {
		t.Fatalf("topics = %#v", state.Topics())
	}

	got = state.Handle(InEvent{
		Kind:    CommandEvent,
		Topic:   topic,
		Command: TopicCommand{Kind: TopicCommandQuit},
	})
	if len(got) != 0 {
		t.Fatalf("quit = %#v, want none", got)
	}
	if len(state.Topics()) != 0 {
		t.Fatalf("topics after quit = %#v", state.Topics())
	}
}

func TestStateDisconnectPeerOnlyAfterLastTopic(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	topicA := TopicID(seq32(3))
	topicB := TopicID(seq32(4))
	state := NewStateWithRand(me, nil, DefaultConfig(), testRand(t))
	state.topics[topicA] = NewTopicStateWithRand(me, nil, DefaultTopicConfig(), testRand(t))
	state.topics[topicB] = NewTopicStateWithRand(me, nil, DefaultTopicConfig(), testRand(t))
	state.peerTopics[peer] = map[TopicID]struct{}{topicA: {}, topicB: {}}

	msg := Message{
		Topic: topicA,
		Message: TopicMessage{
			Kind:  TopicMessageSwarm,
			Swarm: HyparviewMessage{Kind: HyparviewForwardJoin, ForwardJoin: ForwardJoin{Peer: PeerInfo{ID: PeerID(seq32(5))}, Ttl: 1}},
		},
	}
	got := state.Handle(InEvent{Kind: RecvMessage, From: peer, Message: msg})
	if hasDisconnect(got, peer) {
		t.Fatalf("disconnect with another topic still live: %#v", got)
	}

	delete(state.peerTopics[peer], topicB)
	got = state.Handle(InEvent{Kind: RecvMessage, From: peer, Message: msg})
	if !hasDisconnect(got, peer) {
		t.Fatalf("missing disconnect after last topic: %#v", got)
	}
}

func TestStateThreadsMaxPayloadSizeToPlumtree(t *testing.T) {
	me := PeerID(seq32(1))
	topic := TopicID(seq32(2))
	state := NewStateWithRand(me, nil, Config{MaxMessageSize: 1}, testRand(t))
	state.Handle(InEvent{
		Kind:  CommandEvent,
		Topic: topic,
		Command: TopicCommand{
			Kind: TopicCommandJoin,
		},
	})
	st := state.topics[topic]
	if st == nil {
		t.Fatal("topic state was not created")
	}
	want := MaxPlumtreeSize(MinMaxMessageSize)
	if got := st.gossip.MaxPayloadSize(); got != want {
		t.Fatalf("MaxPayloadSize = %d, want %d", got, want)
	}
}

func hasDisconnect(events []OutEvent, peer PeerID) bool {
	for _, ev := range events {
		if ev.Kind == DisconnectPeer && ev.To == peer {
			return true
		}
	}
	return false
}

func hasTopicEvent(events []TopicOutEvent, kind TopicEventKind, peer PeerID) bool {
	for _, ev := range events {
		if ev.Kind == TopicEmitEvent && ev.Event.Kind == kind && ev.Event.Peer == peer {
			return true
		}
	}
	return false
}

func hasTopicTimer(events []TopicOutEvent, kind TopicTimerKind) bool {
	for _, ev := range events {
		if ev.Kind == TopicScheduleTimer && ev.Timer.Kind == kind {
			return true
		}
	}
	return false
}

func hasTopicPlumtreeTimer(events []TopicOutEvent, kind PlumtreeTimerKind) bool {
	for _, ev := range events {
		if ev.Kind == TopicScheduleTimer && ev.Timer.Kind == TopicTimerPlumtree && ev.Timer.Plumtree.Kind == kind {
			return true
		}
	}
	return false
}

func hasTopicGossipSend(events []TopicOutEvent, peer PeerID, id MessageID, content []byte) bool {
	for _, ev := range events {
		if ev.Kind != TopicSendMessage || ev.To != peer || ev.Message.Kind != TopicMessageGossip {
			continue
		}
		g := ev.Message.Gossip
		if g.Kind == PlumtreeGossip && g.Gossip.ID == id && reflect.DeepEqual(g.Gossip.Content, content) {
			return true
		}
	}
	return false
}

func hasStateSend(events []OutEvent, peer PeerID, topic TopicID, kind TopicMessageKind) bool {
	for _, ev := range events {
		if ev.Kind == SendMessage && ev.To == peer && ev.Message.Topic == topic && ev.Message.Message.Kind == kind {
			return true
		}
	}
	return false
}

func hasStateTimer(events []OutEvent, topic TopicID, kind TopicTimerKind) bool {
	for _, ev := range events {
		if ev.Kind == ScheduleTimer && ev.Timer.Topic == topic && ev.Timer.Timer.Kind == kind {
			return true
		}
	}
	return false
}
