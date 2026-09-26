package gossipproto

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func TestHyparviewRequestJoin(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	data := PeerData{1, 2, 3}
	state := NewHyparviewStateWithRand(me, &data, DefaultHyparviewConfig(), testRand(t))

	got := state.Handle(HyparviewInEvent{Kind: HyparviewRequestJoin, Peer: peer})
	wantData := data
	want := []HyparviewOutEvent{
		{
			Kind:    HyparviewSendMessage,
			To:      peer,
			Message: HyparviewMessage{Kind: HyparviewJoin, Join: &wantData},
		},
		{
			Kind:  HyparviewScheduleTimer,
			After: time.Minute,
			Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Handle = %#v, want %#v", got, want)
	}
}

func TestHyparviewJoinAddsActiveAndForwards(t *testing.T) {
	me := PeerID(seq32(1))
	joiner := PeerID(seq32(2))
	existing := PeerID(seq32(3))
	data := PeerData{4, 5}
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), rand.New(rand.NewSource(1)))
	state.active.insert(existing)

	got := state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: joiner,
		Message: HyparviewMessage{
			Kind: HyparviewJoin,
			Join: &data,
		},
	})
	wantData := data
	want := []HyparviewOutEvent{
		{Kind: HyparviewPeerData, To: joiner, Data: &wantData},
		{Kind: HyparviewEmitEvent, Event: HyparviewEvent{Kind: HyparviewNeighborUp, Peer: joiner}},
		{
			Kind: HyparviewSendMessage,
			To:   joiner,
			Message: HyparviewMessage{
				Kind:     HyparviewNeighbor,
				Neighbor: Neighbor{Priority: PriorityHigh},
			},
		},
		{
			Kind: HyparviewSendMessage,
			To:   existing,
			Message: HyparviewMessage{
				Kind: HyparviewForwardJoin,
				ForwardJoin: ForwardJoin{
					Peer: PeerInfo{ID: joiner, Data: &wantData},
					Ttl:  DefaultHyparviewConfig().ActiveRandomWalkLength,
				},
			},
		},
		{
			Kind:  HyparviewScheduleTimer,
			After: time.Minute,
			Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Handle = %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(state.ActivePeers(), []PeerID{existing, joiner}) {
		t.Fatalf("active = %#v", state.ActivePeers())
	}
}

func TestHyparviewForwardJoin(t *testing.T) {
	me := PeerID(seq32(1))
	sender := PeerID(seq32(2))
	next := PeerID(seq32(3))
	joining := PeerID(seq32(4))
	data := PeerData{9}
	config := DefaultHyparviewConfig()
	state := NewHyparviewStateWithRand(me, nil, config, testRand(t))
	state.active.insert(sender)
	state.active.insert(next)

	got := state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: sender,
		Message: HyparviewMessage{
			Kind: HyparviewForwardJoin,
			ForwardJoin: ForwardJoin{
				Peer: PeerInfo{ID: joining, Data: &data},
				Ttl:  config.PassiveRandomWalkLength,
			},
		},
	})
	wantData := data
	want := []HyparviewOutEvent{
		{Kind: HyparviewPeerData, To: joining, Data: &wantData},
		{
			Kind: HyparviewSendMessage,
			To:   next,
			Message: HyparviewMessage{
				Kind: HyparviewForwardJoin,
				ForwardJoin: ForwardJoin{
					Peer: PeerInfo{ID: joining, Data: &wantData},
					Ttl:  config.PassiveRandomWalkLength - 1,
				},
			},
		},
		{Kind: HyparviewScheduleTimer, After: time.Minute, Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("forward = %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(state.PassivePeers(), []PeerID{joining}) {
		t.Fatalf("passive = %#v", state.PassivePeers())
	}
}

func TestHyparviewNeighborRefusalDisconnects(t *testing.T) {
	me := PeerID(seq32(1))
	active := PeerID(seq32(2))
	from := PeerID(seq32(3))
	config := DefaultHyparviewConfig()
	config.ActiveViewCapacity = 1
	state := NewHyparviewStateWithRand(me, nil, config, testRand(t))
	state.active.insert(active)

	got := state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: from,
		Message: HyparviewMessage{
			Kind:     HyparviewNeighbor,
			Neighbor: Neighbor{Priority: PriorityLow},
		},
	})
	want := []HyparviewOutEvent{
		{
			Kind: HyparviewSendMessage,
			To:   from,
			Message: HyparviewMessage{
				Kind:         HyparviewShuffleReply,
				ShuffleReply: ShuffleReply{Nodes: []PeerInfo{{ID: active}}},
			},
		},
		{
			Kind:    HyparviewSendMessage,
			To:      from,
			Message: HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: true}},
		},
		{Kind: HyparviewDisconnectPeer, To: from},
		{Kind: HyparviewDisconnectPeer, To: from},
		{Kind: HyparviewScheduleTimer, After: time.Minute, Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("neighbor = %#v, want %#v", got, want)
	}
}

func TestHyparviewHighPriorityJoinEvictsActive(t *testing.T) {
	me := PeerID(seq32(1))
	old := PeerID(seq32(2))
	joiner := PeerID(seq32(3))
	passive := PeerID(seq32(4))
	config := DefaultHyparviewConfig()
	config.ActiveViewCapacity = 1
	state := NewHyparviewStateWithRand(me, nil, config, testRand(t))
	state.active.insert(old)
	state.passive.insert(passive)

	got := state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: joiner,
		Message: HyparviewMessage{
			Kind: HyparviewJoin,
		},
	})
	want := []HyparviewOutEvent{
		{Kind: HyparviewEmitEvent, Event: HyparviewEvent{Kind: HyparviewNeighborDown, Peer: old}},
		{
			Kind:    HyparviewSendMessage,
			To:      old,
			Message: HyparviewMessage{Kind: HyparviewShuffleReply, ShuffleReply: ShuffleReply{Nodes: []PeerInfo{{ID: passive}}}},
		},
		{
			Kind:    HyparviewSendMessage,
			To:      old,
			Message: HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: true}},
		},
		{Kind: HyparviewDisconnectPeer, To: old},
		{Kind: HyparviewEmitEvent, Event: HyparviewEvent{Kind: HyparviewNeighborUp, Peer: joiner}},
		{
			Kind: HyparviewSendMessage,
			To:   joiner,
			Message: HyparviewMessage{
				Kind:     HyparviewNeighbor,
				Neighbor: Neighbor{Priority: PriorityHigh},
			},
		},
		{Kind: HyparviewScheduleTimer, After: time.Minute, Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("join = %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(state.ActivePeers(), []PeerID{joiner}) {
		t.Fatalf("active = %#v", state.ActivePeers())
	}
	if state.isPending(passive) {
		t.Fatalf("eviction unexpectedly refilled active view from passive peer")
	}
}

func TestHyparviewDisconnectKeepsAlivePeerPassive(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), testRand(t))
	state.active.insert(peer)

	got := state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: peer,
		Message: HyparviewMessage{
			Kind:       HyparviewDisconnect,
			Disconnect: Disconnect{Alive: true},
		},
	})
	want := []HyparviewOutEvent{
		{Kind: HyparviewEmitEvent, Event: HyparviewEvent{Kind: HyparviewNeighborDown, Peer: peer}},
		{Kind: HyparviewDisconnectPeer, To: peer},
		{Kind: HyparviewScheduleTimer, After: time.Minute, Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("disconnect = %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(state.PassivePeers(), []PeerID{peer}) {
		t.Fatalf("passive = %#v", state.PassivePeers())
	}

	got = state.Handle(HyparviewInEvent{Kind: HyparviewPeerDisconnected, Peer: peer})
	if len(got) != 0 {
		t.Fatalf("connection closed = %#v, want none", got)
	}
	if !reflect.DeepEqual(state.PassivePeers(), []PeerID{peer}) {
		t.Fatalf("passive after close = %#v", state.PassivePeers())
	}
}

func TestHyparviewShuffleTimer(t *testing.T) {
	me := PeerID(seq32(1))
	active := PeerID(seq32(2))
	other := PeerID(seq32(3))
	passive := PeerID(seq32(4))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), rand.New(rand.NewSource(1)))
	state.active.insert(active)
	state.active.insert(other)
	state.passive.insert(passive)
	state.shuffleScheduled = true

	got := state.Handle(HyparviewInEvent{
		Kind:  HyparviewTimerExpired,
		Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle},
	})
	want := []HyparviewOutEvent{
		{
			Kind: HyparviewSendMessage,
			To:   other,
			Message: HyparviewMessage{
				Kind: HyparviewShuffle,
				Shuffle: Shuffle{
					Origin: me,
					Nodes:  []PeerInfo{{ID: active}, {ID: passive}, {ID: me}},
					Ttl:    DefaultHyparviewConfig().ShuffleRandomWalkLength,
				},
			},
		},
		{Kind: HyparviewScheduleTimer, After: time.Minute, Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shuffle = %#v, want %#v", got, want)
	}
}

func TestHyparviewRandomSelectionCanPickNonFirst(t *testing.T) {
	peers := peerList{
		PeerID(seq32(1)),
		PeerID(seq32(2)),
		PeerID(seq32(3)),
	}
	r := rand.New(rand.NewSource(1))
	got, ok := peers.random(r)
	if !ok {
		t.Fatal("random returned no peer")
	}
	if got == peers[0] {
		t.Fatalf("random selected first peer with seed 1")
	}

	r = rand.New(rand.NewSource(1))
	got, ok = peers.randomWithout(r, peers[2])
	if !ok {
		t.Fatal("randomWithout returned no peer")
	}
	if got == peers[0] {
		t.Fatalf("randomWithout selected first eligible peer with seed 1")
	}
}

func TestHyparviewPendingNeighborTimerRefills(t *testing.T) {
	me := PeerID(seq32(1))
	missed := PeerID(seq32(2))
	next := PeerID(seq32(3))
	config := DefaultHyparviewConfig()
	config.ActiveViewCapacity = 1
	state := NewHyparviewStateWithRand(me, nil, config, testRand(t))
	state.passive.insert(missed)
	state.passive.insert(next)
	state.pendingNeighbor[missed] = struct{}{}
	state.shuffleScheduled = true

	got := state.Handle(HyparviewInEvent{
		Kind:  HyparviewTimerExpired,
		Timer: HyparviewTimer{Kind: HyparviewTimerPendingNeighborRequest, Peer: missed},
	})
	want := []HyparviewOutEvent{
		{
			Kind: HyparviewSendMessage,
			To:   next,
			Message: HyparviewMessage{
				Kind:     HyparviewNeighbor,
				Neighbor: Neighbor{Priority: PriorityHigh},
			},
		},
		{
			Kind:  HyparviewScheduleTimer,
			After: 500 * time.Millisecond,
			Timer: HyparviewTimer{Kind: HyparviewTimerPendingNeighborRequest, Peer: next},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pending timer = %#v, want %#v", got, want)
	}
	if state.passive.contains(missed) {
		t.Fatalf("missed peer still passive")
	}
}

// TestHyparviewJoinFromPendingPeerAnswersAgain checks that a Join from a peer
// that is already active, with a Neighbor answer still pending, is answered
// again. The peer sends Join from fresh topic state; if it quit before the
// first answer arrived, that answer is lost and nothing else clears the
// pending mark.
func TestHyparviewJoinFromPendingPeerAnswersAgain(t *testing.T) {
	me := PeerID(seq32(1))
	joiner := PeerID(seq32(2))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), testRand(t))
	state.shuffleScheduled = true

	join := HyparviewInEvent{
		Kind:    HyparviewRecvMessage,
		From:    joiner,
		Message: HyparviewMessage{Kind: HyparviewJoin},
	}
	answer := HyparviewOutEvent{
		Kind: HyparviewSendMessage,
		To:   joiner,
		Message: HyparviewMessage{
			Kind:     HyparviewNeighbor,
			Neighbor: Neighbor{Priority: PriorityHigh},
		},
	}
	tests := []struct {
		name string
		want []HyparviewOutEvent
	}{
		{"first", []HyparviewOutEvent{
			{Kind: HyparviewEmitEvent, Event: HyparviewEvent{Kind: HyparviewNeighborUp, Peer: joiner}},
			answer,
		}},
		{"again", []HyparviewOutEvent{answer}},
	}
	for _, tt := range tests {
		got := state.Handle(join)
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%s join = %#v, want %#v", tt.name, got, tt.want)
		}
		if !state.isPending(joiner) {
			t.Fatalf("%s join: answer not pending", tt.name)
		}
	}
}
