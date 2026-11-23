package gossipproto

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func assertInitialTimers(t *testing.T, got []HyparviewOutEvent) []HyparviewOutEvent {
	t.Helper()
	if len(got) < 2 {
		t.Fatalf("missing initial timers in %#v", got)
	}
	shuf := got[len(got)-2]
	maint := got[len(got)-1]
	if shuf.Kind != HyparviewScheduleTimer || shuf.Timer.Kind != HyparviewTimerDoShuffle {
		t.Fatalf("expected DoShuffle timer, got %#v", shuf)
	}
	if shuf.After < 750*time.Millisecond || shuf.After > 1250*time.Millisecond {
		t.Fatalf("initial shuffle delay = %v, want in [750ms, 1250ms]", shuf.After)
	}
	if maint.Kind != HyparviewScheduleTimer || maint.Timer.Kind != HyparviewTimerDoMaintenance || maint.After != maintenanceInterval {
		t.Fatalf("expected DoMaintenance timer after %v, got %#v", maintenanceInterval, maint)
	}
	return got[:len(got)-2]
}

func TestHyparviewRequestJoin(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	data := PeerData{1, 2, 3}
	state := NewHyparviewStateWithRand(me, &data, DefaultHyparviewConfig(), testRand(t))

	got := assertInitialTimers(t, state.Handle(HyparviewInEvent{Kind: HyparviewRequestJoin, Peer: peer}))
	wantData := data
	want := []HyparviewOutEvent{
		{
			Kind:    HyparviewSendMessage,
			To:      peer,
			Message: HyparviewMessage{Kind: HyparviewJoin, Join: &wantData},
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

	got := assertInitialTimers(t, state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: joiner,
		Message: HyparviewMessage{
			Kind: HyparviewJoin,
			Join: &data,
		},
	}))
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

	got := assertInitialTimers(t, state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: sender,
		Message: HyparviewMessage{
			Kind: HyparviewForwardJoin,
			ForwardJoin: ForwardJoin{
				Peer: PeerInfo{ID: joining, Data: &data},
				Ttl:  config.PassiveRandomWalkLength,
			},
		},
	}))
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

	got := assertInitialTimers(t, state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: from,
		Message: HyparviewMessage{
			Kind:     HyparviewNeighbor,
			Neighbor: Neighbor{Priority: PriorityLow},
		},
	}))
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

	got := assertInitialTimers(t, state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: joiner,
		Message: HyparviewMessage{
			Kind: HyparviewJoin,
		},
	}))
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

	got := assertInitialTimers(t, state.Handle(HyparviewInEvent{
		Kind: HyparviewRecvMessage,
		From: peer,
		Message: HyparviewMessage{
			Kind:       HyparviewDisconnect,
			Disconnect: Disconnect{Alive: true},
		},
	}))
	want := []HyparviewOutEvent{
		{Kind: HyparviewEmitEvent, Event: HyparviewEvent{Kind: HyparviewNeighborDown, Peer: peer}},
		{Kind: HyparviewDisconnectPeer, To: peer},
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
	state.timersScheduled = true

	got := state.Handle(HyparviewInEvent{
		Kind:  HyparviewTimerExpired,
		Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle},
	})
	if len(got) != 2 {
		t.Fatalf("shuffle len = %d, want 2: %#v", len(got), got)
	}
	wantSend := HyparviewOutEvent{
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
	}
	if !reflect.DeepEqual(got[0], wantSend) {
		t.Fatalf("shuffle[0] = %#v, want %#v", got[0], wantSend)
	}
	if got[1].Kind != HyparviewScheduleTimer || got[1].Timer.Kind != HyparviewTimerDoShuffle {
		t.Fatalf("shuffle[1] = %#v, want DoShuffle timer", got[1])
	}
	if got[1].After < 750*time.Millisecond || got[1].After > 1250*time.Millisecond {
		t.Fatalf("shuffle[1].After = %v, want in [750ms, 1250ms]", got[1].After)
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
	state.timersScheduled = true

	got := state.Handle(HyparviewInEvent{
		Kind:  HyparviewTimerExpired,
		Timer: HyparviewTimer{Kind: HyparviewTimerPendingNeighborRequest, Peer: missed},
	})
	want := []HyparviewOutEvent{
		{Kind: HyparviewDisconnectPeer, To: missed},
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
	state.timersScheduled = true

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

// TestHyparviewForwardJoinFromPendingPeerAnswersAgain checks that a
// ForwardJoin naming a peer with a Neighbor answer still pending is handled
// as if nothing were pending: answered where the walk ends, forwarded
// elsewhere. The ForwardJoin comes from a Join the peer sent from fresh topic
// state, so the earlier answer may have gone to state the peer has dropped.
func TestHyparviewForwardJoinFromPendingPeerAnswersAgain(t *testing.T) {
	me := PeerID(seq32(1))
	sender := PeerID(seq32(2))
	next := PeerID(seq32(3))
	joining := PeerID(seq32(4))
	config := DefaultHyparviewConfig()
	answer := HyparviewOutEvent{
		Kind: HyparviewSendMessage,
		To:   joining,
		Message: HyparviewMessage{
			Kind:     HyparviewNeighbor,
			Neighbor: Neighbor{Priority: PriorityHigh},
		},
	}
	forward := HyparviewOutEvent{
		Kind: HyparviewSendMessage,
		To:   next,
		Message: HyparviewMessage{
			Kind: HyparviewForwardJoin,
			ForwardJoin: ForwardJoin{
				Peer: PeerInfo{ID: joining},
				Ttl:  config.ActiveRandomWalkLength - 1,
			},
		},
	}
	tests := []struct {
		name   string
		active []PeerID
		ttl    Ttl
		want   []HyparviewOutEvent
	}{
		{"walk end", []PeerID{sender, next}, 0, []HyparviewOutEvent{answer}},
		{"lone neighbor", []PeerID{sender}, config.ActiveRandomWalkLength, []HyparviewOutEvent{answer}},
		{"active", []PeerID{sender, next, joining}, config.ActiveRandomWalkLength, []HyparviewOutEvent{answer}},
		{"forward", []PeerID{sender, next}, config.ActiveRandomWalkLength, []HyparviewOutEvent{forward}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewHyparviewStateWithRand(me, nil, config, testRand(t))
			state.timersScheduled = true
			for _, p := range tt.active {
				state.active.insert(p)
			}
			state.pendingNeighbor[joining] = struct{}{}

			got := state.Handle(HyparviewInEvent{
				Kind: HyparviewRecvMessage,
				From: sender,
				Message: HyparviewMessage{
					Kind:        HyparviewForwardJoin,
					ForwardJoin: ForwardJoin{Peer: PeerInfo{ID: joining}, Ttl: tt.ttl},
				},
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("forward join = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestHyparviewEarlyShuffleDoublesWithJitter(t *testing.T) {
	me := PeerID(seq32(1))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), rand.New(rand.NewSource(7)))

	wantBase := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		60 * time.Second,
		60 * time.Second,
	}
	for i, base := range wantBase {
		var out []HyparviewOutEvent
		if i == 0 {
			out = state.Handle(HyparviewInEvent{Kind: HyparviewRequestJoin, Peer: PeerID(seq32(2))})
		} else {
			out = state.Handle(HyparviewInEvent{
				Kind:  HyparviewTimerExpired,
				Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle},
			})
		}
		var delay time.Duration
		found := false
		for _, ev := range out {
			if ev.Kind == HyparviewScheduleTimer && ev.Timer.Kind == HyparviewTimerDoShuffle {
				delay = ev.After
				found = true
			}
		}
		if !found {
			t.Fatalf("step %d: missing DoShuffle timer", i)
		}
		lo := time.Duration(float64(base) * 0.75)
		hi := time.Duration(float64(base) * 1.25)
		if delay < lo || delay > hi {
			t.Fatalf("step %d: shuffle delay = %v, want in [%v, %v]", i, delay, lo, hi)
		}
	}
}

func TestHyparviewRejoinWhenAloneBackoff(t *testing.T) {
	me := PeerID(seq32(1))
	boot := PeerID(seq32(2))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), testRand(t))
	state.Handle(HyparviewInEvent{Kind: HyparviewRequestJoin, Peer: boot})

	// Expect rejoins on passes 1, 2, 4, 8, 12, 24.
	wantPasses := map[int]bool{1: true, 2: true, 4: true, 8: true, 12: true, 24: true}
	for pass := 1; pass <= 24; pass++ {
		out := state.Handle(HyparviewInEvent{
			Kind:  HyparviewTimerExpired,
			Timer: HyparviewTimer{Kind: HyparviewTimerDoMaintenance},
		})
		joined := false
		for _, ev := range out {
			if ev.Kind == HyparviewSendMessage && ev.To == boot && ev.Message.Kind == HyparviewJoin {
				joined = true
			}
		}
		if joined != wantPasses[pass] {
			t.Fatalf("pass %d: rejoined=%v, want %v", pass, joined, wantPasses[pass])
		}
	}
}

func TestHyparviewRefillAfterFailedDial(t *testing.T) {
	me := PeerID(seq32(1))
	active := PeerID(seq32(2))
	p1 := PeerID(seq32(3))
	p2 := PeerID(seq32(4))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), rand.New(rand.NewSource(1)))
	state.timersScheduled = true
	state.active.insert(active)
	state.passive.insert(p1)
	state.passive.insert(p2)
	state.pendingNeighbor[p1] = struct{}{}

	got := state.Handle(HyparviewInEvent{Kind: HyparviewPeerDisconnected, Peer: p1})
	sentP2 := false
	for _, ev := range got {
		if ev.Kind == HyparviewSendMessage && ev.To == p2 && ev.Message.Kind == HyparviewNeighbor {
			sentP2 = true
		}
	}
	if !sentP2 {
		t.Fatalf("failed dial did not refill from remaining passive peer: %#v", got)
	}
}

func TestHyparviewKeepsConnWhileNeighborReplyDue(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), testRand(t))
	state.timersScheduled = true
	state.pendingNeighbor[peer] = struct{}{}

	got := state.Handle(HyparviewInEvent{
		Kind:    HyparviewRecvMessage,
		From:    peer,
		Message: HyparviewMessage{Kind: HyparviewShuffleReply},
	})
	for _, ev := range got {
		if ev.Kind == HyparviewDisconnectPeer && ev.To == peer {
			t.Fatalf("disconnected peer while Neighbor reply was due: %#v", got)
		}
	}
}

func TestHyparviewRefillBackoffAndLimit(t *testing.T) {
	me := PeerID(seq32(1))
	active := PeerID(seq32(2))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), rand.New(rand.NewSource(1)))
	state.timersScheduled = true
	state.active.insert(active)
	for i := range 10 {
		state.passive.insert(PeerID(seq32(byte(10 + i))))
	}

	// Refuse a neighbor request: sends ShuffleReply + Disconnect{Alive: true}.
	refuse := func(target PeerID) []HyparviewOutEvent {
		out := state.Handle(HyparviewInEvent{
			Kind:    HyparviewRecvMessage,
			From:    target,
			Message: HyparviewMessage{Kind: HyparviewShuffleReply},
		})
		out = append(out, state.Handle(HyparviewInEvent{
			Kind:    HyparviewRecvMessage,
			From:    target,
			Message: HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: true}},
		})...)
		return out
	}

	neighborTarget := func(events []HyparviewOutEvent) (PeerID, bool) {
		for _, ev := range events {
			if ev.Kind == HyparviewSendMessage && ev.Message.Kind == HyparviewNeighbor {
				return ev.To, true
			}
		}
		return PeerID{}, false
	}

	// Maintenance pass 1 is due: should send at most maxRequestsPerRefill (3) requests even when all refuse.
	out := state.Handle(HyparviewInEvent{
		Kind:  HyparviewTimerExpired,
		Timer: HyparviewTimer{Kind: HyparviewTimerDoMaintenance},
	})
	sent := 0
	for {
		target, ok := neighborTarget(out)
		if !ok {
			break
		}
		sent++
		if sent > maxRequestsPerRefill+1 {
			t.Fatalf("refill exceeded limit %d", maxRequestsPerRefill)
		}
		out = refuse(target)
	}
	if sent != maxRequestsPerRefill {
		t.Fatalf("pass 1 sent %d neighbor requests, want %d", sent, maxRequestsPerRefill)
	}

	// Pass 2 is due; pass 3 is skipped by backoff; pass 4 is due.
	wantDue := map[int]bool{2: true, 3: false, 4: true, 5: false}
	for pass := 2; pass <= 5; pass++ {
		out = state.Handle(HyparviewInEvent{
			Kind:  HyparviewTimerExpired,
			Timer: HyparviewTimer{Kind: HyparviewTimerDoMaintenance},
		})
		target, ok := neighborTarget(out)
		if ok != wantDue[pass] {
			t.Fatalf("pass %d: started refill=%v, want %v", pass, ok, wantDue[pass])
		}
		for ok {
			out = refuse(target)
			target, ok = neighborTarget(out)
		}
	}
}

func TestHyparviewRecoveryRefillUnlimited(t *testing.T) {
	me := PeerID(seq32(1))
	keep := PeerID(seq32(2))
	lost := PeerID(seq32(3))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), rand.New(rand.NewSource(1)))
	state.timersScheduled = true
	state.active.insert(keep)
	state.active.insert(lost)
	for i := range 6 {
		state.passive.insert(PeerID(seq32(byte(10 + i))))
	}

	// Losing a neighbor starts an unlimited recovery refill.
	out := state.Handle(HyparviewInEvent{Kind: HyparviewPeerDisconnected, Peer: lost})
	asked := 0
	for {
		var target PeerID
		found := false
		for _, ev := range out {
			if ev.Kind == HyparviewSendMessage && ev.Message.Kind == HyparviewNeighbor {
				target = ev.To
				found = true
				break
			}
		}
		if !found {
			break
		}
		asked++
		out = state.Handle(HyparviewInEvent{
			Kind:    HyparviewRecvMessage,
			From:    target,
			Message: HyparviewMessage{Kind: HyparviewShuffleReply},
		})
		out = append(out, state.Handle(HyparviewInEvent{
			Kind:    HyparviewRecvMessage,
			From:    target,
			Message: HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: true}},
		})...)
	}
	if asked != 6 {
		t.Fatalf("recovery asked %d passive peers, want all 6", asked)
	}
}
