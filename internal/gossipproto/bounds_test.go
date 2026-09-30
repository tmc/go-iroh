package gossipproto

import (
	"encoding/binary"
	"testing"
	"time"
)

// TestHyparviewPeerDataBounded pins that peers named in shuffles do not
// leave their data behind once the passive view evicts them.
func TestHyparviewPeerDataBounded(t *testing.T) {
	me := PeerID(seq32(1))
	from := PeerID(seq32(2))
	config := DefaultHyparviewConfig()
	state := NewHyparviewStateWithRand(me, nil, config, testRand(t))

	for i := range 100 {
		var nodes []PeerInfo
		for j := range 10 {
			var id PeerID
			binary.BigEndian.PutUint32(id[:], uint32(i*10+j+100))
			nodes = append(nodes, PeerInfo{ID: id, Data: &PeerData{1}})
		}
		state.Handle(HyparviewInEvent{
			Kind: HyparviewRecvMessage,
			From: from,
			Message: HyparviewMessage{
				Kind:    HyparviewShuffle,
				Shuffle: Shuffle{Origin: from, Nodes: nodes},
			},
		})
	}
	if n, max := len(state.peerData), config.ActiveViewCapacity+config.PassiveViewCapacity; n > max {
		t.Fatalf("peer data for %d peers, want at most %d", n, max)
	}
}

// TestHyparviewPeerDataOnlyForKnownPeers pins that, under any churn, peer
// data is kept only for peers in a view or awaiting a Neighbor reply.
func TestHyparviewPeerDataOnlyForKnownPeers(t *testing.T) {
	r := testRand(t)
	me := PeerID(seq32(1))
	state := NewHyparviewStateWithRand(me, nil, DefaultHyparviewConfig(), r)
	peer := func() PeerID {
		var id PeerID
		binary.BigEndian.PutUint32(id[:], uint32(r.Intn(200)+100))
		return id
	}
	info := func() PeerInfo { return PeerInfo{ID: peer(), Data: &PeerData{1}} }
	recv := func(m HyparviewMessage) HyparviewInEvent {
		return HyparviewInEvent{Kind: HyparviewRecvMessage, From: peer(), Message: m}
	}
	for i := range 20000 {
		var ev HyparviewInEvent
		switch r.Intn(8) {
		case 0:
			ev = recv(HyparviewMessage{Kind: HyparviewJoin, Join: &PeerData{1}})
		case 1:
			ev = recv(HyparviewMessage{Kind: HyparviewForwardJoin, ForwardJoin: ForwardJoin{Peer: info(), Ttl: Ttl(r.Intn(7))}})
		case 2:
			ev = recv(HyparviewMessage{Kind: HyparviewShuffle, Shuffle: Shuffle{Origin: peer(), Nodes: []PeerInfo{info(), info()}}})
		case 3:
			ev = recv(HyparviewMessage{Kind: HyparviewNeighbor, Neighbor: Neighbor{Priority: Priority(r.Intn(2)), Data: &PeerData{1}}})
		case 4:
			ev = recv(HyparviewMessage{Kind: HyparviewDisconnect, Disconnect: Disconnect{Alive: r.Intn(2) == 0}})
		case 5:
			ev = HyparviewInEvent{Kind: HyparviewPeerDisconnected, Peer: peer()}
		case 6:
			ev = HyparviewInEvent{Kind: HyparviewTimerExpired, Timer: HyparviewTimer{Kind: HyparviewTimerPendingNeighborRequest, Peer: peer()}}
		case 7:
			ev = HyparviewInEvent{Kind: HyparviewTimerExpired, Timer: HyparviewTimer{Kind: HyparviewTimerDoShuffle}}
		}
		state.Handle(ev)
		for id := range state.peerData {
			_, pending := state.pendingNeighbor[id]
			if !state.active.contains(id) && !state.passive.contains(id) && !pending {
				t.Fatalf("event %d (%+v): peer data kept for %x, which is in no view", i, ev, id[:4])
			}
		}
	}
}

// TestPlumtreeMissingBounded pins that one peer's IHaves, repeated or for
// made-up messages, cannot grow the missing set without limit or crowd out
// another peer's.
func TestPlumtreeMissingBounded(t *testing.T) {
	now := time.Unix(1, 0)
	me := PeerID(seq32(1))
	bad := PeerID(seq32(2))
	good := PeerID(seq32(3))
	state := NewPlumtreeState(me, DefaultPlumtreeConfig())
	ihave := func(from PeerID, ihaves []IHave) {
		state.Handle(PlumtreeInEvent{
			Kind:    PlumtreeRecvMessage,
			From:    from,
			Now:     now,
			Message: PlumtreeMessage{Kind: PlumtreeIHave, IHave: ihaves},
		})
	}

	repeated := MessageIDFromContent([]byte("repeated"))
	for range 1000 {
		ihave(bad, []IHave{{ID: repeated}})
	}
	if n := len(state.missing[repeated]); n != 1 {
		t.Fatalf("targets for a repeated IHave = %d, want 1", n)
	}

	for i := range 4 * maxMissingPerPeer {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		ihave(bad, []IHave{{ID: MessageIDFromContent(b[:])}})
	}
	if n := len(state.missing); n > maxMissingPerPeer {
		t.Fatalf("missing messages = %d, want at most %d", n, maxMissingPerPeer)
	}
	if n := len(state.graftTimerScheduled); n > maxMissingPerPeer {
		t.Fatalf("graft timers = %d, want at most %d", n, maxMissingPerPeer)
	}

	id := MessageIDFromContent([]byte("from good"))
	ihave(good, []IHave{{ID: id}})
	if n := len(state.missing[id]); n != 1 {
		t.Fatalf("targets for another peer's IHave = %d, want 1", n)
	}

	for p := range 2 * maxMissing / maxMissingPerPeer {
		from := PeerID(seq32(byte(10 + p)))
		for i := range maxMissingPerPeer {
			var b [16]byte
			binary.BigEndian.PutUint64(b[:], uint64(p))
			binary.BigEndian.PutUint64(b[8:], uint64(i))
			ihave(from, []IHave{{ID: MessageIDFromContent(b[:])}})
		}
	}
	if n := len(state.missing); n > maxMissing {
		t.Fatalf("missing messages from many peers = %d, want at most %d", n, maxMissing)
	}
}

// TestHyparviewPendingBounded pins that peers joining and being evicted do
// not leave Neighbor replies pending.
func TestHyparviewPendingBounded(t *testing.T) {
	config := DefaultHyparviewConfig()
	state := NewHyparviewStateWithRand(PeerID(seq32(1)), nil, config, testRand(t))
	for i := range 1000 {
		var from PeerID
		binary.BigEndian.PutUint32(from[:], uint32(i+100))
		state.Handle(HyparviewInEvent{
			Kind:    HyparviewRecvMessage,
			From:    from,
			Message: HyparviewMessage{Kind: HyparviewJoin, Join: &PeerData{1}},
		})
	}
	if n := len(state.pendingNeighbor); n > config.ActiveViewCapacity {
		t.Fatalf("pending Neighbor replies = %d, want at most %d", n, config.ActiveViewCapacity)
	}
}

// TestPlumtreeTargetsBounded pins that many peers announcing the same
// messages, or announcing and leaving, cannot grow the targets or the graft
// timers past maxMissing.
func TestPlumtreeTargetsBounded(t *testing.T) {
	now := time.Unix(1, 0)
	state := NewPlumtreeState(PeerID(seq32(1)), DefaultPlumtreeConfig())
	peer := func(i int) PeerID {
		var id PeerID
		binary.BigEndian.PutUint32(id[:], uint32(i+100))
		return id
	}
	id := func(i int) MessageID {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(i))
		return MessageIDFromContent(b[:])
	}
	ihave := func(from PeerID, ihaves []IHave) {
		state.Handle(PlumtreeInEvent{
			Kind:    PlumtreeRecvMessage,
			From:    from,
			Now:     now,
			Message: PlumtreeMessage{Kind: PlumtreeIHave, IHave: ihaves},
		})
	}

	for p := range 2 * maxMissing {
		ihave(peer(p), []IHave{{ID: id(0)}})
	}
	if n := len(state.missing[id(0)]); n > maxMissing {
		t.Fatalf("targets for one message = %d, want at most %d", n, maxMissing)
	}

	for p := range 4 * maxMissing / maxMissingPerPeer {
		from := peer(p)
		for i := range maxMissingPerPeer {
			ihave(from, []IHave{{ID: id(p*maxMissingPerPeer + i + 1)}})
		}
		state.Handle(PlumtreeInEvent{Kind: PlumtreeNeighborDown, Neighbor: from, Now: now})
	}
	if n := len(state.graftTimerScheduled); n > maxMissing {
		t.Fatalf("graft timers = %d, want at most %d", n, maxMissing)
	}
}
