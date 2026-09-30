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
}
