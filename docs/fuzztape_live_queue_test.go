package docs

import (
	"context"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/stats"
	"github.com/tmc/go-iroh/key"
)

// This machine tests queue bookkeeping, not goroutine interleavings. Operations
// combine duplicate announcements, overflow, provider failures, new providers,
// and completion without requiring a network or a production test hook.
type liveQueueMachine struct {
	live      *LiveSync
	pending   map[blobs.Hash][]key.EndpointID
	queued    []blobs.Hash
	active    *liveDownload
	tried     int
	hashes    []blobs.Hash
	providers []key.EndpointID
}

func liveQueueMachineSpec() fuzztape.Machine[*liveQueueMachine] {
	return fuzztape.Machine[*liveQueueMachine]{
		Name: "FuzzLiveQueueMachine", MaxOps: 32,
		Init: func(t *fuzztape.T) *liveQueueMachine {
			m := &liveQueueMachine{
				live:    &LiveSync{downloads: make(chan liveDownload, 2)},
				pending: make(map[blobs.Hash][]key.EndpointID),
			}
			for i := byte(1); i <= 4; i++ {
				m.hashes = append(m.hashes, blobs.NewHash([]byte{i}))
				m.providers = append(m.providers, key.NewSecretKey(repeat32(i)).Public().EndpointID())
			}
			return m
		},
		Ops: []fuzztape.Op[*liveQueueMachine]{
			{Name: "announce", Apply: func(t *fuzztape.T, m *liveQueueMachine) {
				hash := m.hashes[t.IntN(len(m.hashes))]
				peer := m.providers[t.IntN(len(m.providers))]
				m.live.queueDownload(context.Background(), liveSyncOptions{}, hash, []byte("k"), true, peer)
				providers, present := m.pending[hash]
				if !present {
					m.queued = append(m.queued, hash)
				}
				for _, existing := range providers {
					if existing == peer {
						return
					}
				}
				m.pending[hash] = append(providers, peer)
			}},
			{Name: "take", When: func(m *liveQueueMachine) bool { return m.active == nil && len(m.queued) != 0 }, Apply: func(t *fuzztape.T, m *liveQueueMachine) {
				select {
				case req := <-m.live.downloads:
					if req.Hash != m.queued[0] {
						t.Fatalf("next hash = %s, want %s", req.Hash, m.queued[0])
					}
					m.live.scheduleDownloads()
					m.queued = m.queued[1:]
					m.active, m.tried = &req, 0
				default:
					t.Fatalf("pending work has no ready request")
				}
			}},
			{Name: "failProviders", When: func(m *liveQueueMachine) bool { return m.active != nil }, Apply: func(t *fuzztape.T, m *liveQueueMachine) {
				want := m.pending[m.active.Hash][m.tried:]
				got := m.live.untried(*m.active, m.tried)
				if len(got) != len(want) {
					t.Fatalf("untried providers = %d, want %d", len(got), len(want))
				}
				for i := range want {
					if got[i].ID != want[i] {
						t.Fatalf("untried provider %d differs", i)
					}
				}
				m.tried += len(want)
				if len(want) == 0 {
					delete(m.pending, m.active.Hash)
					m.active = nil
				}
			}},
			{Name: "finish", When: func(m *liveQueueMachine) bool { return m.active != nil }, Apply: func(t *fuzztape.T, m *liveQueueMachine) {
				m.live.forget(*m.active)
				delete(m.pending, m.active.Hash)
				m.active = nil
			}},
		},
		Check: func(t *fuzztape.T, m *liveQueueMachine) {
			if len(m.live.pending) != len(m.pending) {
				t.Fatalf("retained hashes = %d, want %d", len(m.live.pending), len(m.pending))
			}
			for hash, want := range m.pending {
				p := m.live.pending[hash]
				if p == nil {
					t.Fatalf("missing hash %s", hash)
				}
				got := p.snapshot()
				if len(got) != len(want) {
					t.Fatalf("providers for %s = %d, want %d", hash, len(got), len(want))
				}
				for i := range want {
					if got[i].ID != want[i] {
						t.Fatalf("provider %d for %s differs", i, hash)
					}
				}
			}
			ready := min(cap(m.live.downloads), len(m.queued))
			if len(m.live.downloads) != ready || len(m.live.backlog) != len(m.queued)-ready {
				t.Fatalf("ready/backlog = %d/%d, want %d/%d", len(m.live.downloads), len(m.live.backlog), ready, len(m.queued)-ready)
			}
		},
	}
}

// Source seeds give deterministic coverage of all operation kinds before the
// random run. They need no generated corpus files to replay.
var liveQueueMachineSeeds = [][]byte{
	// Announce a hash twice, take it, exhaust its providers, then retry it.
	{0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0},
	// Four distinct hashes overflow the two-element ready queue, then finish one.
	{0, 0, 0, 0, 1, 0, 0, 3, 0, 0, 2, 0, 1, 2},
}

func TestLiveQueueMachine(t *testing.T) {
	m := liveQueueMachineSpec()
	ops, report := stats.Wrap(m.Ops)
	m.Ops = ops
	for _, seed := range liveQueueMachineSeeds {
		m.Replay(t, seed)
	}
	m.Run(t, 100)
	report.Log(t)
	if missing := report.Missing(); len(missing) != 0 {
		t.Fatalf("operations never applied: %v", missing)
	}
}

func FuzzLiveQueueMachine(f *testing.F) {
	for _, seed := range liveQueueMachineSeeds {
		f.Add(seed)
	}
	liveQueueMachineSpec().Fuzz(f)
}
