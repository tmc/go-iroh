package socket

import (
	"net/netip"
	"testing"
	"testing/synctest"

	"github.com/tmc/go-iroh/internal/fuzztape"
)

// The path watcher machine drives a watcher and its live subscriptions from a
// random operation sequence inside a synctest bubble. It asserts nothing: the
// bubble's exit check is the invariant, because it panics if the sequence
// leaves any goroutine durably blocked, and every subscription runs a delivery
// goroutine.
//
// The state that matters is a delivery goroutine parked handing an event to a
// reader that stopped reading. It takes two waves to reach — Send never
// blocks, so one burst outruns delivery, overflows the ring, and collapses
// into a single Lagged event that fits in the channel buffer. The machine
// reaches it without being told: sends outnumber reads, and the
// [synctest.Wait] after every op lets delivery settle in between, so a burst
// that fills the buffer and a later send land in separate waves.

// pathWatcherMachine is the watcher under test plus its live subscriptions.
type pathWatcherMachine struct {
	w    *PathWatcher
	subs []pathWatcherSub
}

// pathWatcherSub is one live subscription.
type pathWatcherSub struct {
	ch     <-chan PathEvent
	cancel func()
}

func newPathWatcherMachine(t *fuzztape.T) *pathWatcherMachine {
	m := &pathWatcherMachine{w: NewPathWatcher()}
	// Close inside the bubble, before its exit check: a subscription that is
	// still live at the end is idle in cond.Wait, which is durably blocked
	// whether or not the watcher leaks.
	t.Cleanup(m.w.Close)
	return m
}

func TestPathWatcherMachine(t *testing.T) {
	pathWatcherMachineSpec().Run(t, 200)
}

func FuzzPathWatcherMachine(f *testing.F) {
	pathWatcherMachineSpec().Fuzz(f)
}

func pathWatcherMachineSpec() fuzztape.Machine[*pathWatcherMachine] {
	addr := IPAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 9))
	kinds := []PathEventKind{PathEventOpened, PathEventClosed, PathEventSelected}
	return fuzztape.Machine[*pathWatcherMachine]{
		Name:   "FuzzPathWatcherMachine",
		Init:   newPathWatcherMachine,
		Bubble: true,
		// Room for a long run of sends; the input length usually ends the
		// sequence first. Every value from 24 up detected the parked
		// goroutine on every seed measured.
		MaxOps: 80,
		Ops: []fuzztape.Op[*pathWatcherMachine]{{
			Name: "subscribe",
			Apply: func(t *fuzztape.T, m *pathWatcherMachine) {
				ch, cancel := m.w.Subscribe()
				m.subs = append(m.subs, pathWatcherSub{ch, cancel})
			},
		}, {
			Name:   "send",
			Weight: 4,
			Apply: func(t *fuzztape.T, m *pathWatcherMachine) {
				m.w.Send(PathEvent{Kind: fuzztape.Pick(t.Tape, kinds), Addr: addr})
			},
		}, {
			Name: "read",
			When: func(m *pathWatcherMachine) bool { return len(m.subs) > 0 },
			Apply: func(t *fuzztape.T, m *pathWatcherMachine) {
				select {
				case <-m.subs[t.IntN(len(m.subs))].ch:
				default:
				}
			},
		}, {
			Name: "cancel",
			When: func(m *pathWatcherMachine) bool { return len(m.subs) > 0 },
			Apply: func(t *fuzztape.T, m *pathWatcherMachine) {
				i := t.IntN(len(m.subs))
				m.subs[i].cancel()
				m.subs = append(m.subs[:i], m.subs[i+1:]...)
			},
		}},
		// Delivery is asynchronous, so without settling between ops a burst
		// never resolves into the buffer-full-then-one-more shape that parks
		// a delivery goroutine.
		Check: func(t *fuzztape.T, m *pathWatcherMachine) { synctest.Wait() },
	}
}
