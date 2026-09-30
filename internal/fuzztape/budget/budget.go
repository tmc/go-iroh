// Package budget bounds the work and the resources an op sequence is
// allowed to consume.
//
// Two failure modes survive an ordinary invariant. A decoder given a
// large length prefix allocates gigabytes without panicking, so a
// no-panic property sleeps straight through the bug. And a system that
// acquires a resource — a stream credit, a connection, a goroutine —
// and fails to return it stays correct-looking for the whole run,
// wedging only once the pool is exhausted, thousands of operations
// after the op that leaked.
//
// [Alloc] catches the first by tying allocation to input size, on the
// principle that a len(input)-byte input justifies only a bounded
// multiple of that in work. [Ledger] catches the second by requiring
// that every acquire is matched by a release before the sequence ends.
// Both are registered from [fuzztape.Machine] Init and report at the
// end of the sequence, which is the only moment at which "the system
// should have settled" is a meaningful claim.
package budget

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/tmc/go-iroh/internal/fuzztape"
)

// A Ledger records resources an op sequence acquires and releases, so
// that one left outstanding at the end of the sequence is reported as
// the leak it is. The zero Ledger is ready to use. Methods are safe for
// concurrent use, so a system under test may account from its own
// goroutines.
type Ledger struct {
	mu        sync.Mutex
	out       map[string]int
	peak      map[string]int
	unmatched []string
}

// Acquire records one acquisition of the named resource.
func (l *Ledger) Acquire(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.out == nil {
		l.out, l.peak = map[string]int{}, map[string]int{}
	}
	l.out[name]++
	if l.out[name] > l.peak[name] {
		l.peak[name] = l.out[name]
	}
}

// Release records one release of the named resource. A release with no
// matching acquire is itself an error, recorded and reported by
// [Ledger.Balanced]: double frees and phantom releases are as much a
// bug as a leak, and silently clamping at zero would hide them.
func (l *Ledger) Release(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.out == nil {
		l.out, l.peak = map[string]int{}, map[string]int{}
	}
	if l.out[name] == 0 {
		l.unmatched = append(l.unmatched, name)
		return
	}
	l.out[name]--
}

// Outstanding returns the number of the named resource acquired and not
// yet released.
func (l *Ledger) Outstanding(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.out[name]
}

// Peak returns the largest number of the named resource outstanding at
// once, which is what a capacity claim should be checked against.
func (l *Ledger) Peak(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peak[name]
}

// Balanced registers a check that runs when the sequence ends and fails
// if any resource is still outstanding or any release went unmatched.
// Call it from [fuzztape.Machine] Init.
//
// Under Machine.Bubble the check runs inside the bubble, before its
// exit check, so a leaked resource and a leaked goroutine are reported
// from the same input rather than one masking the other.
func (l *Ledger) Balanced(t *fuzztape.T) {
	t.Cleanup(func() {
		if msg := l.imbalance(); msg != "" {
			t.Errorf("budget: %s", msg)
		}
	})
}

// imbalance describes what is left over, or returns "" if the ledger
// balances.
func (l *Ledger) imbalance() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var leaked []string
	for name, n := range l.out {
		if n != 0 {
			leaked = append(leaked, fmt.Sprintf("%s x%d", name, n))
		}
	}
	slices.Sort(leaked)
	b := strings.Builder{}
	b.WriteString(strings.Join(leaked, ", "))
	if len(l.unmatched) > 0 {
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		unmatched := slices.Clone(l.unmatched)
		slices.Sort(unmatched)
		b.WriteString("released without acquiring: ")
		b.WriteString(strings.Join(slices.Compact(unmatched), ", "))
	}
	if b.Len() == 0 {
		return ""
	}
	return "resources outstanding at end of sequence: " + b.String()
}

// Alloc registers a check that runs when the sequence ends and fails if
// it allocated more than perInputByte bytes for every byte of the input,
// plus overhead. Call it from [fuzztape.Machine] Init.
//
// The measurement is [runtime.MemStats] TotalAlloc, which counts bytes
// ever allocated and never decreases. That choice is what makes the
// check deterministic: a live-heap measurement such as HeapAlloc would
// rise and fall with collection, so the same input could pass or fail
// depending on when the collector ran. A cumulative counter cannot.
//
// Determinism holds across a run and across toolchains, but not across
// build configurations. The counter measures the binary that is
// running, and an instrumented build allocates more: the race
// detector's shadow state is heap like anything else, and the same work
// measured about a fifth higher under -race than without it. So a
// ceiling tuned on an ordinary build can trip under -race. Leave
// headroom for it rather than keeping a second ceiling in step.
//
// The counter is also process-wide, not sequence-wide: it counts every
// goroutine in the binary. Machine cases run one after another, so an
// ordinary run measures only the sequence, but a parallel test in the
// same binary or a background goroutine of the program's own lands in
// the measurement and can trip a ceiling the sequence never approached.
//
// Reading it stops the world, so this costs roughly a microsecond per
// input — negligible for [fuzztape.Machine.Run] and for targeted
// fuzzing, but real at full fuzzing throughput. Enable it while hunting
// the unbounded-allocation class, not in every machine forever.
func Alloc(t *fuzztape.T, perInputByte, overhead uint64) {
	max := overhead + perInputByte*uint64(t.Len())
	start := totalAlloc()
	t.Cleanup(func() {
		if used := totalAlloc() - start; used > max {
			t.Errorf("budget: %d-byte input allocated %d bytes, over the %d-byte ceiling (%d/byte + %d)",
				t.Len(), used, max, perInputByte, overhead)
		}
	})
}

// totalAlloc returns the cumulative bytes allocated by this process.
func totalAlloc() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.TotalAlloc
}
