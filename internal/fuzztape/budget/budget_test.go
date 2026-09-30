package budget_test

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/budget"
)

// pool is the system under test: a resource pool that accounts every
// acquire and release into a ledger. When leaky is set it forgets to
// release one handle in ten — the shape of a credit leak, correct in
// every visible way until the pool runs dry.
type pool struct {
	ledger *budget.Ledger
	held   int
	closes int
	leaky  bool
}

func (p *pool) Open() {
	p.ledger.Acquire("handle")
	p.held++
}

func (p *pool) Close() {
	if p.held == 0 {
		return
	}
	p.held--
	p.closes++
	if p.leaky && p.closes%10 == 0 {
		return // the planted leak: the handle is gone, the credit is not
	}
	p.ledger.Release("handle")
}

func poolMachine(leaky bool) fuzztape.Machine[*pool] {
	return fuzztape.Machine[*pool]{
		Name: "",
		Init: func(t *fuzztape.T) *pool {
			p := &pool{ledger: new(budget.Ledger), leaky: leaky}
			p.ledger.Balanced(t)
			// Closing everything at the end of the sequence is what
			// makes an outstanding handle a leak rather than a handle
			// still legitimately in use.
			t.Cleanup(func() {
				for p.held > 0 {
					p.Close()
				}
			})
			return p
		},
		Ops: []fuzztape.Op[*pool]{
			{Name: "open", Weight: 2, Apply: func(t *fuzztape.T, p *pool) { p.Open() }},
			{Name: "close", When: func(p *pool) bool { return p.held > 0 },
				Apply: func(t *fuzztape.T, p *pool) { p.Close() }},
		},
	}
}

// TestLedgerBalances is the negative control: an honest pool must not
// trip the ledger, or the canary proves nothing.
func TestLedgerBalances(t *testing.T) {
	poolMachine(false).Run(t, 300)
}

// TestLedgerCanary proves the ledger catches a leak that no invariant
// on the visible state would see.
func TestLedgerCanary(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		poolMachine(true).Run(t, 2000)
		return
	}
	out, err := child(t, "^TestLedgerCanary$")
	if err == nil {
		t.Fatalf("planted leak not found; output:\n%s", out)
	}
	for _, want := range []string{"resources outstanding", "handle x", "op sequence"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; output:\n%s", want, out)
		}
	}
}

func TestLedgerUnmatchedRelease(t *testing.T) {
	var l budget.Ledger
	l.Acquire("a")
	l.Release("a")
	l.Release("a") // one too many
	if got := l.Outstanding("a"); got != 0 {
		t.Errorf("Outstanding = %d, want 0 (an unmatched release must not go negative)", got)
	}
	if got := l.Peak("a"); got != 1 {
		t.Errorf("Peak = %d, want 1", got)
	}
	fake := &recorder{TB: t}
	l.Balanced(fuzztape.NewT(fake, nil))
	fake.runCleanups()
	if !strings.Contains(fake.msg, "released without acquiring") {
		t.Errorf("message = %q, want it to report the unmatched release", fake.msg)
	}
}

// TestAllocCatchesUnboundedAllocation covers the decoder bug class: a
// small input that allocates far more than its size justifies.
func TestAllocCatchesUnboundedAllocation(t *testing.T) {
	var sink []byte
	fake := &recorder{TB: t}
	ft := fuzztape.NewT(fake, make([]byte, 8))
	budget.Alloc(ft, 16, 4096) // 8 bytes of input buys 4224 bytes
	sink = make([]byte, 1<<20)
	_ = sink
	fake.runCleanups()
	if !fake.failed {
		t.Fatal("a 1 MiB allocation for an 8-byte input did not trip the ceiling")
	}
	if !strings.Contains(fake.msg, "over the") {
		t.Errorf("message = %q", fake.msg)
	}
}

// TestAllocIsDeterministic settles the question the design note left
// open: whether garbage collection makes an allocation ceiling flaky.
// It does not, because the measurement is a cumulative counter rather
// than a live-heap one. Forcing collections between identical
// measurements must not change the verdict.
func TestAllocIsDeterministic(t *testing.T) {
	measure := func(collect bool) bool {
		fake := &recorder{TB: t}
		ft := fuzztape.NewT(fake, make([]byte, 64))
		budget.Alloc(ft, 8, 1024)
		var keep [][]byte
		for range 100 {
			keep = append(keep, make([]byte, 512))
			if collect {
				runtime.GC()
			}
		}
		_ = keep
		fake.runCleanups()
		return fake.failed
	}
	withGC, withoutGC := measure(true), measure(false)
	if withGC != withoutGC {
		t.Errorf("verdict changed with collection: %v with GC, %v without", withGC, withoutGC)
	}
	if !withGC {
		t.Error("the over-budget allocation was not caught in either run")
	}
}

// TestAllocPassesWithinBudget proves the ceiling is not simply always
// tripped.
func TestAllocPassesWithinBudget(t *testing.T) {
	fake := &recorder{TB: t}
	ft := fuzztape.NewT(fake, make([]byte, 1024))
	budget.Alloc(ft, 64, 1<<20)
	_ = make([]byte, 4096)
	fake.runCleanups()
	if fake.failed {
		t.Errorf("a modest allocation tripped the ceiling: %s", fake.msg)
	}
}

func child(t *testing.T, run string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", run, "-test.v")
	cmd.Env = append(os.Environ(), "FUZZTAPE_CANARY=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// recorder stands in for the testing.TB a machine would supply,
// capturing reports and running cleanups on demand.
type recorder struct {
	testing.TB
	failed   bool
	msg      string
	cleanups []func()
}

func (r *recorder) Errorf(format string, args ...any) {
	r.failed = true
	r.msg = fmt.Sprintf(format, args...)
}

func (r *recorder) Helper()          {}
func (r *recorder) Cleanup(f func()) { r.cleanups = append(r.cleanups, f) }
func (r *recorder) runCleanups() {
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
	r.cleanups = nil
}
