package sched_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/sched"
)

// opening is every account's starting balance.
const opening = 100

// account is the system under test: a balance withdrawn from by
// concurrent goroutines, alongside a running total of what has been
// taken out.
type account struct {
	sched     *sched.Scheduler
	balance   int
	withdrawn int
	safe      bool
}

// Withdraw is check-then-act. It reads the balance, offers a scheduling
// point, then writes back a value derived from the stale read — the
// lost update every concurrent counter gets wrong at least once. With
// safe set it re-reads after the yield, which closes the window.
//
// Note what the bug does and does not do. Two withdrawals that
// interleave inside the window both succeed, but the second overwrites
// the first, so the balance ends too high rather than negative: the
// money leaves the ledger without leaving the account. Only comparing
// the balance against the total withdrawn catches it, which is why the
// invariant is stated as conservation and not as a bound.
func (a *account) Withdraw(n int) {
	have := a.balance
	if have < n {
		return
	}
	a.sched.Yield()
	if a.safe {
		if a.balance < n {
			return
		}
		a.balance -= n
		a.withdrawn += n
		return
	}
	a.balance = have - n
	a.withdrawn += n
}

func machine(safe bool) fuzztape.Machine[*account] {
	return fuzztape.Machine[*account]{
		Bubble: true,
		Init: func(t *fuzztape.T) *account {
			a := &account{balance: opening, safe: safe}
			a.sched = sched.New(t)
			return a
		},
		Ops: []fuzztape.Op[*account]{
			{Name: "withdraw", Weight: 2, Apply: func(t *fuzztape.T, a *account) {
				amount := fuzztape.IntRange(1, 100)(t.Tape)
				a.sched.Go("withdraw", func() { a.Withdraw(amount) })
			}},
			sched.StepOp("step", func(a *account) *sched.Scheduler { return a.sched }),
			sched.SettleOp("settle", func(a *account) *sched.Scheduler { return a.sched }),
		},
		Check: func(t *fuzztape.T, a *account) {
			if a.balance != opening-a.withdrawn {
				t.Fatalf("balance %d, but %d of %d was withdrawn (lost update) after schedule [%s]",
					a.balance, a.withdrawn, opening, a.sched)
			}
		},
	}
}

// TestSafeImplementationPasses is the negative control. The version
// that re-reads after the yield must survive every schedule, or the
// canary below proves only that the scheduler can break correct code.
func TestSafeImplementationPasses(t *testing.T) {
	machine(true).Run(t, 300)
}

// TestCanary proves the scheduler reaches an interleaving no
// sequential machine can: two withdrawals both past the balance check
// before either writes.
func TestCanary(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		machine(false).Run(t, 3000)
		return
	}
	out, err := child(t, "^TestCanary$")
	if err == nil {
		t.Fatalf("planted race not found; output:\n%s", out)
	}
	for _, want := range []string{"lost update", "op sequence", "shrunk failing input"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; output:\n%s", want, out)
		}
	}
}

// TestStepLeavesNothingRunning is the regression test for the race the
// trailing wait in Step prevents. Every goroutine the scheduler owns is
// either parked or finished; none is mid-execution. If Step returned
// before the goroutine it released reached its next scheduling point,
// that goroutine would be neither, and the count would come up short —
// which is precisely the window in which the op goroutine would run the
// invariant against a system another goroutine was still mutating.
func TestStepLeavesNothingRunning(t *testing.T) {
	type fleet struct {
		sched    *sched.Scheduler
		spawned  int
		finished atomic.Int32
	}
	m := fuzztape.Machine[*fleet]{
		Bubble: true,
		Init: func(t *fuzztape.T) *fleet {
			f := new(fleet)
			f.sched = sched.New(t)
			return f
		},
		Ops: []fuzztape.Op[*fleet]{
			{Name: "spawn", Weight: 2, Apply: func(t *fuzztape.T, f *fleet) {
				f.spawned++
				f.sched.Go("worker", func() {
					f.sched.Yield()
					f.sched.Yield()
					f.finished.Add(1)
				})
			}},
			sched.StepOp("step", func(f *fleet) *sched.Scheduler { return f.sched }),
		},
		Check: func(t *fuzztape.T, f *fleet) {
			if got := f.sched.Parked() + int(f.finished.Load()); got != f.spawned {
				t.Fatalf("%d parked + %d finished = %d, want %d spawned: a goroutine is still running",
					f.sched.Parked(), f.finished.Load(), got, f.spawned)
			}
		},
	}
	m.Run(t, 200)
}

// TestPanicNamesTheGoroutine covers the label [Scheduler.Go] attaches.
// A panic in a scheduled goroutine must say which one it was: the
// traceback otherwise shows an anonymous function inside the system
// under test, and with several goroutines under one name there is
// nothing to tell them apart.
//
// The child sets GODEBUG=tracebacklabels=1 rather than relying on the
// default, so the test holds on the floor toolchain too. go1.26 and
// go1.27 format the line differently, so it asserts on the key and the
// value and not on the punctuation around them.
func TestPanicNamesTheGoroutine(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		m := fuzztape.Machine[*sched.Scheduler]{
			Bubble: true,
			Init:   func(t *fuzztape.T) *sched.Scheduler { return sched.New(t) },
			Ops: []fuzztape.Op[*sched.Scheduler]{
				{Name: "spawn", Apply: func(t *fuzztape.T, s *sched.Scheduler) {
					s.Go("exploder", func() { panic("boom") })
				}},
			},
		}
		// The scheduler drains at the end of the sequence, so a spawned
		// goroutine is always released and always panics.
		m.Run(t, 50)
		return
	}
	out, err := child(t, "^TestPanicNamesTheGoroutine$", "GODEBUG=tracebacklabels=1")
	if err == nil {
		t.Fatalf("the panicking goroutine did not crash the child; output:\n%s", out)
	}
	// Not "exploder#1": a sequence spawns several goroutines before the
	// drain releases any, and the one that panics is whichever the tape
	// released first, which is the whole point of the ordinal.
	for _, want := range []string{sched.LabelKey, "exploder#"} {
		if !strings.Contains(out, want) {
			t.Errorf("traceback missing %q; output:\n%s", want, out)
		}
	}
}

// TestScheduleIsDeterministic is the property the whole package exists
// for: the same input must produce the same schedule and the same
// final state, every time. Without it a failing corpus file would not
// reproduce and shrinking would be meaningless.
func TestScheduleIsDeterministic(t *testing.T) {
	input := []byte{9, 3, 17, 42, 5, 200, 1, 8, 77, 4, 12, 250, 6, 31, 2, 90}
	var schedules []string
	var balances []int
	for range 8 {
		schedule, balance := replay(t, input)
		schedules = append(schedules, schedule)
		balances = append(balances, balance)
	}
	for i := range schedules {
		if schedules[i] != schedules[0] {
			t.Fatalf("run %d scheduled [%s], first run scheduled [%s]", i, schedules[i], schedules[0])
		}
		if balances[i] != balances[0] {
			t.Fatalf("run %d ended at %d, first run ended at %d", i, balances[i], balances[0])
		}
	}
	if schedules[0] == "" {
		t.Fatal("no goroutine was ever scheduled; the test proves nothing")
	}
}

// TestSpawnOrderIsReproducible is the regression test for choosing by
// arrival. Goroutines started together park together, in whatever order
// the runtime lets them reach the scheduler's lock, and a tape that
// indexed them by arrival released a different one for the same byte:
// the empty input below once produced 58 distinct orders in 100 runs.
// Every fresh bubble must now produce the same one.
func TestSpawnOrderIsReproducible(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"drain", nil},
		{"steps", []byte{0, 7, 0, 3, 0, 11, 0, 5, 0, 200, 0, 1, 0, 9, 0, 4, 0, 250, 0, 6, 0, 2, 0, 8}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := map[string]int{}
			for range 100 {
				var ran []string
				m := fuzztape.Machine[*sched.Scheduler]{
					Bubble: true,
					Init: func(ft *fuzztape.T) *sched.Scheduler {
						s := sched.New(ft)
						for i := range 12 {
							s.Go("g", func() {
								ran = append(ran, fmt.Sprint(i))
								s.Yield()
								ran = append(ran, fmt.Sprint(i, "'"))
							})
						}
						return s
					},
					Ops: []fuzztape.Op[*sched.Scheduler]{
						sched.StepOp("step", func(s *sched.Scheduler) *sched.Scheduler { return s }),
					},
				}
				m.Replay(t, tt.input)
				if len(ran) != 24 {
					t.Fatalf("%d of 24 steps ran", len(ran))
				}
				seen[strings.Join(ran, " ")]++
			}
			if len(seen) != 1 {
				t.Errorf("one input produced %d orders in 100 runs, want 1: %v", len(seen), seen)
			}
		})
	}
}

// replay runs input once against a fresh account and returns the
// schedule and balance it ended with.
func replay(t *testing.T, input []byte) (schedule string, balance int) {
	t.Helper()
	m := machine(false)
	m.Check = nil // the lost update is expected here, not a failure
	init := m.Init
	m.Init = func(ft *fuzztape.T) *account {
		// Registered before Init runs, so it is the last cleanup to
		// execute: after the scheduler has drained, when the schedule
		// and the balance are final.
		var a *account
		ft.Cleanup(func() { schedule, balance = a.sched.String(), a.balance })
		a = init(ft)
		return a
	}
	// Splits replays one input against a fresh system, which is the
	// exported way to run exactly one input.
	m.Splits(t, input)
	return schedule, balance
}

func child(t *testing.T, run string, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", run, "-test.v")
	cmd.Env = append(os.Environ(), "FUZZTAPE_CANARY=1")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
