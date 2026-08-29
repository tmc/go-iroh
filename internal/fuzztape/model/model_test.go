package model_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/fuzztape/model"
)

// queue is the system under test: a FIFO over a slice.
type queue struct {
	xs     []int
	pushes int
	buggy  bool
}

func (q *queue) Push(v int) {
	q.xs = append(q.xs, v)
	q.pushes++
}

// Pop removes and returns the oldest element. When buggy is set it
// returns the newest instead, but only after the fourth push — a wrong
// answer that leaves the queue in a perfectly plausible state, which is
// exactly what an invariant cannot see.
func (q *queue) Pop() (int, bool) {
	if len(q.xs) == 0 {
		return 0, false
	}
	i := 0
	if q.buggy && q.pushes > 4 {
		i = len(q.xs) - 1
	}
	v := q.xs[i]
	q.xs = append(q.xs[:i], q.xs[i+1:]...)
	return v, true
}

func (q *queue) Len() int { return len(q.xs) }

// popped is the observation both implementations return, so a
// divergence in either the value or the emptiness is caught.
type popped struct {
	V  int
	OK bool
}

// ops builds the machine's operation set over a reference []int.
func ops() []fuzztape.Op[model.Pair[*queue, *[]int]] {
	return []fuzztape.Op[model.Pair[*queue, *[]int]]{
		model.Do("push", fuzztape.IntRange(0, 99),
			func(q *queue, v int) { q.Push(v) },
			func(m *[]int, v int) { *m = append(*m, v) }),
		model.Op("pop", fuzztape.Const(0),
			func(q *queue, _ int) popped {
				v, ok := q.Pop()
				return popped{v, ok}
			},
			func(m *[]int, _ int) popped {
				if len(*m) == 0 {
					return popped{0, false}
				}
				v := (*m)[0]
				*m = (*m)[1:]
				return popped{v, true}
			}),
	}
}

func machine(buggy bool) fuzztape.Machine[model.Pair[*queue, *[]int]] {
	return fuzztape.Machine[model.Pair[*queue, *[]int]]{
		Init: model.Init(
			func(t *fuzztape.T) *queue { return &queue{buggy: buggy} },
			func(t *fuzztape.T) *[]int { return new([]int) },
		),
		Ops: ops(),
		Check: model.Equal(
			func(q *queue) int { return q.Len() },
			func(m *[]int) int { return len(*m) },
		),
	}
}

// TestCorrectImplementationPasses is the negative control: without the
// planted bug the machine must survive, or the canary below proves
// nothing.
func TestCorrectImplementationPasses(t *testing.T) {
	machine(false).Run(t, 300)
}

// TestCanary proves the oracle has teeth. The planted bug returns a
// wrong value while leaving a valid-looking queue, so only a
// result-comparing op can catch it; the run must fail, shrink, and name
// the divergence. It runs in a child process so the deliberate failure
// does not fail this test.
func TestCanary(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		machine(true).Run(t, 2000)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestCanary$", "-test.v")
	cmd.Env = append(os.Environ(), "FUZZTAPE_CANARY=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("planted divergence not found in 2000 cases; output:\n%s", out)
	}
	for _, want := range []string{"model says", "op sequence", "shrunk failing input"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("child output missing %q; output:\n%s", want, out)
		}
	}
}

// TestOpDrawsParameterOnce is the regression test for the trap this
// package exists to avoid: if the constructor drew from the tape once
// per side, the model would receive the bytes following the system
// under test's, and the two would disagree on nearly every input.
func TestOpDrawsParameterOnce(t *testing.T) {
	var sutSaw, modelSaw []int
	op := model.Op("draw", fuzztape.IntRange(0, 1<<20),
		func(s *int, v int) int { sutSaw = append(sutSaw, v); return 0 },
		func(m *int, v int) int { modelSaw = append(modelSaw, v); return 0 })

	p := model.Pair[*int, *int]{SUT: new(int), Model: new(int)}
	for i := range 256 {
		data := []byte{byte(i), byte(i * 7), 3, 9, 4, 7, 1, 2, 8, 5}
		op.Apply(fuzztape.NewT(t, data), p)
	}
	if len(sutSaw) != len(modelSaw) {
		t.Fatalf("%d draws reached the system under test, %d reached the model", len(sutSaw), len(modelSaw))
	}
	for i := range sutSaw {
		if sutSaw[i] != modelSaw[i] {
			t.Fatalf("draw %d: system under test got %d, model got %d; the parameter was drawn twice",
				i, sutSaw[i], modelSaw[i])
		}
	}
	// A tape that never advanced would make the check above vacuous.
	distinct := map[int]bool{}
	for _, v := range sutSaw {
		distinct[v] = true
	}
	if len(distinct) < 2 {
		t.Fatalf("generator produced %d distinct values; the test proves nothing", len(distinct))
	}
}

// TestMismatchIsReportedNotPanicked is the regression test for the
// second trap: a divergence must arrive as an ordinary test failure. A
// panic would kill the binary outright in an unbubbled machine, taking
// the shrinker, the op log, and the saved corpus file with it.
func TestMismatchIsReportedNotPanicked(t *testing.T) {
	op := model.Op("differ", fuzztape.Const(0),
		func(s *int, _ int) int { return 1 },
		func(m *int, _ int) int { return 2 })

	fake := &recorder{TB: t}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("mismatch panicked instead of reporting: %v", r)
			}
		}()
		op.Apply(fuzztape.NewT(fake, nil), model.Pair[*int, *int]{SUT: new(int), Model: new(int)})
	}()
	if !fake.failed {
		t.Fatal("mismatch did not report a failure")
	}
	if !strings.Contains(fake.msg, "model says") {
		t.Errorf("failure message = %q, want it to name the model's value", fake.msg)
	}
}

// recorder captures the report a T forwards, standing in for the
// testing.TB a machine would supply. Fatalf must not Goexit here: the
// op is being driven directly, not from a machine's sequence goroutine.
type recorder struct {
	testing.TB
	failed bool
	msg    string
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = true
	r.msg = fmt.Sprintf(format, args...)
}

func (r *recorder) Helper() {}
