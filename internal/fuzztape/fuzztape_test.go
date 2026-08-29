package fuzztape

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"
)

func TestTapeZero(t *testing.T) {
	tape := New(nil)
	if !tape.Done() {
		t.Error("empty tape not Done")
	}
	if got := tape.Byte(); got != 0 {
		t.Errorf("Byte() = %d, want 0", got)
	}
	if tape.Bool() {
		t.Error("Bool() = true, want false")
	}
	if got := tape.Uint64(); got != 0 {
		t.Errorf("Uint64() = %d, want 0", got)
	}
	if got := tape.IntN(100); got != 0 {
		t.Errorf("IntN(100) = %d, want 0", got)
	}
	if got := tape.Bytes(16); len(got) != 0 {
		t.Errorf("Bytes(16) = %d bytes, want 0", len(got))
	}
	if got := Pick(tape, []string{"a", "b"}); got != "a" {
		t.Errorf("Pick = %q, want %q (first option)", got, "a")
	}
}

func TestTapeIntN(t *testing.T) {
	// Every selector byte, with a fixed uniform payload, stays in range
	// for a spread of n, and decoding is deterministic.
	for _, n := range []int{1, 2, 3, 7, 100, 1 << 20} {
		for sel := 0; sel < 256; sel++ {
			data := append([]byte{byte(sel)}, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4)
			got := New(data).IntN(n)
			if got < 0 || got >= n {
				t.Fatalf("IntN(%d) with selector %d = %d, out of range", n, sel, got)
			}
			if again := New(data).IntN(n); again != got {
				t.Fatalf("IntN(%d) not deterministic: %d then %d", n, got, again)
			}
		}
	}
	// The boundary selectors hit the documented values.
	for sel, want := range map[byte]int{0: 0, 1: 1, 2: 99, 3: 64} {
		if got := New([]byte{sel}).IntN(100); got != want {
			t.Errorf("IntN(100) with selector %d = %d, want %d", sel, got, want)
		}
	}
}

func TestTapeIntNPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("IntN(0) did not panic")
		}
	}()
	New(nil).IntN(0)
}

func TestTapeBytes(t *testing.T) {
	// Selector 2 forces the boundary length max; payload comes from the
	// tape then zero-fills.
	tape := New([]byte{2, 0xaa, 0xbb})
	got := tape.Bytes(4)
	if want := []byte{0xaa, 0xbb, 0, 0}; !bytes.Equal(got, want) {
		t.Errorf("Bytes(4) = %x, want %x", got, want)
	}
}

// TestLengthMaxPanics covers the one contract every generator taking a
// maximum length shares. Bytes used to clamp a negative max to zero
// while its three cousins panicked through IntN, so the same mistake
// produced a silent empty-forever generator in one place and a crash in
// another.
func TestLengthMaxPanics(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(max int)
	}{
		{"Bytes", func(max int) { New(nil).Bytes(max) }},
		{"SliceOf", func(max int) { SliceOf(Const(0), max) }},
		{"StringASCII", func(max int) { StringASCII(max) }},
		{"StringUTF8", func(max int) { StringUTF8(max) }},
	} {
		for _, max := range []int{-1, math.MaxInt} {
			t.Run(fmt.Sprintf("%s/%d", tc.name, max), func(t *testing.T) {
				defer func() {
					if recover() == nil {
						t.Errorf("%s(%d) did not panic", tc.name, max)
					}
				}()
				tc.call(max)
			})
		}
	}
}

func TestTapeFrontToBack(t *testing.T) {
	tape := New([]byte{7, 8, 9})
	if got := tape.Byte(); got != 7 {
		t.Errorf("first Byte() = %d, want 7", got)
	}
	if got := tape.Byte(); got != 8 {
		t.Errorf("second Byte() = %d, want 8", got)
	}
	if tape.Done() {
		t.Error("Done() with one byte left")
	}
	tape.Byte()
	if !tape.Done() {
		t.Error("not Done() after consuming all input")
	}
}

func TestGen(t *testing.T) {
	if got := Const(42)(New(nil)); got != 42 {
		t.Errorf("Const(42) = %d", got)
	}
	for sel := 0; sel < 256; sel++ {
		g := IntRange(10, 20)(New([]byte{byte(sel), 5, 6, 7, 8}))
		if g < 10 || g > 20 {
			t.Fatalf("IntRange(10, 20) = %d, out of range", g)
		}
	}
	one := OneOf(Const("x"), Const("y"))
	if got := one(New(nil)); got != "x" {
		t.Errorf("OneOf on zero tape = %q, want first generator", got)
	}
	double := Map(Const(21), func(n int) int { return 2 * n })
	if got := double(New(nil)); got != 42 {
		t.Errorf("Map = %d, want 42", got)
	}
	s := SliceOf(Const(1), 5)(New([]byte{2}))
	if len(s) != 5 {
		t.Errorf("SliceOf with max-boundary selector: len = %d, want 5", len(s))
	}
}

func TestGenWeighted(t *testing.T) {
	opts := []string{"rare", "common"}
	g := Weighted(opts, []int{1, 9})
	if got := g(New(nil)); got != "rare" {
		t.Errorf("Weighted on zero tape = %q, want first option", got)
	}
	// Every selector lands on a declared option, and the heavy option
	// dominates a uniform sweep of the selector byte.
	counts := map[string]int{}
	for sel := 0; sel < 256; sel++ {
		counts[g(New([]byte{byte(sel), 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}))]++
	}
	if counts["rare"]+counts["common"] != 256 {
		t.Errorf("Weighted produced values outside opts: %v", counts)
	}
	if counts["common"] <= counts["rare"] {
		t.Errorf("weight 9 option not dominant: %v", counts)
	}
}

func TestGenWeightedPanics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    []int
		weights []int
	}{
		{"empty", nil, nil},
		{"mismatched", []int{1, 2}, []int{1}},
		{"negative", []int{1}, []int{-1}},
		{"all zero", []int{1, 2}, []int{0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			Weighted(tc.opts, tc.weights)
		})
	}
}

func TestGenFloat(t *testing.T) {
	if got := Float64()(New(nil)); got != 0 || math.Signbit(got) {
		t.Errorf("Float64 on zero tape = %v, want +0", got)
	}
	if got := Float32()(New(nil)); got != 0 {
		t.Errorf("Float32 on zero tape = %v, want 0", got)
	}
	// The skew reaches the values a uniform bit pattern almost never
	// produces, and every selector byte decodes to something.
	var sawNaN, sawInf, sawNegZero bool
	for sel := 0; sel < 256; sel++ {
		v := Float64()(New([]byte{byte(sel), 1, 2, 3, 4, 5, 6, 7, 8}))
		switch {
		case math.IsNaN(v):
			sawNaN = true
		case math.IsInf(v, 0):
			sawInf = true
		case v == 0 && math.Signbit(v):
			sawNegZero = true
		}
	}
	if !sawNaN || !sawInf || !sawNegZero {
		t.Errorf("Float64 skew missed a boundary: NaN=%v Inf=%v -0=%v", sawNaN, sawInf, sawNegZero)
	}
}

func TestGenStrings(t *testing.T) {
	if got := StringASCII(8)(New(nil)); got != "" {
		t.Errorf("StringASCII on zero tape = %q, want empty", got)
	}
	if got := StringUTF8(8)(New(nil)); got != "" {
		t.Errorf("StringUTF8 on zero tape = %q, want empty", got)
	}
	// Selector 2 forces the boundary length, then payload bytes.
	data := append([]byte{2}, bytes.Repeat([]byte{0x41}, 64)...)
	s := StringASCII(8)(New(data))
	if len(s) != 8 {
		t.Errorf("StringASCII(8) length = %d, want 8", len(s))
	}
	for _, c := range []byte(s) {
		if c < ' ' || c > '~' {
			t.Errorf("StringASCII produced non-printable %#x in %q", c, s)
		}
	}
	// Every input decodes to valid UTF-8, including the unskewed path.
	for sel := 0; sel < 256; sel++ {
		payload := bytes.Repeat([]byte{byte(sel)}, 96)
		got := StringUTF8(6)(New(append([]byte{2}, payload...)))
		if !utf8.ValidString(got) {
			t.Fatalf("StringUTF8 with selector %d produced invalid UTF-8: %q", sel, got)
		}
	}
}

func TestGenDuration(t *testing.T) {
	g := Duration(time.Second, time.Hour)
	if got := g(New(nil)); got != time.Second {
		t.Errorf("Duration on zero tape = %v, want the low bound", got)
	}
	for sel := 0; sel < 256; sel++ {
		d := g(New([]byte{byte(sel), 9, 8, 7, 6, 5, 4, 3, 2}))
		if d < time.Second || d > time.Hour {
			t.Fatalf("Duration with selector %d = %v, out of range", sel, d)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Duration(hi < lo) did not panic")
			}
		}()
		Duration(time.Hour, time.Second)
	}()
}

// counter is the canary system under test: a counter that the planted
// invariant forbids from reaching 7.
type counter struct{ n int }

var canary = Machine[*counter]{
	Init: func(t *T) *counter { return new(counter) },
	Ops: []Op[*counter]{
		{Name: "inc", Weight: 3, Apply: func(t *T, c *counter) { c.n++ }},
		{Name: "dec", When: func(c *counter) bool { return c.n > 0 },
			Apply: func(t *T, c *counter) { c.n-- }},
	},
	Check: func(t *T, c *counter) {
		if c.n == 7 {
			t.Fatalf("planted violation: counter reached 7")
		}
	},
}

// TestMachineRunPasses exercises Run on a machine whose invariant holds.
var clean = Machine[*counter]{
	Init: canary.Init,
	Ops:  canary.Ops,
	Check: func(t *T, c *counter) {
		if c.n < 0 {
			t.Fatalf("counter negative: %d", c.n)
		}
	},
}

func TestMachineRunPasses(t *testing.T) {
	clean.Run(t, 50)
}

func TestMachineFuzzOpSelection(t *testing.T) {
	// A zero tape of any length decodes to a prefix of "inc" ops (the
	// first enabled op) and never trips the clean invariant.
	clean.runTape(t, make([]byte, 64), true, nil, nil)
}

func TestMachineSplits(t *testing.T) {
	// Selector 0 decodes IntN in one byte, so each of the five zero
	// bytes is exactly one op: boundaries at 0..5.
	splits := clean.Splits(t, make([]byte, 5))
	want := []int{0, 1, 2, 3, 4, 5}
	if !slices.Equal(splits, want) {
		t.Fatalf("Splits = %v, want %v", splits, want)
	}
	// A 0xff selector consumes 1 selector + 8 payload bytes.
	splits = clean.Splits(t, bytes.Repeat([]byte{0xff}, 9))
	if !slices.Equal(splits, []int{0, 9}) {
		t.Fatalf("Splits(ff×9) = %v, want [0 9]", splits)
	}
}

// TestMachineInitDrawsFromTape covers an Init that varies the starting
// state: its draws come off the front of the tape, so the first op
// boundary moves past them.
func TestMachineInitDrawsFromTape(t *testing.T) {
	m := Machine[*counter]{
		Init: func(t *T) *counter { return &counter{n: t.IntN(4)} },
		Ops:  clean.Ops,
	}
	// One byte for Init, then one byte per op.
	splits := m.Splits(t, make([]byte, 4))
	if !slices.Equal(splits, []int{1, 2, 3, 4}) {
		t.Fatalf("Splits = %v, want [1 2 3 4] (Init consumed the first byte)", splits)
	}
}

// rejecter proves Reject stops the op without failing the test and
// without ending the sequence: "bump" rejects on an odd counter, and
// the reason reaches the op log.
var rejecter = Machine[*counter]{
	Init: func(t *T) *counter { return new(counter) },
	Ops: []Op[*counter]{
		{Name: "bump", Apply: func(t *T, c *counter) {
			if c.n%2 == 1 {
				t.Reject("counter is odd: %d", c.n)
			}
			c.n += 2
		}},
		{Name: "odd", Apply: func(t *T, c *counter) { c.n = 1 }},
	},
}

func TestMachineReject(t *testing.T) {
	var applied []string
	// "odd" then "bump": the second op rejects, and the sequence
	// survives it.
	rejecter.runOps(t, []byte{0, 1, 0, 0}, &applied, nil)
	if t.Failed() {
		t.Fatal("Reject failed the test; it must not")
	}
	joined := strings.Join(applied, " | ")
	if !strings.Contains(joined, "rejected: counter is odd") {
		t.Errorf("op log missing the rejection reason: %s", joined)
	}
	if len(applied) < 3 {
		t.Errorf("sequence stopped at the rejection: %s", joined)
	}
}

// TestMachineRejectRestoresState proves a rejection does not leak its
// unwinding into the next op: the panic Reject uses is caught per op.
func TestMachineRejectRestoresState(t *testing.T) {
	var applied []string
	rejecter.runOps(t, bytes.Repeat([]byte{1, 0}, 8), &applied, nil)
	if t.Failed() {
		t.Fatal("repeated rejections failed the test")
	}
	if len(applied) == 0 {
		t.Fatal("no ops recorded")
	}
}

// TestOpOver covers the eligible-set constructor: the op is disabled
// while the set is empty and draws from it once it is not.
func TestOpOver(t *testing.T) {
	type bag struct{ items []int }
	var picked []int
	m := Machine[*bag]{
		Init: func(t *T) *bag { return &bag{} },
		Ops: []Op[*bag]{
			{Name: "add", Apply: func(t *T, b *bag) { b.items = append(b.items, len(b.items)) }},
			OpOver("take", func(b *bag) []int { return b.items }, func(t *T, b *bag, v int) {
				picked = append(picked, v)
			}),
		},
	}
	// The first op cannot be "take": with an empty bag it is disabled,
	// so a zero tape selects "add" every time.
	var applied []string
	m.runOps(t, make([]byte, 6), &applied, nil)
	if t.Failed() {
		t.Fatal("OpOver machine failed")
	}
	for _, name := range applied {
		if strings.HasPrefix(name, "take") {
			t.Fatalf("take ran on a zero tape, which should always select add: %v", applied)
		}
	}
	// Alternating selector bytes reach "take" once the bag is non-empty.
	picked = nil
	m.runOps(t, []byte{0, 0, 1, 0, 1, 0}, &applied, nil)
	if len(picked) == 0 {
		t.Error("take never ran")
	}
	for _, v := range picked {
		if v < 0 {
			t.Errorf("take drew %d, outside the candidate set", v)
		}
	}
}

// TestNewOp covers the typed op constructor: the parameter is drawn
// once, before apply runs.
func TestNewOp(t *testing.T) {
	var seen []int
	op := NewOp("set", IntRange(10, 20), func(t *T, c *counter, v int) {
		seen = append(seen, v)
		c.n = v
	})
	m := Machine[*counter]{
		Init: func(t *T) *counter { return new(counter) },
		Ops:  []Op[*counter]{op},
	}
	var applied []string
	m.runOps(t, []byte{0, 2, 0, 0}, &applied, nil)
	if len(seen) == 0 {
		t.Fatal("op never applied")
	}
	for _, v := range seen {
		if v < 10 || v > 20 {
			t.Errorf("drew %d, outside IntRange(10, 20)", v)
		}
	}
}

// TestCleanupOrder pins that cleanups run last-registered-first, which
// is what lets one cleanup settle the system — closing what is still
// open — before a later-checked, earlier-registered one asserts that
// nothing was left behind.
func TestCleanupOrder(t *testing.T) {
	var order []string
	m := Machine[*counter]{
		Init: func(t *T) *counter {
			t.Cleanup(func() { order = append(order, "registered first") })
			t.Cleanup(func() { order = append(order, "registered second") })
			return new(counter)
		},
		Ops: clean.Ops,
	}
	var applied []string
	m.runOps(t, make([]byte, 3), &applied, nil)
	want := []string{"registered second", "registered first"}
	if !slices.Equal(order, want) {
		t.Errorf("cleanup order = %v, want %v", order, want)
	}
}

// cleanupFailer reports a failure from a cleanup rather than from an
// op, which is how the budget subpackage reports a leak.
var cleanupFailer = Machine[*counter]{
	Init: func(t *T) *counter {
		t.Cleanup(func() { t.Errorf("planted cleanup failure") })
		return new(counter)
	},
	Ops: clean.Ops,
}

// TestCleanupFailureIsAttributed proves a failure reported after the
// last op still belongs to the sequence that caused it: it is logged
// with the op sequence and shrunk. Deferring cleanups to the end of the
// test instead would report them after the machine had stopped
// listening, losing both.
func TestCleanupFailureIsAttributed(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		cleanupFailer.Run(t, 1)
		return
	}
	out, err := runChild(t, "^TestCleanupFailureIsAttributed$")
	if err == nil {
		t.Fatalf("cleanup failure did not fail the run; output:\n%s", out)
	}
	wantAll(t, out, "planted cleanup failure", "op sequence", "shrunk failing input")
}

// TestMachineCanary proves the harness has teeth: a planted invariant
// violation must be found by Run, and the shrunk op sequence must be
// reported. The failing Run executes in a child process so the failure
// does not fail this test.
func TestMachineCanary(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		canary.Run(t, 2000)
		return
	}
	out, err := runChild(t, "^TestMachineCanary$")
	if err == nil {
		t.Fatalf("planted violation not found in 2000 cases; output:\n%s", out)
	}
	wantAll(t, out, "planted violation", "op sequence", "shrunk failing input")
}

// panicker is the panic canary: an op that indexes out of range once
// the counter reaches 7, standing in for the ordinary crash a system
// under test produces. There is no Check: the panic is the failure.
var panicker = Machine[*counter]{
	Name: "FuzzPanicker",
	Init: canary.Init,
	Ops: []Op[*counter]{
		{Name: "inc", Weight: 3, Apply: func(t *T, c *counter) {
			c.n++
			if c.n == 7 {
				var empty []int
				_ = empty[0]
			}
		}},
		{Name: "dec", When: func(c *counter) bool { return c.n > 0 },
			Apply: func(t *T, c *counter) { c.n-- }},
	},
}

// TestMachinePanicCanary proves a panicking op is an ordinary failure
// rather than the end of the test binary. A panic in the system under
// test is the most common thing a fuzz target finds, so everything the
// package does with a failure has to apply to it: the op sequence is
// logged, the input is shrunk, and the shrunk input is saved as a seed.
// The failing Run executes in a child process so it does not fail this
// test, in a temporary directory so the seed it saves is discarded.
func TestMachinePanicCanary(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		chdir(t, t.TempDir())
		panicker.Run(t, 2000)
		return
	}
	out, err := runChild(t, "^TestMachinePanicCanary$")
	if err == nil {
		t.Fatalf("planted panic not found in 2000 cases; output:\n%s", out)
	}
	wantAll(t, out, "index out of range", "inc panicked", "op sequence",
		"shrunk failing input", "saved failing input")
}

// bubblePanicker is panicker under Bubble, for the symmetry check
// below. It saves no seed: the corpus path is covered by panicker.
var bubblePanicker = Machine[*counter]{Bubble: true, Init: panicker.Init, Ops: panicker.Ops}

// TestMachineBubblePanicCanary proves a panic shrinks the same way with
// a bubble around the sequence as without one. Bubbled machines used to
// convert op panics to failures by accident, as a side effect of the
// recover that exists for the bubble's exit check, so whether a panic
// shrank depended on a flag that has nothing to do with panics.
func TestMachineBubblePanicCanary(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		bubblePanicker.Run(t, 2000)
		return
	}
	out, err := runChild(t, "^TestMachineBubblePanicCanary$")
	if err == nil {
		t.Fatalf("planted panic not found in 2000 cases; output:\n%s", out)
	}
	wantAll(t, out, "index out of range", "inc panicked", "op sequence", "shrunk failing input")
}

// TestMachineTracePanic proves Trace surfaces a panicking input rather
// than swallowing it. corpus.Audit is built on Trace, so a blanket
// recover here made the audit report the most broken seed in a corpus
// as decoding to nothing.
func TestMachineTracePanic(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		// Seven zero bytes decode to seven "inc" ops, the seventh of
		// which panics.
		t.Logf("trace: %q", panicker.Trace(t, make([]byte, 7)))
		return
	}
	out, err := runChild(t, "^TestMachineTracePanic$")
	if err == nil {
		t.Fatalf("Trace hid a panicking input; output:\n%s", out)
	}
	wantAll(t, out, "index out of range", "inc panicked", `inc (panicked:`)
}

// worker is a system under test exercised under Bubble: "spawn" starts
// a goroutine that sleeps for up to an hour before reporting, and waits
// for the report; "sleep" and "settle" advance and quiesce the bubble.
// The sleeps cost no real time, and the bubble's exit check fails the
// case if any goroutine outlives the op sequence.
type worker struct {
	spawned, reported int
}

var napGen = Duration(0, time.Hour)

var workers = Machine[*worker]{
	Bubble: true,
	Init:   func(t *T) *worker { return new(worker) },
	Ops: []Op[*worker]{
		{Name: "spawn", Weight: 3, Apply: func(t *T, w *worker) {
			d := napGen(t.Tape)
			w.spawned++
			done := make(chan struct{})
			go func() {
				time.Sleep(d)
				close(done)
			}()
			<-done
			w.reported++
		}},
		{Name: "sleep", Apply: func(t *T, w *worker) { time.Sleep(napGen(t.Tape)) }},
		{Name: "settle", Apply: func(t *T, w *worker) { synctest.Wait() }},
	},
	Check: func(t *T, w *worker) {
		if w.reported != w.spawned {
			t.Fatalf("%d reports from %d goroutines", w.reported, w.spawned)
		}
	},
}

// TestMachineBubble runs a machine whose ops spawn goroutines that sleep
// for virtual hours. It passes only if every case ends with no goroutine
// left durably blocked and the sleeps cost no real time.
func TestMachineBubble(t *testing.T) {
	start := time.Now()
	workers.Run(t, 50)
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("Run took %v of real time; sleeps were not virtual", d)
	}
}

// leaker is the Bubble canary system under test: "leak" starts a
// goroutine that blocks forever, which the bubble's exit check must
// catch, and "noop" gives the shrinker something to remove.
var leaker = Machine[*counter]{
	Bubble: true,
	Init:   func(t *T) *counter { return new(counter) },
	Ops: []Op[*counter]{
		{Name: "noop", Weight: 3, Apply: func(t *T, c *counter) { c.n++ }},
		{Name: "leak", Apply: func(t *T, c *counter) {
			go func() { <-make(chan struct{}) }()
		}},
	},
}

// TestMachineBubbleCanary proves a leak is an ordinary failure rather
// than the end of the test binary: the bubble reports the blocked
// goroutine's stack, and Run goes on to shrink the input and save it,
// which it can only do if it survived the bubble's panic. The failing
// Run executes in a child process so the failure does not fail this
// test.
func TestMachineBubbleCanary(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		leaker.Run(t, 200)
		return
	}
	out, err := runChild(t, "^TestMachineBubbleCanary$")
	if err == nil {
		t.Fatalf("planted leak not found in 200 cases; output:\n%s", out)
	}
	wantAll(t, out, "deadlock", "synctest bubble", "op sequence", "shrunk failing input")
}

// TestCorpusFileRoundTrip covers the seed corpus reader against the
// writer's own output, including inputs that need escaping.
func TestCorpusFileRoundTrip(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{0},
		[]byte("plain"),
		{0x00, 0x22, 0x5c, 0xff, '\n', '\t'},
		bytes.Repeat([]byte{0xde, 0xad}, 64),
	} {
		t.Run("", func(t *testing.T) {
			chdir(t, t.TempDir())
			path, err := writeCorpusFile("FuzzX", data)
			if err != nil {
				t.Fatalf("writeCorpusFile: %v", err)
			}
			got, err := readCorpusFile(path)
			if err != nil {
				t.Fatalf("readCorpusFile: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("round trip = %x, want %x", got, data)
			}
		})
	}
}

// TestCorpusFileRejectsOtherShapes proves the reader refuses the corpus
// records it cannot faithfully decode instead of guessing.
func TestCorpusFileRejectsOtherShapes(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct{ name, content string }{
		{"wrong version", "go test fuzz v2\n[]byte(\"a\")\n"},
		{"multiple values", "go test fuzz v1\nstring(\"a\")\nint(1)\n"},
		{"not bytes", "go test fuzz v1\nstring(\"a\")\n"},
		{"unquotable", "go test fuzz v1\n[]byte(nope)\n"},
		{"empty", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "seed")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := readCorpusFile(path); err == nil {
				t.Error("readCorpusFile accepted a record it cannot decode")
			}
		})
	}
}

// TestMachineRunReplaysSeeds proves the corpus is checked by an
// ordinary test run: a saved seed that trips the invariant must fail
// Run even though Run's own random cases would not reach it.
func TestMachineRunReplaysSeeds(t *testing.T) {
	if os.Getenv("FUZZTAPE_CANARY") == "1" {
		// The child plants a seed that drives the counter to 7 with
		// seven "inc" ops, then runs a machine with zero random cases:
		// only the seed can fail it.
		chdir(t, t.TempDir())
		if _, err := writeCorpusFile("FuzzSeeded", make([]byte, 7)); err != nil {
			t.Fatalf("writeCorpusFile: %v", err)
		}
		seeded := Machine[*counter]{
			Init: canary.Init, Ops: canary.Ops, Check: canary.Check, Name: "FuzzSeeded",
		}
		seeded.Run(t, 1)
		return
	}
	out, err := runChild(t, "^TestMachineRunReplaysSeeds$")
	if err == nil {
		t.Fatalf("saved seed did not fail Run; output:\n%s", out)
	}
	wantAll(t, out, "seed/fuzztape-", "planted violation", "already minimal")
}

// runChild re-runs one of this binary's tests in a child process, so a
// deliberately failing test does not fail the parent.
func runChild(t *testing.T, run string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run", run, "-test.v")
	cmd.Env = append(os.Environ(), "FUZZTAPE_CANARY=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// wantAll fails t for every want missing from out.
func wantAll(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("child output missing %q; output:\n%s", want, out)
		}
	}
}

// chdir moves into dir for the duration of the test. It exists because
// the corpus paths are relative to the working directory.
func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
}

// FuzzMachineCanaryClean is the fuzz-mode integration check: the clean
// machine holds under arbitrary inputs. Run with -fuzz to explore.
func FuzzMachineCanaryClean(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 128))
	clean.Fuzz(f)
}
