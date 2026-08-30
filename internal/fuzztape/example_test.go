package fuzztape_test

import (
	"fmt"

	"github.com/tmc/go-iroh/internal/fuzztape"
)

// A Tape decodes a fuzz input front to back; reads past the end return
// zero values, so any prefix of an input is itself a valid input.
func Example() {
	tape := fuzztape.New([]byte{0x2a, 0x03})
	fmt.Println(tape.Byte())
	fmt.Println(tape.Bool())
	fmt.Println(tape.Byte()) // exhausted: zero value
	// Output:
	// 42
	// true
	// 0
}

// Generators compose over a tape; a zero (or exhausted) tape decodes to
// the simplest value each generator offers.
func ExampleGen() {
	size := fuzztape.IntRange(1, 8)
	sizes := fuzztape.SliceOf(size, 4)
	fmt.Println(sizes(fuzztape.New(nil)))
	fmt.Println(size(fuzztape.New([]byte{2}))) // selector 2 forces the upper boundary
	// Output:
	// []
	// 8
}

func ExamplePick() {
	tape := fuzztape.New(nil)
	fmt.Println(fuzztape.Pick(tape, []string{"open", "close", "reset"}))
	// Output:
	// open
}

// Weighted selects proportionally; a zero tape takes the first option
// with a positive weight.
func ExampleWeighted() {
	g := fuzztape.Weighted([]string{"read", "write"}, []int{1, 9})
	fmt.Println(g(fuzztape.New(nil)))
	// Output:
	// read
}

// Float64 skews toward the values that break arithmetic. Selector 6
// draws NaN, which a uniform bit pattern reaches vanishingly rarely.
func ExampleFloat64() {
	g := fuzztape.Float64()
	fmt.Println(g(fuzztape.New(nil)))
	fmt.Println(g(fuzztape.New([]byte{6})))
	// Output:
	// 0
	// NaN
}

// An op can draw its parameter through a generator, which keeps the
// value typed and lets the same draw drive a reference implementation.
func ExampleNewOp() {
	type queue struct{ xs []int }
	op := fuzztape.NewOp("push", fuzztape.IntRange(1, 100),
		func(t *fuzztape.T, q *queue, v int) { q.xs = append(q.xs, v) })
	fmt.Println(op.Name)
	// Output:
	// push
}
