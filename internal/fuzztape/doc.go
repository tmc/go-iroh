/*
Package fuzztape adapts go test -fuzz for typed and stateful testing.

The fuzzing engine built into go test mutates and minimizes flat byte
slices. Fuzztape layers structure on top of those bytes without hiding
them from the engine, so coverage guidance, corpus files, and input
minimization keep working while tests operate on typed values and
operation sequences.

# Tapes

A [Tape] reads a fuzz input as a sequence of typed decisions: bytes,
booleans, integers, and choices. Reads past the end of the input return
zero values, so every input decodes to a valid value and shorter inputs
decode to simpler ones. Consumption is strictly front-to-back, which
lets the engine's byte-level minimizer shrink decoded values and
operation sequences without knowing they exist: truncating an input
truncates the decoded behavior.

[Tape.IntN] deliberately skews toward boundary values — 0, 1, n-1, and
powers of two — because most bugs live at boundaries and uniform random
bytes rarely land there. [Float64] and [StringUTF8] skew the same way,
toward NaN and the infinities, toward the UTF-8 encoding boundaries.

# Generators

A [Gen] composes typed generators over a Tape. Generators are plain
functions, combined with [Const], [IntRange], [OneOf], [Map], [Weighted],
and [SliceOf]; every generator bottoms out in Tape reads, so the tape's
decoding and shrinking properties hold for generated values
automatically.

# Machines

A [Machine] runs a stateful property test: each fuzz input decodes to a
bounded sequence of operations applied to a fresh system under test,
with an invariant checked after every step. A machine runs either under
go test -fuzz ([Machine.Fuzz]) or as a bounded number of pseudo-random
cases inside an ordinary test ([Machine.Run]), sharing one corpus: a
failure found by either is shrunk, saved as a seed input, and replayed
by both. A panic out of an op counts as a failure and takes that same
path, so the crash a fuzz target most often finds arrives as a minimal
op sequence rather than as a raw traceback.

A typical machine and its two entry points:

	var m = fuzztape.Machine[*Stack]{
		Init: func(t *fuzztape.T) *Stack { return new(Stack) },
		Ops: []fuzztape.Op[*Stack]{
			{Name: "push", Apply: func(t *fuzztape.T, s *Stack) {
				s.Push(t.Byte())
			}},
			{Name: "pop", When: func(s *Stack) bool { return s.Len() > 0 },
				Apply: func(t *fuzztape.T, s *Stack) {
					s.Pop()
				}},
		},
		Check: func(t *fuzztape.T, s *Stack) {
			if s.Len() < 0 {
				t.Fatalf("negative length %d", s.Len())
			}
		},
		Name: "FuzzStack",
	}

	func FuzzStack(f *testing.F)  { m.Fuzz(f) }
	func TestStack(t *testing.T)  { m.Run(t, 500) }

Setting [Machine.Bubble] runs each case inside a [testing/synctest]
bubble: time is virtual, and the bubble's exit check turns every case
into a goroutine-leak check.

# The T

Ops, Init, and Check receive a [T]: the tape they draw from and the
failure reporting of the test running them, in one value. Report a
violation with [T.Fatalf], abandon an op that turns out not to apply
with [T.Reject], and assert what should hold once the sequence has
settled from [T.Cleanup].

T embeds *Tape but not *testing.T, which is deliberate. Embedding the
test would hand every op Run, Parallel, and Skip, each of which either
panics inside a synctest bubble or abandons a sequence mid-flight.

# Subpackages

Each subpackage addresses one way a stateful test can pass while
testing nothing.

  - budget bounds work and resources: an allocation ceiling tied to
    input size, and a ledger that requires every acquire to be matched
    by a release before the sequence ends.
  - corpus loads seed inputs from a directory and reports the ones that
    no longer decode to a distinct op sequence.
  - faults injects tape-driven I/O faults, so a shrunk input names the
    single fault that breaks an invariant.
  - linear checks that a concurrent history is linearizable, for the
    overlapping operations a per-op comparison cannot judge.
  - model checks a system under test against a reference implementation
    or a second real one, comparing results and not only state.
  - sched makes goroutine interleaving a tape decision, so a race
    reproduces from its corpus file and shrinks.
  - splice builds seeds by crossing corpus inputs at the operation
    boundaries [Machine.Splits] recovers.
  - stats counts how often each op actually runs, turning a machine
    that has silently stopped exercising an operation into a visible
    gap.
  - trace turns a failing input into a test you can paste.

Command fuzztape runs every fuzz target in a module, which go test
cannot: -fuzz takes one target in one package per invocation.

# Go version

The module builds with Go 1.26 and later. Under Go 1.27 and later it
additionally provides method spellings of four of its functions —
[Tape.Draw], [Tape.Pick], [Tape.OneOf], and [Gen.Map] — for
left-to-right composition. Those methods are compiled only by a 1.27
or later toolchain, and this documentation is built by one, so it
lists them unconditionally: code that must build under 1.26 has to use
the free functions [Pick], [OneOf], and [Map] instead.

# API stability

This package is pre-v1 and its API is not yet stable. It may change
without notice.
*/
package fuzztape
