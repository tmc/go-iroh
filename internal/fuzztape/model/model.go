// Package model checks a system under test against a reference model.
//
// A fuzztape [fuzztape.Machine] asserts an invariant: a property of the
// state, checked after every op. That catches a system that reaches an
// impossible state, and misses a system that returns a wrong answer and
// leaves a plausible one — [fuzztape.Op] has no result to inspect, and
// Machine.Check sees only the state that follows.
//
// This package supplies the missing half. A [Pair] holds the system
// under test beside a reference implementation; the op constructors
// apply the same drawn parameter to both and compare what each
// returned. The reference is usually a slow, obviously-correct model —
// a slice standing in for a ring buffer — but it can equally be a
// second real implementation, which makes the same constructors a
// differential test:
//
//	Pair[*Ours, *Theirs]
//
// Both forms shrink like any other machine, so a divergence arrives as
// the shortest op sequence that produces it.
package model

import "github.com/tmc/go-iroh/internal/fuzztape"

// A Pair holds a system under test and the reference it is checked
// against. It is the state type of a model-based machine.
type Pair[S, M any] struct {
	SUT   S
	Model M
}

// Init returns a [fuzztape.Machine] Init that builds both sides.
func Init[S, M any](sut func(t *fuzztape.T) S, model func(t *fuzztape.T) M) func(t *fuzztape.T) Pair[S, M] {
	return func(t *fuzztape.T) Pair[S, M] {
		return Pair[S, M]{SUT: sut(t), Model: model(t)}
	}
}

// Op returns an op that draws one parameter with g, applies it to both
// implementations, and fails the test if they return different values.
//
// The parameter is drawn once and handed to both. Drawing separately
// for each side would be a bug rather than a nicety: a tape is consumed
// front to back, so the second draw would read the bytes after the
// first and drive the model with different input than the system under
// test, reporting a mismatch on every op.
func Op[S, M, A any, R comparable](name string, g fuzztape.Gen[A], sut func(s S, v A) R, model func(m M, v A) R) fuzztape.Op[Pair[S, M]] {
	return OpFunc(name, g, sut, model, func(got, want R) bool { return got == want })
}

// OpFunc is [Op] for a result that is not comparable, or one whose
// equality is not ==: a slice, a struct holding a time, a value with a
// tolerance.
func OpFunc[S, M, A, R any](name string, g fuzztape.Gen[A], sut func(s S, v A) R, model func(m M, v A) R, equal func(got, want R) bool) fuzztape.Op[Pair[S, M]] {
	return fuzztape.Op[Pair[S, M]]{
		Name: name,
		Apply: func(t *fuzztape.T, p Pair[S, M]) {
			v := g(t.Tape)
			got := sut(p.SUT, v)
			want := model(p.Model, v)
			if !equal(got, want) {
				t.Fatalf("%s(%+v) = %+v, model says %+v", name, v, got, want)
			}
		},
	}
}

// Do returns an op that applies a drawn parameter to both
// implementations and compares nothing. It is for operations with no
// observable result, whose divergence shows up in a later op or in
// [Equal].
func Do[S, M, A any](name string, g fuzztape.Gen[A], sut func(s S, v A), model func(m M, v A)) fuzztape.Op[Pair[S, M]] {
	return fuzztape.Op[Pair[S, M]]{
		Name: name,
		Apply: func(t *fuzztape.T, p Pair[S, M]) {
			v := g(t.Tape)
			sut(p.SUT, v)
			model(p.Model, v)
		},
	}
}

// Equal returns a [fuzztape.Machine] Check that compares a projection
// of both implementations after every op — a length, a checksum, a
// sorted key list. It is the state half of the comparison, where the op
// constructors cover the result half.
func Equal[S, M any, R comparable](sut func(s S) R, model func(m M) R) func(t *fuzztape.T, p Pair[S, M]) {
	return EqualFunc(sut, model, func(got, want R) bool { return got == want })
}

// EqualFunc is [Equal] for a projection that is not comparable, or one
// whose equality is not ==.
func EqualFunc[S, M, R any](sut func(s S) R, model func(m M) R, equal func(got, want R) bool) func(t *fuzztape.T, p Pair[S, M]) {
	return func(t *fuzztape.T, p Pair[S, M]) {
		got, want := sut(p.SUT), model(p.Model)
		if !equal(got, want) {
			t.Fatalf("state diverged: system under test %+v, model %+v", got, want)
		}
	}
}
