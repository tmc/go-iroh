//go:build go1.27

package fuzztape

// This file holds the method spellings that generic methods (go1.27)
// permit. Each is a one-line delegation to the portable free function,
// which stays the canonical spelling: the module's floor is go 1.26,
// and these methods do not exist under a 1.26 toolchain, which cannot
// parse them. Code that must build under 1.26 has to use the free
// functions.
//
// The methods are declared on *Tape rather than on *T so that they
// promote through the embedded *Tape to every op's *T as well; that
// promotion is verified by TestGenericMethodPromotion.
//
// The build tag is what keeps a 1.26 build working, but it does not
// help gofmt, which parses a file whether or not its tag selects it.
// Formatting this repo therefore requires a 1.27 or later gofmt; CI
// runs the format check only on that toolchain.
//
// When the floor moves to 1.27 this file folds into tape.go and gen.go
// and the tag comes off.

// Draw returns a value of g decoded from the tape. It is g(t) as a
// method, for left-to-right composition.
func (t *Tape) Draw[V any](g Gen[V]) V {
	return g(t)
}

// Pick returns one of opts, chosen by the tape. It is the free
// function Pick as a method.
func (t *Tape) Pick[V any](opts []V) V {
	return Pick(t, opts)
}

// OneOf returns a value drawn from one of gens, chosen by the tape.
func (t *Tape) OneOf[V any](gens ...Gen[V]) V {
	return OneOf(gens...)(t)
}

// Map returns a generator that yields f applied to g's values. It is
// the free function Map as a method.
func (g Gen[A]) Map[B any](f func(A) B) Gen[B] {
	return Map(g, f)
}
