package fuzztape

import (
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// A Gen decodes a value of type V from a tape. A generator is a plain
// function: composite generators are written as func literals calling
// other generators, and every Gen bottoms out in Tape reads, so the
// tape's decoding and shrinking properties hold for generated values
// automatically.
//
// The type parameter is named V rather than the conventional T because
// this package has a type named [T].
type Gen[V any] func(*Tape) V

// Const returns a generator that always yields v.
func Const[V any](v V) Gen[V] {
	return func(*Tape) V { return v }
}

// IntRange returns a generator of integers in [lo, hi].
// It panics if hi < lo.
func IntRange(lo, hi int) Gen[int] {
	if hi < lo {
		panic("fuzztape: IntRange called with hi < lo")
	}
	return func(t *Tape) int { return lo + t.IntN(hi-lo+1) }
}

// OneOf returns a generator that defers to one of gens.
// It panics if gens is empty.
func OneOf[V any](gens ...Gen[V]) Gen[V] {
	if len(gens) == 0 {
		panic("fuzztape: OneOf called with no generators")
	}
	return func(t *Tape) V { return gens[t.IntN(len(gens))](t) }
}

// Map returns a generator that yields f applied to g's values.
func Map[A, B any](g Gen[A], f func(A) B) Gen[B] {
	return func(t *Tape) B { return f(g(t)) }
}

// Or returns a generator that defers to g or one of alts.
// It is OneOf as a method, for left-to-right composition.
func (g Gen[V]) Or(alts ...Gen[V]) Gen[V] {
	return OneOf(append([]Gen[V]{g}, alts...)...)
}

// SliceOf returns a generator of slices of up to max values of g.
// It panics if max is negative or [math.MaxInt].
func SliceOf[V any](g Gen[V], max int) Gen[[]V] {
	n := lengths("SliceOf", max)
	return func(t *Tape) []V {
		out := make([]V, t.IntN(n))
		for i := range out {
			out[i] = g(t)
		}
		return out
	}
}

// Weighted returns a generator of opts, selecting opts[i] with
// frequency proportional to weights[i]. It panics unless opts and
// weights have the same non-zero length, every weight is non-negative,
// at least one is positive, and they sum within int. A zero tape yields
// the first option with a positive weight.
func Weighted[V any](opts []V, weights []int) Gen[V] {
	if len(opts) == 0 {
		panic("fuzztape: Weighted called with no options")
	}
	if len(opts) != len(weights) {
		panic("fuzztape: Weighted called with mismatched options and weights")
	}
	total := 0
	for _, w := range weights {
		if w < 0 {
			panic("fuzztape: Weighted called with a negative weight")
		}
		if total > math.MaxInt-w {
			panic("fuzztape: Weighted called with weights summing past int")
		}
		total += w
	}
	if total == 0 {
		panic("fuzztape: Weighted called with all-zero weights")
	}
	return func(t *Tape) V {
		n := t.IntN(total)
		for i, w := range weights {
			if n -= w; n < 0 {
				return opts[i]
			}
		}
		return opts[len(opts)-1]
	}
}

// Float64 returns a generator of float64 values, skewed like [Tape.IntN]
// toward the values that break arithmetic: zero, negative zero, both
// infinities, NaN, the subnormal boundary, and the largest magnitudes.
// A zero tape yields 0.
//
// The unskewed case draws a uniform bit pattern, so NaN payloads and
// subnormals occur naturally as well.
func Float64() Gen[float64] {
	return func(t *Tape) float64 {
		switch t.Byte() {
		case 0:
			return 0
		case 1:
			return 1
		case 2:
			return -1
		case 3:
			return math.Copysign(0, -1)
		case 4:
			return math.Inf(1)
		case 5:
			return math.Inf(-1)
		case 6:
			return math.NaN()
		case 7:
			return math.SmallestNonzeroFloat64
		case 8:
			return math.MaxFloat64
		case 9:
			return -math.MaxFloat64
		}
		return math.Float64frombits(t.Uint64())
	}
}

// Float32 returns a generator of float32 values, skewed as [Float64] is.
// A zero tape yields 0.
func Float32() Gen[float32] {
	return func(t *Tape) float32 {
		switch t.Byte() {
		case 0:
			return 0
		case 1:
			return 1
		case 2:
			return -1
		case 3:
			return float32(math.Copysign(0, -1))
		case 4:
			return float32(math.Inf(1))
		case 5:
			return float32(math.Inf(-1))
		case 6:
			return float32(math.NaN())
		case 7:
			return math.SmallestNonzeroFloat32
		case 8:
			return math.MaxFloat32
		case 9:
			return -math.MaxFloat32
		}
		return math.Float32frombits(uint32(t.Uint64()))
	}
}

// StringASCII returns a generator of printable-ASCII strings of length
// in [0, max]. A zero tape yields "". It panics if max is negative or
// [math.MaxInt].
func StringASCII(max int) Gen[string] {
	n := lengths("StringASCII", max)
	return func(t *Tape) string {
		b := make([]byte, t.IntN(n))
		for i := range b {
			b[i] = ' ' + t.Byte()%('~'-' '+1)
		}
		return string(b)
	}
}

// StringUTF8 returns a generator of valid UTF-8 strings of up to max
// runes, skewed toward the runes that break text handling: NUL, the
// ASCII and multi-byte boundaries, a combining mark, the replacement
// character, and the largest legal rune. A zero tape yields "".
//
// Every string it produces is valid UTF-8 by construction. To generate
// invalid encodings — a lone surrogate, a truncated sequence, an
// overlong form — draw raw bytes with [Tape.Bytes] instead; a generator
// that returns a string cannot represent them.
//
// It panics if max is negative or [math.MaxInt].
func StringUTF8(max int) Gen[string] {
	n := lengths("StringUTF8", max)
	return func(t *Tape) string {
		var b strings.Builder
		for range t.IntN(n) {
			b.WriteRune(utf8Rune(t))
		}
		return b.String()
	}
}

// utf8Rune draws one legal rune, skewed toward encoding boundaries.
func utf8Rune(t *Tape) rune {
	switch t.Byte() {
	case 0:
		return 'a'
	case 1:
		return 0 // NUL
	case 2:
		return 0x7f // last 1-byte rune
	case 3:
		return 0x80 // first 2-byte rune
	case 4:
		return 0x7ff // last 2-byte rune
	case 5:
		return 0x800 // first 3-byte rune
	case 6:
		return 0x0301 // combining acute accent
	case 7:
		return utf8.RuneError
	case 8:
		return 0xffff // last 3-byte rune
	case 9:
		return 0x10000 // first 4-byte rune
	case 10:
		return utf8.MaxRune
	}
	// Surrogates are not legal runes; WriteRune would silently
	// substitute RuneError, so skip the range explicitly.
	r := rune(t.Uint64() % (utf8.MaxRune + 1 - (0xe000 - 0xd800)))
	if r >= 0xd800 {
		r += 0xe000 - 0xd800
	}
	return r
}

// Duration returns a generator of durations in [lo, hi]. It panics if
// hi < lo or if the span exceeds the range of int. A zero tape yields
// lo.
//
// Under [Machine.Bubble] a drawn duration costs no real time, which is
// what makes timeout and retry paths cheap to explore.
func Duration(lo, hi time.Duration) Gen[time.Duration] {
	if hi < lo {
		panic("fuzztape: Duration called with hi < lo")
	}
	span := uint64(hi - lo)
	if span >= math.MaxInt {
		panic("fuzztape: Duration called with a span exceeding int")
	}
	return func(t *Tape) time.Duration {
		return lo + time.Duration(t.IntN(int(span)+1))
	}
}
