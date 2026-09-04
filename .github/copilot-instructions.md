# Review instructions for go-iroh

A pure-Go port of [iroh](https://github.com/n0-computer/iroh): QUIC connections
between endpoints identified by public key, with relay fallback. One module, no
dependencies outside `golang.org/x/*`.

Review as the Go project would: see [Go Code Review
Comments](https://go.dev/wiki/CodeReviewComments). Prefer specific findings
about correctness, compatibility, and documentation accuracy over style notes.

## Compatibility

Pre-1.0. A patch release (v0.1.x) may add exported symbols but never remove one
or change its type; a minor release (v0.2.0) may break. See [Keeping your
modules compatible](https://go.dev/blog/module-compatibility) and [Go 1 and the
Future of Go Programs](https://go.dev/doc/go1compat).

Flag anything that stops downstream code compiling, and name which use breaks —
the last three are *additions*, which
[gorelease](https://pkg.go.dev/golang.org/x/exp/cmd/gorelease) reports as
compatible:

- **call-breaking** — symbol removed or renamed, parameter list changed.
- **value-breaking** — the function's type changes, so `var f func() *T = New`
  fails though every call still compiles. Adding variadic options does this.
- **literal-breaking** — a new exported struct field breaks unkeyed literals.
- **implementer-breaking** — a new interface method breaks outside implementers.
- **embed-breaking** — a new name collides in types that embed this one.

## Documentation

Doc comments follow [go.dev/doc/comment](https://go.dev/doc/comment).

Doc links and README prose are not compiled, so an exported identifier named in
either can silently go missing. Report identifiers that do not exist in the tree.

Check each doc comment against the code: report where it claims more than the
implementation does — an unconditional rule where the code has a condition, an
invariant the code does not maintain, a hard-coded constant that will drift from
its named default. This is the most useful review this repo gets.

## Examples

`example_test.go` files are documentation and readers copy them (see
[testable examples](https://go.dev/blog/examples)). Hold them above test code:
no discarded errors, no value used before its error is checked, no cleanup that
can panic on a nil returned alongside an error.

## internal/qng

A vendored fork of [quic-go](https://github.com/quic-go/quic-go), kept close to
upstream so new releases can be merged; `anchor.go` records the base release.
Do not suggest renames or idiomatic rewrites there — divergence costs us at
every merge. Do report defects, and say whether the code is upstream's or the
fork's, since fork code often mirrors an upstream function and can still carry a
bug upstream already fixed.

## Concurrency

Report races, lock-ordering problems, and state read outside its guarding lock;
run findings against the [Go Memory Model](https://go.dev/ref/mem). Tests that
infer blocking from elapsed time are flaky under CI load — prefer synchronising
on the event.
