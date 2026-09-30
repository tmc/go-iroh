# Synced helpers

`sched` and `budget` were copied from `github.com/tmc/fuzztape` at
`f170d646bc4a7180cdc99d5bbcc145b7ae9c0c5a` on 2026-09-30, including tests.
Only import paths were rewritten to `github.com/tmc/go-iroh/internal/fuzztape`.
The scheduler assigns parked goroutines their spawn order before launching them;
its replay determinism regression tests are included.

The existing root package remains unchanged. Other standalone helpers are not
part of this sync.
