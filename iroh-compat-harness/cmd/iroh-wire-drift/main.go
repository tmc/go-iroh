// Command iroh-wire-drift checks the small upstream-main wire-vector suite.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/tmc/go-iroh/iroh-compat-harness/runner"
)

func main() {
	expected := flag.String("expected-key", "1.1-pre", "pinned prediction key")
	vector := flag.String("rust-vector", "", "path to the Rust vector driver")
	scenarios := flag.String("scenarios", "scenarios", "scenario declaration directory")
	repo := flag.String("repo", "..", "go-iroh repository root")
	commitOverride := flag.String("commit", "", "go-iroh source commit override")
	upstreamCommit := flag.String("upstream-commit", "", "upstream main commit")
	upstreamDescribe := flag.String("upstream-describe", "", "git describe of upstream main")
	jsonOutput := flag.String("json", "results/tip.json", "tip evidence output")
	markdownOutput := flag.String("markdown", "../COMPATIBILITY-tip.md", "tip Markdown output")
	flag.Parse()

	goCommit, err := runner.SourceCommit(filepath.Clean(*repo), *commitOverride)
	if err != nil {
		fatal(err)
	}
	report := runner.TipReport{
		Schema: runner.TipSchema, Generated: time.Now().UTC(), GoCommit: goCommit,
		UpstreamCommit: *upstreamCommit, UpstreamDescribe: *upstreamDescribe, ExpectedPin: *expected,
		Cells: runner.RunCustomAddrLive(*vector, "tip"),
	}
	if err := runner.ApplyExpectedSubset(*scenarios, *expected, report.Cells); err != nil {
		fatal(err)
	}
	if err := report.Write(*jsonOutput, *markdownOutput); err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fatal(err)
	}
	if err := report.Unexpected(); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "iroh-wire-drift:", err)
	os.Exit(1)
}
