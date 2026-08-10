// Command iroh-wire-drift checks the small upstream-main wire-vector suite.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/tmc/go-iroh/iroh-compat-harness/runner"
)

func main() {
	version := flag.String("iroh-version", ">=NEXT", "upstream prediction key")
	vector := flag.String("rust-vector", "", "path to the Rust vector driver")
	scenarios := flag.String("scenarios", "scenarios", "scenario declaration directory")
	flag.Parse()

	report := runner.Report{
		Schema: runner.Schema,
		Cells:  runner.RunCustomAddrLive(*vector, *version),
	}
	if err := runner.ApplyExpectedSubset(*scenarios, *version, report.Cells); err != nil {
		fatal(err)
	}
	if err := report.Validate(); err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report.Cells); err != nil {
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
