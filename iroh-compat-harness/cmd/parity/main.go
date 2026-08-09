package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh-compat-harness/runner"
)

func main() {
	version := flag.String("iroh-version", "1.0.3", "Rust iroh version")
	doctor := flag.String("rust-doctor", "", "path to the pinned iroh-doctor binary")
	flag.Parse()

	root, err := repoRoot()
	if err != nil {
		fatal(err)
	}
	report := runner.Report{Schema: runner.Schema, Generated: time.Now().UTC(), GoIroh: runner.GoIroh{Version: "main", Commit: gitCommit(root)}}
	report.Cells = runEcho(*doctor, *version)
	report.Cells = append(report.Cells, runner.ExtendedCells(*version)...)
	if err := runner.ApplyExpected(filepath.Join(root, "iroh-compat-harness", "scenarios"), *version, report.Cells); err != nil {
		fatal(err)
	}
	if err := report.Write(filepath.Join(root, "iroh-compat-harness", "results"), root); err != nil {
		fatal(err)
	}
}

func runEcho(doctor, version string) []runner.Cell {
	scenarios := []string{
		"handshake/go-client-rust-server",
		"handshake/rust-client-go-server",
		"handshake/alpn-mismatch",
		"handshake/wrong-endpoint-id",
	}
	const detail = "set RUST_DOCTOR_BIN to an unmodified iroh-doctor 0.101.0 binary built against the pinned iroh release"
	if doctor == "" {
		return setupCells(scenarios, version, detail)
	}
	digest, err := runner.FileDigest(doctor)
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	return runner.RunDoctorEcho(doctor, version, digest)
}

func setupCells(scenarios []string, version, detail string) []runner.Cell {
	cells := make([]runner.Cell, len(scenarios))
	for i, scenario := range scenarios {
		cells[i] = runner.Cell{Scenario: scenario, Iroh: version, Tier: "A", Result: runner.SetupError, Expected: runner.Pass, Detail: detail}
	}
	return cells
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			b, _ := os.ReadFile(filepath.Join(dir, "go.mod"))
			if strings.HasPrefix(string(b), "module github.com/tmc/go-iroh\n") {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go-iroh repository root not found")
		}
		dir = parent
	}
}

func gitCommit(root string) string {
	out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		return "unknown"
	}
	return string(out[:len(out)-1])
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "parity:", err)
	os.Exit(1)
}
