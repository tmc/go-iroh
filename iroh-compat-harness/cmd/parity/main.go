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
	if err := report.Write(filepath.Join(root, "iroh-compat-harness", "results"), root); err != nil {
		fatal(err)
	}
}

func runEcho(doctor, version string) []runner.Cell {
	const detail = "set RUST_DOCTOR_BIN to an unmodified iroh-doctor 0.101.0 binary built against the pinned iroh release"
	if doctor == "" {
		return []runner.Cell{
			{Scenario: "handshake/go-client-rust-server", Iroh: version, Tier: "A", Result: runner.SetupError, Expected: runner.Pass, Detail: detail},
			{Scenario: "handshake/rust-client-go-server", Iroh: version, Tier: "A", Result: runner.SetupError, Expected: runner.Pass, Detail: detail},
		}
	}
	digest, err := runner.FileDigest(doctor)
	if err != nil {
		return []runner.Cell{{Scenario: "handshake/doctor", Iroh: version, Tier: "A", Result: runner.SetupError, Expected: runner.Pass, Detail: err.Error()}}
	}
	return runner.RunDoctorEcho(doctor, version, digest)
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
