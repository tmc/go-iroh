package main

import (
	"errors"
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
	goRelay := flag.String("go-relay", "", "path to the go-iroh relay binary")
	rustRelay := flag.String("rust-relay", "", "path to the pinned upstream iroh-relay binary")
	goDNS := flag.String("go-dns", "", "path to the go-iroh DNS server binary")
	rustDNS := flag.String("rust-dns", "", "path to the pinned upstream iroh-dns-server binary")
	vector := flag.String("rust-vector", "", "path to the pinned Rust vector driver")
	pq := flag.String("rust-pq", "", "path to the pinned Rust PQ peer")
	flag.Parse()

	root, err := repoRoot()
	if err != nil {
		fatal(err)
	}
	report := runner.Report{Schema: runner.Schema, Generated: time.Now().UTC(), GoIroh: runner.GoIroh{Version: "main", Commit: gitCommit(root)}}
	report.Cells = runner.RunVectorCorpus(*vector, filepath.Join(root, "iroh-compat-harness", "vectors", "corpus.json"), *version)
	report.Cells = append(report.Cells, runEcho(*doctor, *version)...)
	report.Cells = append(report.Cells, runRelay(*goRelay, *rustRelay, *vector, *version)...)
	report.Cells = append(report.Cells, runDiscovery(*goDNS, *rustDNS, *rustRelay, *vector, *version)...)
	report.Cells = append(report.Cells, runQAD(*doctor, *version))
	report.Cells = append(report.Cells, runTransport(*vector, *version)...)
	report.Cells = append(report.Cells, runGossip(*vector, *version))
	report.Cells = append(report.Cells, runPQ(*pq, *version)...)
	if err := runner.ApplyExpected(filepath.Join(root, "iroh-compat-harness", "scenarios"), *version, report.Cells); err != nil {
		fatal(err)
	}
	if err := report.Write(filepath.Join(root, "iroh-compat-harness", "results"), root); err != nil {
		fatal(err)
	}
}

func runPQ(bin, version string) []runner.Cell {
	scenarios := []string{"handshake/pq-only", "handshake/prefer-pq"}
	digest, err := peerDigest(bin, "set the pinned Rust PQ peer binary path")
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	return runner.RunPQMatrix(bin, version, digest)
}

func runQAD(bin, version string) runner.Cell {
	digest, err := peerDigest(bin, "set the pinned iroh-doctor binary path")
	if err != nil {
		return setupCells([]string{"discovery/qad-report"}, version, err.Error())[0]
	}
	return runner.RunQADReport(bin, version, digest)
}

func runGossip(rustClient, version string) runner.Cell {
	if version != "1.0.3" {
		return runner.Cell{Scenario: "vectors/gossip-frame", Iroh: version, Result: runner.Unsupported, Detail: "the Rust gossip test driver is pinned to iroh 1.0.3"}
	}
	digest, err := peerDigest(rustClient, "set the pinned Rust driver binary path")
	if err != nil {
		return runner.Cell{Scenario: "vectors/gossip-frame", Iroh: version, Result: runner.SetupError, Detail: err.Error()}
	}
	return runner.RunGossip(rustClient, version, digest)
}

func runTransport(rustClient, version string) []runner.Cell {
	scenarios := []string{"handshake/datagrams", "handshake/close-semantics", "handshake/remote-info", "handshake/zero-rtt"}
	digest, err := peerDigest(rustClient, "set the pinned Rust driver binary path")
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	return runner.RunTransportMatrix(rustClient, version, digest)
}

func runDiscovery(goDNS, rustDNS, rustRelay, rustClient, version string) []runner.Cell {
	scenarios := []string{"discovery/go-publish-rust-dns", "discovery/rust-publish-go-dns", "discovery/relay-urls"}
	if goDNS == "" || rustDNS == "" || rustRelay == "" || rustClient == "" {
		return setupCells(scenarios, version, "set the Go DNS, pinned upstream DNS and relay, and pinned Rust driver binary paths")
	}
	dnsDigest, err := runner.FileDigest(rustDNS)
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	relayDigest, err := runner.FileDigest(rustRelay)
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	clientDigest, err := runner.FileDigest(rustClient)
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	return runner.RunDiscovery(goDNS, rustDNS, rustRelay, rustClient, version, dnsDigest, relayDigest, clientDigest)
}

func runRelay(goRelay, rustRelay, rustClient, version string) []runner.Cell {
	scenarios := []string{
		"relay/go-client-rust-relay",
		"relay/rust-client-go-relay",
		"relay/rust-client-rust-relay",
		"relay/websocket-upgrade",
		"relay/ping-pong",
		"relay/idle-timeout",
	}
	if goRelay == "" || rustRelay == "" || rustClient == "" {
		return setupCells(scenarios, version, "set the Go relay, pinned upstream iroh-relay, and pinned Rust driver binary paths")
	}
	rustRelayDigest, err := runner.FileDigest(rustRelay)
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	rustClientDigest, err := runner.FileDigest(rustClient)
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	return runner.RunRelayMatrix(goRelay, rustRelay, rustClient, version, rustRelayDigest, rustClientDigest)
}

func runEcho(doctor, version string) []runner.Cell {
	scenarios := []string{
		"handshake/go-client-rust-server",
		"handshake/rust-client-go-server",
		"handshake/alpn-mismatch",
		"handshake/wrong-endpoint-id",
	}
	const detail = "set RUST_DOCTOR_BIN to an unmodified iroh-doctor 0.101.0 binary built against the pinned iroh release"
	digest, err := peerDigest(doctor, detail)
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	return runner.RunDoctorEcho(doctor, version, digest)
}

func peerDigest(path, missing string) (string, error) {
	if path == "" {
		return "", errors.New(missing)
	}
	return runner.FileDigest(path)
}

func setupCells(scenarios []string, version, detail string) []runner.Cell {
	cells := make([]runner.Cell, len(scenarios))
	for i, scenario := range scenarios {
		cells[i] = runner.Cell{Scenario: scenario, Iroh: version, Result: runner.SetupError, Detail: detail}
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
	out, err := exec.Command("git", "-C", root, "describe", "--always", "--dirty").Output()
	if err != nil {
		return "unknown"
	}
	return string(out[:len(out)-1])
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "iroh-compat:", err)
	os.Exit(1)
}
