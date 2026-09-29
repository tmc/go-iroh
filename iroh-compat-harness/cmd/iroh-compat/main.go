package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh-compat-harness/runner"
)

// Iroh-compat runs the parity matrix against one pinned upstream release and
// records the cells in a run file. With -merge, it combines run files for
// several releases into results.json, badge.json, and COMPATIBILITY.md, and
// exits non-zero if any cell disagrees with its expected verdict.
func main() {
	merge := flag.Bool("merge", false, "merge the run files named as arguments into the report")
	releaseVersion := flag.String("release-version", "", "pinned upstream release, such as 1.3.0")
	releaseCommit := flag.String("release-commit", "", "pinned upstream release commit")
	out := flag.String("o", "", "run file to write (default results/runs/iroh-VERSION.json)")
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
	harness := filepath.Join(root, "iroh-compat-harness")
	if *merge {
		if err := mergeRuns(root, harness, flag.Args()); err != nil {
			fatal(err)
		}
		return
	}
	train, err := runner.Train(*releaseVersion)
	if err != nil {
		fatal(err)
	}
	commit, err := gitCommit(root)
	if err != nil {
		fatal(err)
	}
	report := runner.Report{
		Schema: runner.Schema, Generated: time.Now().UTC(), GoIroh: runner.GoIroh{Version: "main", Commit: commit},
		Pins: []runner.Pin{
			{Key: train, Train: train, Version: *releaseVersion, Commit: *releaseCommit, Kind: "release"},
		},
	}
	corpus := filepath.Join(harness, "vectors", "corpus", *releaseVersion+".json")
	report.Cells = runner.RunVectorCorpus(*vector, corpus, train)
	report.Cells = append(report.Cells, runEcho(*doctor, train)...)
	report.Cells = append(report.Cells, runRelay(*goRelay, *rustRelay, *vector, train)...)
	report.Cells = append(report.Cells, runDiscovery(*goDNS, *rustDNS, *rustRelay, *vector, train)...)
	report.Cells = append(report.Cells, runQAD(*doctor, train))
	report.Cells = append(report.Cells, runTransport(*vector, train)...)
	report.Cells = append(report.Cells, runGossip(*vector, train))
	report.Cells = append(report.Cells, runBlobs(*vector, train)...)
	report.Cells = append(report.Cells, runPQ(*pq, train)...)
	if err := runner.ApplyExpected(filepath.Join(harness, "scenarios"), train, report.Cells); err != nil {
		fatal(err)
	}
	if *out == "" {
		*out = filepath.Join(harness, "results", "runs", "iroh-"+*releaseVersion+".json")
	}
	if err := report.WriteRun(*out); err != nil {
		fatal(err)
	}
}

func mergeRuns(root, harness string, paths []string) error {
	if len(paths) == 0 {
		return errors.New("-merge needs at least one run file")
	}
	var runs []runner.Report
	for _, path := range paths {
		run, err := runner.ReadRun(path)
		if err != nil {
			return err
		}
		runs = append(runs, run)
	}
	report, err := runner.Merge(runs)
	if err != nil {
		return err
	}
	scenarioDir := filepath.Join(harness, "scenarios")
	report.Envelopes, err = runner.LoadEnvelopes(scenarioDir)
	if err != nil {
		return err
	}
	report.PeerNotes, err = runner.LoadPeerNotes(scenarioDir)
	if err != nil {
		return err
	}
	return report.Write(filepath.Join(harness, "results"), root)
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
	digest, err := peerDigest(rustClient, "set the pinned Rust driver binary path")
	if err != nil {
		return runner.Cell{Scenario: "vectors/gossip-frame", Iroh: version, Result: runner.SetupError, Detail: err.Error()}
	}
	return runner.RunGossip(rustClient, version, digest)
}

func runBlobs(rustClient, version string) []runner.Cell {
	scenarios := []string{"blobs/rust-get-sendme", "blobs/rust-get-per-child"}
	digest, err := peerDigest(rustClient, "set the pinned Rust driver binary path")
	if err != nil {
		return setupCells(scenarios, version, err.Error())
	}
	return runner.RunBlobs(rustClient, version, digest)
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

func gitCommit(root string) (string, error) {
	return runner.SourceCommit(root)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "iroh-compat:", err)
	os.Exit(1)
}
