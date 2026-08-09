package runner

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

var vectorScenarios = []string{
	"vectors/keys-z32-sign",
	"vectors/postcard-varints",
	"vectors/endpoint-ticket-roundtrip",
	"vectors/pkarr-txt",
}

func RunVectorCorpus(bin, corpus, version string) []Cell {
	if version != "1.0.3" {
		return vectorCells(version, Unsupported, "the Tier B vector generator is pinned to iroh 1.0.3", "", 0, "")
	}
	if bin == "" {
		return vectorCells(version, SetupError, "RUST_VECTOR_BIN is not set", "", 0, "")
	}
	digest, err := FileDigest(bin)
	if err != nil {
		return vectorCells(version, SetupError, err.Error(), "", 0, "")
	}
	want, err := os.ReadFile(corpus)
	if err != nil {
		return vectorCells(version, SetupError, fmt.Sprintf("read vector corpus: %v", err), "", 0, "")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return vectorCells(version, SetupError, fmt.Sprintf("start Rust vector peer: %v", err), digest, 0, "")
	}
	pid := cmd.Process.Pid
	err = cmd.Wait()
	duration := time.Since(start).Milliseconds()
	peer := "rust-driver@" + digest
	if err != nil {
		return vectorCells(version, Fail, fmt.Sprintf("Rust vector peer: %v: %s", err, stderr.String()), digest, pid, peer)
	}
	if !bytes.Equal(stdout.Bytes(), want) {
		return vectorCells(version, Fail, "fresh Rust vectors differ from committed corpus", digest, pid, peer)
	}
	cells := vectorCells(version, Pass, "fresh Rust output is byte-identical to the Go-verified corpus", digest, pid, peer)
	for i := range cells {
		cells[i].DurationMS = duration
	}
	return cells
}

func vectorCells(version string, result Verdict, detail, digest string, pid int, peer string) []Cell {
	cells := make([]Cell, len(vectorScenarios))
	for i, scenario := range vectorScenarios {
		expected := Pass
		if version != "1.0.3" {
			expected = Unsupported
		}
		cells[i] = Cell{
			Scenario: scenario, Iroh: version, Tier: "B", Result: result, Expected: expected,
			Detail: detail, Peer: peer, PeerPID: pid, PeerDigest: digest,
		}
	}
	return cells
}
