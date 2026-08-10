package runner

import (
	"strings"
	"testing"
	"time"
)

func TestPassRequiresRustPeerEvidence(t *testing.T) {
	c := Cell{Scenario: "echo", Description: "A pass proves echo.", Counterpart: "upstream CLI", Iroh: "1.0.3", Result: Pass}
	if err := c.Validate(); err == nil {
		t.Fatal("pass without Rust peer evidence was accepted")
	}
	c.Peer = "iroh-doctor@sha256:abc"
	c.PeerPID = 42
	c.PeerDigest = "sha256:abc"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestCellRequiresDescription(t *testing.T) {
	c := Cell{Scenario: "echo", Iroh: "1.0.3", Counterpart: "upstream CLI", Result: Fail}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "description is missing") {
		t.Fatalf("Validate() error = %v, want missing description", err)
	}
}

func TestDoctorConnectLineUsesFirstDirectAddress(t *testing.T) {
	line := "iroh-doctor connect " + strings.Repeat("2a", 32) + " --remote-endpoint 127.0.0.1:1234 --remote-endpoint '[::1]:5678'"
	m := doctorConnectLine.FindStringSubmatch(line)
	if len(m) != 3 || m[2] != "127.0.0.1:1234" {
		t.Fatalf("match = %q, want first IPv4 address", m)
	}
}

func TestUnexpectedVerdictFailsEitherDirection(t *testing.T) {
	for _, tt := range []struct {
		result Verdict
		want   Verdict
	}{
		{result: Fail, want: Pass},
		{result: Pass, want: Fail},
	} {
		r := Report{Cells: []Cell{{Scenario: "x", Iroh: "1", Result: tt.result, Expected: tt.want}}}
		if err := r.Unexpected(); err == nil {
			t.Fatalf("result %s, expected %s: mismatch accepted", tt.result, tt.want)
		}
	}
}

func TestMarkdownNamesRustCounterpart(t *testing.T) {
	r := Report{
		Generated: time.Unix(0, 0).UTC(),
		GoIroh:    GoIroh{Commit: "abc123"},
		Cells: []Cell{
			{Scenario: "echo", Description: "Go and Rust exchange an echo, and a pass proves compatible streams.", Counterpart: "upstream CLI", Iroh: "1.0.3", Result: Pass, Peer: "iroh-doctor@sha256:abc"},
			{Scenario: "datagrams", Description: "Go and Rust exchange datagrams, and a pass proves compatible datagrams.", Counterpart: "Rust test driver", Iroh: "1.0.3", Result: Pass, Peer: "rust-driver@sha256:def"},
		},
	}
	got := string(r.Markdown())
	for _, want := range []string{
		"## How to read this table",
		"unsupported` means go-iroh lacks the feature, not that the feature is broken",
		"| Rust counterpart |",
		"| upstream CLI |",
		"| Rust test driver |",
		"SHA-256 digest",
		"## Scenario definitions",
		"Go and Rust exchange an echo",
		"## Reproduce",
		"make parity",
		"[harness README](iroh-compat-harness/README.md)",
		"[results.json](iroh-compat-harness/results/results.json)",
		"Go-client↔Go-relay pairings contain no Rust peer",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Markdown() does not contain %q", want)
		}
	}
	if strings.Contains(got, "| Tier |") {
		t.Error("Markdown() still presents counterpart provenance as a tier")
	}
}
