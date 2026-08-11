package runner

import (
	"strings"
	"testing"
	"time"
)

func TestPassRequiresRustPeerEvidence(t *testing.T) {
	c := Cell{Scenario: "echo", Description: "A pass proves echo.", Tier: "stable", Counterpart: "upstream CLI", Iroh: "1.0", Result: Pass}
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

func TestAdjudicationRendersEitherUnexpectedDirection(t *testing.T) {
	for _, tt := range []struct {
		cell Cell
		want string
	}{
		{cell: Cell{Result: Fail, Expected: Pass}, want: "FAIL (unexpected)"},
		{cell: Cell{Result: Pass, Expected: Fail}, want: "PASS (unexpected)"},
		{cell: Cell{Result: Fail, Expected: Fail}, want: "fail (expected)"},
	} {
		if got := formatAdjudication(tt.cell, 0); got != tt.want {
			t.Errorf("formatAdjudication(%s, %s) = %q, want %q", tt.cell.Result, tt.cell.Expected, got, tt.want)
		}
	}
}

func TestEnvelopeStatusVocabulary(t *testing.T) {
	for _, status := range []string{"verified-interop", "observed-incompatible", "predicted-interop", "predicted-incompatible", "unsupported", "untested"} {
		r := Report{
			Schema:    Schema,
			Pins:      []Pin{{Key: "1.0", Train: "1.0", Version: "1.0.3", Kind: "release"}},
			Cells:     []Cell{{Scenario: "x", Description: "A fail observes x.", Tier: "stable", Counterpart: "upstream CLI", Iroh: "1.0", Result: Fail, Expected: Fail}},
			Envelopes: []Envelope{{Surface: "x", Tier: "stable", UpstreamVersion: "1.0", Status: status, Detail: "evidence"}},
		}
		if err := r.Validate(); err != nil {
			t.Errorf("status %q: %v", status, err)
		}
	}
}

func TestReportRejectsDuplicateVersionCell(t *testing.T) {
	cell := Cell{Scenario: "x", Description: "A fail observes x.", Tier: "stable", Counterpart: "upstream CLI", Iroh: "1.0", Result: Fail, Expected: Fail}
	r := Report{
		Schema: Schema,
		Pins:   []Pin{{Key: "1.0", Train: "1.0", Version: "1.0.3", Kind: "release"}},
		Cells:  []Cell{cell, cell},
	}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate cell") {
		t.Fatalf("Validate() error = %v, want duplicate cell", err)
	}
}

func TestMarkdownNamesRustCounterpart(t *testing.T) {
	r := Report{
		Generated: time.Unix(0, 0).UTC(),
		GoIroh:    GoIroh{Commit: "abc123"},
		Pins:      []Pin{{Key: "1.0", Train: "1.0", Version: "1.0.3", Kind: "release"}, {Key: "1.1-pre", Train: "1.1", Commit: "4706ec97", Kind: "pre-release"}},
		Envelopes: []Envelope{{Surface: "CustomAddr endpoint tickets", Tier: "experimental", UpstreamVersion: "1.0", Status: "observed-incompatible", Detail: "Observed in both directions."}},
		Cells: []Cell{
			{Scenario: "echo", Description: "Go and Rust exchange an echo, and a pass proves compatible streams.", Tier: "stable", Counterpart: "upstream CLI", Iroh: "1.0", Result: Pass, Expected: Pass, Peer: "iroh-doctor@sha256:abc", PeerDigest: "sha256:abc"},
			{Scenario: "echo", Description: "Go and Rust exchange an echo, and a pass proves compatible streams.", Tier: "stable", Counterpart: "upstream CLI", Iroh: "1.1-pre", Result: Pass, Expected: Pass, Peer: "iroh-doctor@sha256:ghi", PeerDigest: "sha256:ghi"},
			{Scenario: "datagrams", Description: "Go and Rust exchange datagrams, and a pass proves compatible datagrams.", Tier: "stable", Counterpart: "Rust test driver", Iroh: "1.0", Result: Fail, Expected: Fail, Peer: "rust-driver@sha256:def", PeerDigest: "sha256:def", Detail: "Rust accepted 0/1 datagrams"},
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
		"## Compatibility envelope",
		"CustomAddr endpoint tickets",
		"observed-incompatible",
		"1.0 (1.0.3)",
		"1.1-pre @ 4706ec9",
		"| echo | stable | upstream CLI | pass [2] | pass [3] | — |",
		"fail (expected)",
		"Rust accepted 0/1 datagrams",
		"### Peers",
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
}
