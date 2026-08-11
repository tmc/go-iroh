package runner

import (
	"strings"
	"testing"
	"time"
)

func TestTipMarkdownIsAdvisory(t *testing.T) {
	report := TipReport{
		Schema: TipSchema, Generated: time.Unix(0, 0).UTC(), GoCommit: "abc123",
		UpstreamCommit: "4706ec97e991", UpstreamDescribe: "v1.0.3-16-g4706ec97", ExpectedPin: "1.1-pre",
		Cells: []Cell{{
			Scenario: "vectors/custom-addr-ticket-go-to-rust", Description: "A pass proves ticket compatibility.",
			Tier: "experimental", Counterpart: "Rust test driver", Iroh: "tip", Result: Pass, Expected: Pass,
			Peer: "rust-driver@sha256:abc", PeerPID: 42, PeerDigest: "sha256:abc", Detail: "Rust accepted 6/6 Go tickets",
		}},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	got := string(report.Markdown())
	for _, want := range []string{
		"Advisory only",
		"v1.0.3-16-g4706ec97",
		"Expected at pinned 1.1-pre",
		"pass [1]",
		"Rust accepted 6/6 Go tickets",
		"All other scenarios are `—` (untested) at tip",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Markdown() does not contain %q", want)
		}
	}
}
