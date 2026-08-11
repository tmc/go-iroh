package runner

import (
	"strings"
	"testing"
)

func TestSourceCommitOverride(t *testing.T) {
	got, err := SourceCommit("does-not-exist", "build-123")
	if err != nil {
		t.Fatal(err)
	}
	if got != "build-123-override" {
		t.Fatalf("SourceCommit override = %q, want build-123-override", got)
	}
}

func TestSourceCommitFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := SourceCommit(".", "")
	if err == nil || !strings.Contains(err.Error(), "resolve go-iroh source commit") {
		t.Fatalf("SourceCommit error = %v, want resolution failure", err)
	}
}
