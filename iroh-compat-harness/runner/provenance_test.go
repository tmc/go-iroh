package runner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceCommitFailure(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := SourceCommit(".")
	if err == nil || !strings.Contains(err.Error(), "resolve go-iroh source commit") {
		t.Fatalf("SourceCommit error = %v, want resolution failure", err)
	}
}

func TestSourceCommitRejectsDirtyTree(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.name", "Test")
	runGit(t, dir, "config", "user.email", "test@example.com")
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("clean\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "file")
	runGit(t, dir, "commit", "-m", "initial")

	if _, err := SourceCommit(dir); err != nil {
		t.Fatalf("SourceCommit clean tree: %v", err)
	}
	if err := os.WriteFile(path, []byte("dirty\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := SourceCommit(dir); err == nil || !strings.Contains(err.Error(), "working tree is dirty") {
		t.Fatalf("SourceCommit dirty tree error = %v", err)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}
