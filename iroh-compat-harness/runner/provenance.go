package runner

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// SourceCommit returns the commit hash of a clean checkout at dir.
//
// It reports the hash rather than a git describe string. Evidence names a
// commit so the provenance check can test whether it is an ancestor of what is
// being pushed, and describe stops yielding a bare hash as soon as any tag is
// reachable.
func SourceCommit(dir string) (string, error) {
	status, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return "", fmt.Errorf("resolve go-iroh source commit: inspect working tree: %w", err)
	}
	if len(status) != 0 {
		return "", errors.New("resolve go-iroh source commit: working tree is dirty")
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("resolve go-iroh source commit: %w", err)
	}
	commit := strings.TrimSpace(string(out))
	if commit == "" {
		return "", errors.New("resolve go-iroh source commit: empty output")
	}
	return commit, nil
}
