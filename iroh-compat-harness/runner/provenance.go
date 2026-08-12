package runner

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// SourceCommit returns a git description of a clean checkout at dir.
func SourceCommit(dir string) (string, error) {
	status, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return "", fmt.Errorf("resolve go-iroh source commit: inspect working tree: %w", err)
	}
	if len(status) != 0 {
		return "", errors.New("resolve go-iroh source commit: working tree is dirty")
	}
	out, err := exec.Command("git", "-C", dir, "describe", "--always").Output()
	if err != nil {
		return "", fmt.Errorf("resolve go-iroh source commit: %w", err)
	}
	commit := strings.TrimSpace(string(out))
	if commit == "" {
		return "", errors.New("resolve go-iroh source commit: empty output")
	}
	return commit, nil
}
