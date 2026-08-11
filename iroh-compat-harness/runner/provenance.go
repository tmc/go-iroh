package runner

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// SourceCommit returns a git description of dir. Override is for hermetic
// builds that make the repository metadata unavailable.
func SourceCommit(dir, override string) (string, error) {
	if override != "" {
		return override + "-override", nil
	}
	out, err := exec.Command("git", "-C", dir, "describe", "--always", "--dirty").Output()
	if err != nil {
		return "", fmt.Errorf("resolve go-iroh source commit: %w", err)
	}
	commit := strings.TrimSpace(string(out))
	if commit == "" {
		return "", errors.New("resolve go-iroh source commit: empty output")
	}
	return commit, nil
}
