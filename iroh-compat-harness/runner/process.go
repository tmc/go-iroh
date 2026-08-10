package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func FileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open peer binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash peer binary: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func writeArtifact(name, evidence string) (string, error) {
	dir := filepath.Join("results", "artifacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create artifact directory: %w", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.TrimSpace(evidence)+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write artifact: %w", err)
	}
	return filepath.ToSlash(path), nil
}
