package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGobulkDiagSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	diagFile := filepath.Join(tmpDir, "diag.json")

	// Set flags for small test transfer in both mode
	*diagPath = diagFile
	*mode = "both"
	*streams = 1
	*downloadSize = 4 << 20 // 4 MiB
	*uploadSize = 0
	*timeout = 10 * time.Second
	*jsonOut = true

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := runBoth(ctx); err != nil {
		t.Fatalf("runBoth failed: %v", err)
	}

	data, err := os.ReadFile(diagFile)
	if err != nil {
		t.Fatalf("failed to read diag file: %v", err)
	}

	var snap DiagSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("failed to unmarshal diag json: %v", err)
	}

	if snap.Mode != "both" {
		t.Errorf("got mode %q, want %q", snap.Mode, "both")
	}
	if len(snap.Roles) != 2 {
		t.Fatalf("got %d roles, want 2", len(snap.Roles))
	}

	clientRole := snap.Roles[0]
	serverRole := snap.Roles[1]

	if clientRole.Role != "client" {
		t.Errorf("got role %q, want client", clientRole.Role)
	}
	if serverRole.Role != "server" {
		t.Errorf("got role %q, want server", serverRole.Role)
	}

	if clientRole.Stats.BytesReceived < 4<<20 {
		t.Errorf("client BytesReceived=%d, want >= %d", clientRole.Stats.BytesReceived, 4<<20)
	}
	if serverRole.Stats.BytesSent < 4<<20 {
		t.Errorf("server BytesSent=%d, want >= %d", serverRole.Stats.BytesSent, 4<<20)
	}
}
