package runner

import (
	"strings"
	"testing"
)

func TestPassRequiresRustPeerEvidence(t *testing.T) {
	c := Cell{Scenario: "echo", Iroh: "1.0.3", Tier: "A", Result: Pass}
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

func TestDoctorConnectLineUsesFirstDirectAddress(t *testing.T) {
	line := "iroh-doctor connect " + strings.Repeat("2a", 32) + " --remote-endpoint 127.0.0.1:1234 --remote-endpoint '[::1]:5678'"
	m := doctorConnectLine.FindStringSubmatch(line)
	if len(m) != 3 || m[2] != "127.0.0.1:1234" {
		t.Fatalf("match = %q, want first IPv4 address", m)
	}
}
