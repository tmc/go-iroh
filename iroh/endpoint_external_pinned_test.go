package iroh

// A net report replacing the discovered set must never drop addresses pinned
// with AddExternalAddr.

import (
	"context"
	"net/netip"
	"slices"
	"testing"
)

func TestPinnedExternalAddrSurvivesNetReport(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	pinned := netip.MustParseAddrPort("192.0.2.7:1111")
	discovered1 := netip.MustParseAddrPort("203.0.113.10:4444")
	discovered2 := netip.MustParseAddrPort("203.0.113.11:5555")

	ep.AddExternalAddr(pinned)
	if !ep.setExternalNATTraversalCandidates(discovered1) {
		t.Fatal("first setExternalNATTraversalCandidates = false, want true")
	}

	got := ep.localNATTraversalCandidates()
	for _, want := range []netip.AddrPort{pinned, discovered1} {
		if !slices.Contains(got, want) {
			t.Fatalf("candidates after report = %v, missing %v", got, want)
		}
	}

	// The next report replaces the discovered set: the old mapping retires,
	// the pinned address stays.
	if !ep.setExternalNATTraversalCandidates(discovered2) {
		t.Fatal("second setExternalNATTraversalCandidates = false, want true")
	}
	got = ep.localNATTraversalCandidates()
	if !slices.Contains(got, pinned) {
		t.Fatalf("candidates after second report = %v, pinned %v was dropped", got, pinned)
	}
	if !slices.Contains(got, discovered2) {
		t.Fatalf("candidates after second report = %v, missing %v", got, discovered2)
	}
	if slices.Contains(got, discovered1) {
		t.Fatalf("candidates after second report = %v, stale discovered %v not retired", got, discovered1)
	}
	if ips := ep.Addr().IPAddrs(); !slices.Contains(ips, pinned) {
		t.Fatalf("Addr() = %v, pinned %v missing", ep.Addr(), pinned)
	}

	// Unpinning removes it everywhere; the discovered mapping is untouched.
	if !ep.RemoveExternalAddr(pinned) {
		t.Fatal("RemoveExternalAddr = false, want true")
	}
	got = ep.localNATTraversalCandidates()
	if slices.Contains(got, pinned) {
		t.Fatalf("candidates after unpin = %v, %v still present", got, pinned)
	}
	if !slices.Contains(got, discovered2) {
		t.Fatalf("candidates after unpin = %v, discovered %v lost", got, discovered2)
	}
}
