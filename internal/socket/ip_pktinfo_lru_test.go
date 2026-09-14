package socket

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

// newPktinfoTransport returns an IpTransport on a wildcard socket, skipping
// when the platform delivers no packet info.
func newPktinfoTransport(t *testing.T) *IpTransport {
	t.Helper()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	tr := NewIpTransport(udp, make(chan recvBatch, 1))
	if !tr.pktinfo {
		t.Skip("packet info not available on a wildcard socket")
	}
	return tr
}

// remoteN returns a distinct remote address for n.
func remoteN(n int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)}), 4434)
}

var arrival = localAddr{addr: netip.AddrFrom4([4]byte{192, 0, 2, 1})}

// TestIpTransportEvictsLeastRecentlyHeardRemote checks that a full table
// drops only the remote heard from longest ago.
func TestIpTransportEvictsLeastRecentlyHeardRemote(t *testing.T) {
	tr := newPktinfoTransport(t)
	for n := 1; n <= maxLocalAddrs; n++ {
		tr.record(remoteN(n), arrival)
	}
	tr.record(remoteN(1), arrival) // heard from again: now the most recent
	tr.record(remoteN(maxLocalAddrs+1), arrival)

	if got := len(tr.local); got != maxLocalAddrs {
		t.Errorf("table holds %d remotes, want %d", got, maxLocalAddrs)
	}
	for _, tc := range []struct {
		n    int
		want bool
	}{
		{1, true},                 // refreshed after the table filled
		{2, false},                // heard from longest ago
		{3, true},                 // one eviction made room for one newcomer
		{maxLocalAddrs, true},     // the last of the first fill
		{maxLocalAddrs + 1, true}, // the newcomer
	} {
		if got := tr.packetInfoFor(remoteN(tc.n)) != nil; got != tc.want {
			t.Errorf("remote %d recorded = %v, want %v", tc.n, got, tc.want)
		}
	}
}

// TestIpTransportForgottenRemoteLeavesRecencyOrder checks that a forgotten
// remote frees its place and does not absorb a later eviction.
func TestIpTransportForgottenRemoteLeavesRecencyOrder(t *testing.T) {
	tr := newPktinfoTransport(t)
	for n := 1; n <= maxLocalAddrs; n++ {
		tr.record(remoteN(n), arrival)
	}
	tr.forgetLocal(remoteN(1))
	tr.record(remoteN(maxLocalAddrs+1), arrival) // takes the freed place
	tr.record(remoteN(maxLocalAddrs+2), arrival) // evicts remote 2, the oldest left

	if got := len(tr.local); got != maxLocalAddrs {
		t.Errorf("table holds %d remotes, want %d", got, maxLocalAddrs)
	}
	if tr.packetInfoFor(remoteN(2)) != nil {
		t.Error("remote 2 still recorded: the forgotten remote 1 absorbed the eviction")
	}
	if tr.packetInfoFor(remoteN(3)) == nil {
		t.Error("remote 3 was evicted")
	}
}

// TestIpTransportRecordReplacesChangedArrivalAddress checks that a remote
// reaching the socket at a new local address gets a new control message and
// keeps a single entry.
func TestIpTransportRecordReplacesChangedArrivalAddress(t *testing.T) {
	tr := newPktinfoTransport(t)
	r := remoteN(1)
	moved := localAddr{addr: netip.AddrFrom4([4]byte{192, 0, 2, 2})}
	tr.record(r, arrival)
	tr.record(r, moved)
	if got, want := tr.packetInfoFor(r), packetInfoMessage(r, moved); !bytes.Equal(got, want) {
		t.Errorf("control message % x, want % x", got, want)
	}
	if got := len(tr.local); got != 1 {
		t.Errorf("table holds %d remotes, want 1", got)
	}
}
