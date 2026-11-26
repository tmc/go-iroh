package udp

import (
	"net"
	"testing"
)

// TestWrapSetsDF checks that Wrap actually sets the don't-fragment bit
// on a UDP socket. Path MTU discovery is started only when the send connection
// reports DF, so a change that stops Wrap from calling setDF silently disables
// PMTU discovery.
func TestWrapSetsDF(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	rawConn, err := pc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	// Ask the platform directly whether it supports DF on this socket, so the
	// test doesn't fail where setDF is a no-op (unsupported OS or OS version).
	want, err := setDF(rawConn)
	if err != nil {
		t.Fatalf("setDF: %v", err)
	}
	if !want {
		t.Skip("platform does not support setting the DF bit")
	}

	c, err := Wrap(pc)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Capabilities().DF; !got {
		t.Errorf("Wrap: Capabilities().DF = false, want true")
	}
}
