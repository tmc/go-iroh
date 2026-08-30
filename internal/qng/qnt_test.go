package quic

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestQNTAPIFailsClosed(t *testing.T) {
	c := &Conn{}
	addr := netip.MustParseAddrPort("192.0.2.1:1234")

	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "add local address",
			run:  func() error { return c.AddNATTraversalAddress(addr) },
		},
		{
			name: "remove local address",
			run:  func() error { return c.RemoveNATTraversalAddress(addr) },
		},
		{
			name: "initiate round",
			run: func() error {
				addrs, err := c.InitiateNATTraversalRound(context.Background())
				if len(addrs) != 0 {
					t.Fatalf("InitiateNATTraversalRound addresses = %v, want none", addrs)
				}
				return err
			},
		},
		{
			name: "remote addresses",
			run: func() error {
				addrs, err := c.NATTraversalAddresses()
				if len(addrs) != 0 {
					t.Fatalf("NATTraversalAddresses = %v, want none", addrs)
				}
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("err = %v, want ErrNATTraversalNotNegotiated", err)
			}
		})
	}
}

func TestQNTLocalAddressState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)

	mapped := netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234")
	canon := netip.MustParseAddrPort("192.0.2.1:1234")
	if err := c.AddNATTraversalAddress(mapped); err != nil {
		t.Fatalf("AddNATTraversalAddress(mapped): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != canon {
		t.Fatalf("local addresses = %v, want [%v]", got, canon)
	}

	if err := c.AddNATTraversalAddress(canon); err != nil {
		t.Fatalf("AddNATTraversalAddress(duplicate): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != canon {
		t.Fatalf("after duplicate add = %v, want [%v]", got, canon)
	}

	v6 := netip.MustParseAddrPort("[2001:db8::1]:4433")
	if err := c.AddNATTraversalAddress(v6); err != nil {
		t.Fatalf("AddNATTraversalAddress(v6): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 2 || got[0] != canon || got[1] != v6 {
		t.Fatalf("after v6 add = %v, want [%v %v]", got, canon, v6)
	}

	if err := c.RemoveNATTraversalAddress(mapped); err != nil {
		t.Fatalf("RemoveNATTraversalAddress(mapped): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != v6 {
		t.Fatalf("after remove mapped = %v, want [%v]", got, v6)
	}

	if err := c.RemoveNATTraversalAddress(canon); err != nil {
		t.Fatalf("RemoveNATTraversalAddress(absent): %v", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != v6 {
		t.Fatalf("after absent remove = %v, want [%v]", got, v6)
	}
}

func TestQNTLocalAddressStatePerConnection(t *testing.T) {
	c1 := newNegotiatedQNTConn(8, 16)
	c2 := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
	if err := c1.AddNATTraversalAddress(addr); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	if got := c2.qntLocalNATTraversalAddresses(); len(got) != 0 {
		t.Fatalf("second connection local addresses = %v, want none", got)
	}
}

func TestQNTLocalAddressStateLimit(t *testing.T) {
	c := newNegotiatedQNTConn(8, 1)
	if err := c.AddNATTraversalAddress(netip.MustParseAddrPort("192.0.2.1:1234")); err != nil {
		t.Fatalf("first AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(netip.MustParseAddrPort("192.0.2.1:1234")); err != nil {
		t.Fatalf("duplicate AddNATTraversalAddress: %v", err)
	}
	err := c.AddNATTraversalAddress(netip.MustParseAddrPort("192.0.2.2:1234"))
	if !errors.Is(err, ErrNATTraversalTooManyAddresses) {
		t.Fatalf("second distinct AddNATTraversalAddress err = %v, want ErrNATTraversalTooManyAddresses", err)
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 1 || got[0] != netip.MustParseAddrPort("192.0.2.1:1234") {
		t.Fatalf("local addresses after limit = %v, want [192.0.2.1:1234]", got)
	}
}

func TestQNTLocalAddressQueuesAddAddressFrame(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.perspective = protocol.PerspectiveServer
	c.framer = newFramer(nil)
	c.sendingScheduled = make(chan struct{}, 1)
	addr1 := netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234")
	addr2 := netip.MustParseAddrPort("[2001:db8::1]:4433")

	if err := c.AddNATTraversalAddress(addr1); err != nil {
		t.Fatalf("first AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(addr1); err != nil {
		t.Fatalf("duplicate AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(addr2); err != nil {
		t.Fatalf("second AddNATTraversalAddress: %v", err)
	}

	frames := queuedAddAddressFrames(c)
	if len(frames) != 2 {
		t.Fatalf("queued %d ADD_ADDRESS frames, want 2", len(frames))
	}
	if frames[0].SeqNo != 0 || netip.AddrPortFrom(frames[0].Addr, frames[0].Port) != netip.MustParseAddrPort("192.0.2.1:1234") {
		t.Fatalf("first ADD_ADDRESS = seq %d %s:%d, want seq 0 192.0.2.1:1234", frames[0].SeqNo, frames[0].Addr, frames[0].Port)
	}
	if frames[1].SeqNo != 1 || netip.AddrPortFrom(frames[1].Addr, frames[1].Port) != addr2 {
		t.Fatalf("second ADD_ADDRESS = seq %d %s:%d, want seq 1 %v", frames[1].SeqNo, frames[1].Addr, frames[1].Port, addr2)
	}
	select {
	case <-c.sendingScheduled:
	default:
		t.Fatal("AddNATTraversalAddress did not schedule sending")
	}
}

func TestQNTAddRemoteNATTraversalAddress(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	remote := netip.MustParseAddrPort("192.0.2.10:1234")
	if err := c.AddRemoteNATTraversalAddress(remote); err != nil {
		t.Fatalf("AddRemoteNATTraversalAddress: %v", err)
	}
	if err := c.AddRemoteNATTraversalAddress(remote); err != nil {
		t.Fatalf("duplicate AddRemoteNATTraversalAddress: %v", err)
	}
	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != remote {
		t.Fatalf("NATTraversalAddresses = %v, want [%v]", addrs, remote)
	}
}

func TestQNTClientLocalAddressDoesNotQueueAddAddressFrame(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.perspective = protocol.PerspectiveClient
	c.framer = newFramer(nil)
	c.sendingScheduled = make(chan struct{}, 1)
	addr := netip.MustParseAddrPort("192.0.2.1:1234")

	if err := c.AddNATTraversalAddress(addr); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	if frames := queuedAddAddressFrames(c); len(frames) != 0 {
		t.Fatalf("queued %d ADD_ADDRESS frames, want 0", len(frames))
	}
	if got := c.qntLocalNATTraversalAddresses(); !slices.Equal(got, []netip.AddrPort{addr}) {
		t.Fatalf("local addresses = %v, want [%v]", got, addr)
	}
	select {
	case <-c.sendingScheduled:
		t.Fatal("client AddNATTraversalAddress scheduled sending")
	default:
	}
}

func TestQNTLocalAddressQueuesRemoveAddressFrame(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.perspective = protocol.PerspectiveServer
	c.framer = newFramer(nil)
	c.sendingScheduled = make(chan struct{}, 1)
	addr1 := netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234")
	addr2 := netip.MustParseAddrPort("192.0.2.2:4321")
	absent := netip.MustParseAddrPort("192.0.2.3:4321")

	if err := c.AddNATTraversalAddress(addr1); err != nil {
		t.Fatalf("first AddNATTraversalAddress: %v", err)
	}
	if err := c.AddNATTraversalAddress(addr2); err != nil {
		t.Fatalf("second AddNATTraversalAddress: %v", err)
	}
	select {
	case <-c.sendingScheduled:
	default:
	}
	if err := c.RemoveNATTraversalAddress(addr1); err != nil {
		t.Fatalf("RemoveNATTraversalAddress: %v", err)
	}
	if err := c.RemoveNATTraversalAddress(addr1); err != nil {
		t.Fatalf("duplicate RemoveNATTraversalAddress: %v", err)
	}
	if err := c.RemoveNATTraversalAddress(absent); err != nil {
		t.Fatalf("absent RemoveNATTraversalAddress: %v", err)
	}

	frames := queuedRemoveAddressFrames(c)
	if len(frames) != 1 {
		t.Fatalf("queued %d REMOVE_ADDRESS frames, want 1", len(frames))
	}
	if frames[0].SeqNo != 0 {
		t.Fatalf("REMOVE_ADDRESS seq = %d, want 0", frames[0].SeqNo)
	}
	if got := c.qntLocalNATTraversalAddresses(); !slices.Equal(got, []netip.AddrPort{addr2}) {
		t.Fatalf("local addresses after remove = %v, want [%v]", got, addr2)
	}
	select {
	case <-c.sendingScheduled:
	default:
		t.Fatal("RemoveNATTraversalAddress did not schedule sending")
	}
}

func TestQNTClientLocalAddressDoesNotQueueRemoveAddressFrame(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.perspective = protocol.PerspectiveClient
	c.framer = newFramer(nil)
	c.sendingScheduled = make(chan struct{}, 1)
	addr := netip.MustParseAddrPort("192.0.2.1:1234")

	if err := c.AddNATTraversalAddress(addr); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	if err := c.RemoveNATTraversalAddress(addr); err != nil {
		t.Fatalf("RemoveNATTraversalAddress: %v", err)
	}
	if frames := queuedRemoveAddressFrames(c); len(frames) != 0 {
		t.Fatalf("queued %d REMOVE_ADDRESS frames, want 0", len(frames))
	}
	if got := c.qntLocalNATTraversalAddresses(); len(got) != 0 {
		t.Fatalf("local addresses after remove = %v, want none", got)
	}
	select {
	case <-c.sendingScheduled:
		t.Fatal("client RemoveNATTraversalAddress scheduled sending")
	default:
	}
}

func TestQNTLocalAddressStateFailsClosedWhenNotNegotiated(t *testing.T) {
	addr := netip.MustParseAddrPort("192.0.2.1:1234")
	add := &wire.AddAddressFrame{SeqNo: 1, Addr: addr.Addr(), Port: addr.Port()}
	remove := &wire.RemoveAddressFrame{SeqNo: 1}
	cases := []struct {
		name string
		c    *Conn
	}{
		{name: "empty", c: &Conn{}},
		{name: "local only", c: newLocalOnlyQNTConn(8)},
		{name: "peer only", c: newPeerOnlyQNTConn(8)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.c.AddNATTraversalAddress(addr); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("AddNATTraversalAddress err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if err := tc.c.RemoveNATTraversalAddress(addr); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("RemoveNATTraversalAddress err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if err := tc.c.addRemoteNATTraversalAddressFrame(add); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("addRemoteNATTraversalAddressFrame err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if err := tc.c.removeRemoteNATTraversalAddressFrame(remove); !errors.Is(err, ErrNATTraversalNotNegotiated) {
				t.Fatalf("removeRemoteNATTraversalAddressFrame err = %v, want ErrNATTraversalNotNegotiated", err)
			}
			if got := tc.c.qntLocalNATTraversalAddresses(); len(got) != 0 {
				t.Fatalf("local addresses after failed operations = %v, want none", got)
			}
		})
	}
}

func TestQNTRoundQueuesState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local := netip.MustParseAddrPort("192.0.2.1:1234")
	remote := netip.MustParseAddrPort("198.51.100.2:5678")

	addrs, err := c.InitiateNATTraversalRound(context.Background())
	if !errors.Is(err, ErrNATTraversalNotEnoughAddresses) {
		t.Fatalf("InitiateNATTraversalRound without candidates err = %v, want ErrNATTraversalNotEnoughAddresses", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("InitiateNATTraversalRound without candidates addresses = %v, want none", addrs)
	}

	if err := c.AddNATTraversalAddress(local); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	addrs, err = c.InitiateNATTraversalRound(context.Background())
	if !errors.Is(err, ErrNATTraversalNotEnoughAddresses) {
		t.Fatalf("InitiateNATTraversalRound without remote candidates err = %v, want ErrNATTraversalNotEnoughAddresses", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("InitiateNATTraversalRound without remote candidates addresses = %v, want none", addrs)
	}

	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  remote.Addr(),
		Port:  remote.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame: %v", err)
	}
	addrs, err = c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("InitiateNATTraversalRound with candidates: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != remote {
		t.Fatalf("InitiateNATTraversalRound with candidates addresses = %v, want [%v]", addrs, remote)
	}
	reachOut := c.qntPendingReachOutFrames()
	if len(reachOut) != 1 {
		t.Fatalf("pending REACH_OUT frames = %d, want 1", len(reachOut))
	}
	if reachOut[0].Round != 1 || netip.AddrPortFrom(reachOut[0].Addr, reachOut[0].Port) != local {
		t.Fatalf("pending REACH_OUT = round %d %s:%d, want round 1 %v", reachOut[0].Round, reachOut[0].Addr, reachOut[0].Port, local)
	}
	probes := c.qntPendingProbeAddresses()
	if len(probes) != 1 || probes[0] != remote {
		t.Fatalf("pending probe addresses = %v, want [%v]", probes, remote)
	}

	addrs, err = c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("second InitiateNATTraversalRound with candidates: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != remote {
		t.Fatalf("second InitiateNATTraversalRound addresses = %v, want [%v]", addrs, remote)
	}
	reachOut = c.qntPendingReachOutFrames()
	if len(reachOut) != 1 {
		t.Fatalf("second pending REACH_OUT frames = %d, want 1", len(reachOut))
	}
	if reachOut[0].Round != 2 || netip.AddrPortFrom(reachOut[0].Addr, reachOut[0].Port) != local {
		t.Fatalf("second pending REACH_OUT = round %d %s:%d, want round 2 %v", reachOut[0].Round, reachOut[0].Addr, reachOut[0].Port, local)
	}
}

func TestQNTRoundQueuesOneReachOutPerLocalAndProbePerRemote(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local1 := netip.MustParseAddrPort("192.0.2.1:1234")
	local2 := netip.MustParseAddrPort("[2001:db8::1]:4433")
	remote1 := netip.MustParseAddrPort("198.51.100.1:1001")
	remote2 := netip.MustParseAddrPort("198.51.100.2:1002")

	for _, addr := range []netip.AddrPort{local1, local2} {
		if err := c.AddNATTraversalAddress(addr); err != nil {
			t.Fatalf("AddNATTraversalAddress(%v): %v", addr, err)
		}
	}
	for seq, addr := range map[uint64]netip.AddrPort{1: remote1, 2: remote2} {
		if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{SeqNo: seq, Addr: addr.Addr(), Port: addr.Port()}); err != nil {
			t.Fatalf("add remote seq %d: %v", seq, err)
		}
	}

	addrs, err := c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("InitiateNATTraversalRound: %v", err)
	}
	if len(addrs) != 2 || !slices.Contains(addrs, remote1) || !slices.Contains(addrs, remote2) {
		t.Fatalf("round addresses = %v, want %v and %v", addrs, remote1, remote2)
	}
	reachOut := c.qntPendingReachOutFrames()
	if len(reachOut) != 2 {
		t.Fatalf("pending REACH_OUT frames = %d, want 2", len(reachOut))
	}
	for _, f := range reachOut {
		if f.Round != 1 {
			t.Fatalf("REACH_OUT round = %d, want 1", f.Round)
		}
	}
	if !hasReachOut(reachOut, local1) || !hasReachOut(reachOut, local2) {
		t.Fatalf("pending REACH_OUT frames = %+v, want local candidates %v and %v", reachOut, local1, local2)
	}
	probes := c.qntPendingProbeAddresses()
	if len(probes) != 2 || !slices.Contains(probes, remote1) || !slices.Contains(probes, remote2) {
		t.Fatalf("pending probes = %v, want %v and %v", probes, remote1, remote2)
	}
}

func TestQNTRoundQueuesReachOutFramesToFramer(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local := netip.MustParseAddrPort("192.0.2.1:1234")
	remote := netip.MustParseAddrPort("198.51.100.1:1001")

	if err := c.AddNATTraversalAddress(local); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	c.framer = newFramer(noopConnectionFlowController{})
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{SeqNo: 1, Addr: remote.Addr(), Port: remote.Port()}); err != nil {
		t.Fatalf("add remote: %v", err)
	}
	if _, err := c.InitiateNATTraversalRound(context.Background()); err != nil {
		t.Fatalf("InitiateNATTraversalRound: %v", err)
	}
	if pending := c.qntPendingReachOutFrames(); len(pending) != 0 {
		t.Fatalf("pending REACH_OUT after queueing = %+v, want none", pending)
	}
	queued := queuedReachOutFrames(c)
	if len(queued) != 1 {
		t.Fatalf("queued REACH_OUT frames = %d, want 1", len(queued))
	}
	if got := netip.AddrPortFrom(queued[0].Addr, queued[0].Port); queued[0].Round != 1 || got != local {
		t.Fatalf("queued REACH_OUT = round %d %v, want round 1 %v", queued[0].Round, got, local)
	}

	frames, _, _, _, _ := c.framer.Append(nil, nil, 1200, monotime.Now(), protocol.Version1)
	if len(frames) != 1 {
		t.Fatalf("framer returned %d frames, want 1", len(frames))
	}
	got, ok := frames[0].Frame.(*wire.ReachOutFrame)
	if !ok {
		t.Fatalf("framer returned %T, want *wire.ReachOutFrame", frames[0].Frame)
	}
	if got.Round != 1 || netip.AddrPortFrom(got.Addr, got.Port) != local {
		t.Fatalf("packed REACH_OUT = round %d %s:%d, want round 1 %v", got.Round, got.Addr, got.Port, local)
	}
	if c.framer.HasData() {
		t.Fatal("framer still has REACH_OUT data after append")
	}
}

func TestQNTRoundClearsPreviousPendingState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local1 := netip.MustParseAddrPort("192.0.2.1:1234")
	local2 := netip.MustParseAddrPort("192.0.2.2:1234")
	remote1 := netip.MustParseAddrPort("198.51.100.1:1001")
	remote2 := netip.MustParseAddrPort("198.51.100.2:1002")

	for _, addr := range []netip.AddrPort{local1, local2} {
		if err := c.AddNATTraversalAddress(addr); err != nil {
			t.Fatalf("AddNATTraversalAddress(%v): %v", addr, err)
		}
	}
	for seq, addr := range map[uint64]netip.AddrPort{1: remote1, 2: remote2} {
		if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{SeqNo: seq, Addr: addr.Addr(), Port: addr.Port()}); err != nil {
			t.Fatalf("add remote seq %d: %v", seq, err)
		}
	}
	if _, err := c.InitiateNATTraversalRound(context.Background()); err != nil {
		t.Fatalf("first InitiateNATTraversalRound: %v", err)
	}
	st := c.qntLocalState()
	st.mu.Lock()
	st.sentProbes = map[[8]byte]netip.AddrPort{{1, 2, 3, 4, 5, 6, 7, 8}: remote1}
	st.mu.Unlock()

	if err := c.RemoveNATTraversalAddress(local1); err != nil {
		t.Fatalf("RemoveNATTraversalAddress: %v", err)
	}
	if err := c.removeRemoteNATTraversalAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1}); err != nil {
		t.Fatalf("remove remote seq 1: %v", err)
	}
	addrs, err := c.InitiateNATTraversalRound(context.Background())
	if err != nil {
		t.Fatalf("second InitiateNATTraversalRound: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != remote2 {
		t.Fatalf("second round addresses = %v, want [%v]", addrs, remote2)
	}
	reachOut := c.qntPendingReachOutFrames()
	if len(reachOut) != 1 || reachOut[0].Round != 2 || netip.AddrPortFrom(reachOut[0].Addr, reachOut[0].Port) != local2 {
		t.Fatalf("second round REACH_OUT = %+v, want round 2 for %v", reachOut, local2)
	}
	probes := c.qntPendingProbeAddresses()
	if len(probes) != 1 || probes[0] != remote2 {
		t.Fatalf("second round probes = %v, want [%v]", probes, remote2)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.sentProbes) != 0 {
		t.Fatalf("sent probes after second round = %v, want none", st.sentProbes)
	}
}

func TestQNTProbeUDPAddr(t *testing.T) {
	tests := []struct {
		name string
		addr netip.AddrPort
		want netip.AddrPort
	}{
		{
			name: "ipv4",
			addr: netip.MustParseAddrPort("192.0.2.1:1234"),
			want: netip.MustParseAddrPort("192.0.2.1:1234"),
		},
		{
			name: "mapped ipv4",
			addr: netip.MustParseAddrPort("[::ffff:192.0.2.1]:1234"),
			want: netip.MustParseAddrPort("192.0.2.1:1234"),
		},
		{
			name: "ipv6",
			addr: netip.MustParseAddrPort("[2001:db8::1]:4433"),
			want: netip.MustParseAddrPort("[2001:db8::1]:4433"),
		},
		{
			name: "invalid",
		},
		{
			name: "zero port",
			addr: netip.MustParseAddrPort("192.0.2.1:0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := qntProbeUDPAddr(tt.addr)
			if !tt.want.IsValid() {
				if got != nil {
					t.Fatalf("qntProbeUDPAddr(%v) = %v, want nil", tt.addr, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("qntProbeUDPAddr(%v) = nil, want %v", tt.addr, tt.want)
			}
			if got.AddrPort() != tt.want {
				t.Fatalf("qntProbeUDPAddr(%v) = %v, want %v", tt.addr, got.AddrPort(), tt.want)
			}
		})
	}
}

func TestQNTSentProbeConsumesMatchingPathResponse(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remote := netip.MustParseAddrPort("198.51.100.1:1234")
	mapped := netip.MustParseAddrPort("[::ffff:198.51.100.1]:1234")

	c.qntRecordSentProbe(challenge, remote)
	got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, mapped)
	if !ok || got != remote {
		t.Fatalf("qntConsumePathResponse = %v, %v, want %v, true", got, ok, remote)
	}
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, remote); ok || got.IsValid() {
		t.Fatalf("duplicate qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
}

func TestQNTNextProbeFramePopsPendingProbeAndRecordsChallenge(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	local := netip.MustParseAddrPort("192.0.2.1:1234")
	remote := netip.MustParseAddrPort("198.51.100.1:5678")

	if err := c.AddNATTraversalAddress(local); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  remote.Addr(),
		Port:  remote.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame: %v", err)
	}
	if _, err := c.InitiateNATTraversalRound(context.Background()); err != nil {
		t.Fatalf("InitiateNATTraversalRound: %v", err)
	}

	got, frame, ok, err := c.qntNextProbeFrame()
	if err != nil {
		t.Fatalf("qntNextProbeFrame: %v", err)
	}
	if !ok {
		t.Fatal("qntNextProbeFrame ok = false, want true")
	}
	if got != remote {
		t.Fatalf("qntNextProbeFrame remote = %v, want %v", got, remote)
	}
	pathChallenge, ok := frame.Frame.(*wire.PathChallengeFrame)
	if !ok {
		t.Fatalf("qntNextProbeFrame frame = %T, want *wire.PathChallengeFrame", frame.Frame)
	}
	if probes := c.qntPendingProbeAddresses(); len(probes) != 0 {
		t.Fatalf("pending probes after qntNextProbeFrame = %v, want none", probes)
	}
	if matched, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: pathChallenge.Data}, remote); !ok || matched != remote {
		t.Fatalf("qntConsumePathResponse after qntNextProbeFrame = %v, %v, want %v, true", matched, ok, remote)
	}
}

func TestQNTNextProbeFrameReturnsFalseWhenEmpty(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)

	remote, frame, ok, err := c.qntNextProbeFrame()
	if err != nil {
		t.Fatalf("qntNextProbeFrame: %v", err)
	}
	if ok || remote.IsValid() || frame.Frame != nil {
		t.Fatalf("qntNextProbeFrame = %v, %#v, %v, want zero frame false", remote, frame, ok)
	}
}

func TestQNTNextProbeFrameInvalidState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.qntLocalState().pendingProbes = []netip.AddrPort{netip.AddrPort{}}

	got, frame, ok, err := c.qntNextProbeFrame()
	if err != nil {
		t.Fatalf("qntNextProbeFrame: %v", err)
	}
	if ok || got.IsValid() || frame.Frame != nil {
		t.Fatalf("qntNextProbeFrame invalid = %v, %#v, %v, want zero frame false", got, frame, ok)
	}
}

func TestQNTProbeRetriesRequeueUntilExhausted(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1001")
	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: addr.Addr(), Port: addr.Port()}); err != nil {
		t.Fatalf("handle REACH_OUT: %v", err)
	}

	for attempt := 0; attempt < qntMaxProbeAttempts; attempt++ {
		got, _, ok, err := c.qntNextProbeFrame()
		if err != nil {
			t.Fatalf("qntNextProbeFrame attempt %d: %v", attempt, err)
		}
		if !ok || got != addr {
			t.Fatalf("qntNextProbeFrame attempt %d = %v, %v, want %v true", attempt, got, ok, addr)
		}
		if attempt == qntMaxProbeAttempts-1 {
			break
		}
		if !c.qntQueueProbeRetries() {
			t.Fatalf("qntQueueProbeRetries attempt %d = false, want true", attempt)
		}
	}
	if c.qntQueueProbeRetries() {
		t.Fatal("qntQueueProbeRetries after exhaustion = true, want false")
	}
	if probes := c.qntPendingProbeAddresses(); len(probes) != 0 {
		t.Fatalf("pending probes after exhaustion = %v, want none", probes)
	}
}

func TestQNTProbeRetriesStopAfterPathResponse(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1001")
	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: addr.Addr(), Port: addr.Port()}); err != nil {
		t.Fatalf("handle REACH_OUT: %v", err)
	}
	got, frame, ok, err := c.qntNextProbeFrame()
	if err != nil {
		t.Fatalf("qntNextProbeFrame: %v", err)
	}
	if !ok || got != addr {
		t.Fatalf("qntNextProbeFrame = %v, %v, want %v true", got, ok, addr)
	}
	challenge, ok := frame.Frame.(*wire.PathChallengeFrame)
	if !ok {
		t.Fatalf("qntNextProbeFrame frame = %T, want *wire.PathChallengeFrame", frame.Frame)
	}
	if matched, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge.Data}, addr); !ok || matched != addr {
		t.Fatalf("qntConsumePathResponse = %v, %v, want %v true", matched, ok, addr)
	}
	if c.qntQueueProbeRetries() {
		t.Fatal("qntQueueProbeRetries after PATH_RESPONSE = true, want false")
	}
	if probes := c.qntPendingProbeAddresses(); len(probes) != 0 {
		t.Fatalf("pending probes after PATH_RESPONSE = %v, want none", probes)
	}
}

func TestQNTValidatedProbeQueue(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	addr := netip.MustParseAddrPort("[::ffff:198.51.100.1]:1234")
	want := netip.MustParseAddrPort("198.51.100.1:1234")

	if !c.qntQueueValidatedProbe(addr) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	if c.qntQueueValidatedProbe(want) {
		t.Fatal("duplicate qntQueueValidatedProbe = true, want false")
	}
	if c.qntQueueValidatedProbe(netip.AddrPort{}) {
		t.Fatal("invalid qntQueueValidatedProbe = true, want false")
	}
	got, ok := c.qntPopValidatedProbe()
	if !ok || got != want {
		t.Fatalf("qntPopValidatedProbe = %v, %v, want %v, true", got, ok, want)
	}
	if got, ok := c.qntPopValidatedProbe(); ok || got.IsValid() {
		t.Fatalf("empty qntPopValidatedProbe = %v, %v, want zero false", got, ok)
	}
}

func TestQNTOpenValidatedPathStoresRoute(t *testing.T) {
	c, frames := newQNTRoutePathTestConn(t)
	c.multipathManager.handleMaxPathID(protocol.PathID(4))
	addr := netip.MustParseAddrPort("[::ffff:198.51.100.1]:1234")
	want := netip.MustParseAddrPort("198.51.100.1:1234")

	if !c.qntQueueValidatedProbe(addr) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	pid, route, ok, err := c.qntOpenValidatedPathLocked()
	if err != nil {
		t.Fatalf("qntOpenValidatedPathLocked: %v", err)
	}
	if !ok || pid != protocol.PathID(1) || route != want {
		t.Fatalf("qntOpenValidatedPathLocked = %d, %v, %v, want 1, %v, true", pid, route, ok, want)
	}
	st := c.multipathOut.paths[pid]
	if st == nil {
		t.Fatalf("multipath path %d not stored", pid)
	}
	if st.qntRoute != want {
		t.Fatalf("qntRoute = %v, want %v", st.qntRoute, want)
	}
	if !st.validated {
		t.Fatal("QNT route path is not marked validated after QNT PATH_RESPONSE")
	}
	if _, ok := c.sentPacketHandler.PathDebugStats(pid); !ok {
		t.Fatalf("sent recovery state for path %d not allocated", pid)
	}
	if alarm := c.receivedPacketHandler.GetAlarmTimeoutForPath(pid); !alarm.IsZero() {
		t.Fatalf("new recv path %d ACK alarm = %v, want zero", pid, alarm)
	}
	// Path open now tops the pool up to the CID budget (min(peer limit,
	// MaxIssuedConnectionIDs)); with the default peer limit of 2 that is two
	// frames, where the old reactive path issued exactly one.
	if len(*frames) != 2 {
		t.Fatalf("queued %d local path CID frames, want 2", len(*frames))
	}
	nc, ok := (*frames)[0].(*wire.NewConnectionIDFrame)
	if !ok {
		t.Fatalf("queued frame = %T, want *wire.NewConnectionIDFrame", (*frames)[0])
	}
	if nc.PathID == nil || *nc.PathID != pid {
		t.Fatalf("PATH_NEW_CONNECTION_ID PathID = %v, want %d", nc.PathID, pid)
	}
	if c.multipathOut.nextPathID != protocol.PathID(2) {
		t.Fatalf("nextPathID = %d, want 2", c.multipathOut.nextPathID)
	}
	if got, ok := c.qntPopValidatedProbe(); ok || got.IsValid() {
		t.Fatalf("validated queue after route = %v, %v, want zero false", got, ok)
	}
}

func TestQNTOpenValidatedPathAllocationErrorPreservesCandidate(t *testing.T) {
	c, _ := newQNTRoutePathTestConn(t)
	c.multipathManager.handleMaxPathID(protocol.PathID(4))
	if err := c.sentPacketHandler.AddPath(protocol.PathID(1)); err != nil {
		t.Fatalf("pre-add sent path: %v", err)
	}
	addr := netip.MustParseAddrPort("198.51.100.1:1234")
	if !c.qntQueueValidatedProbe(addr) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	pid, route, ok, err := c.qntOpenValidatedPathLocked()
	if err == nil {
		t.Fatal("qntOpenValidatedPathLocked err = nil, want allocation error")
	}
	if ok || pid != protocol.PathIDZero || route.IsValid() {
		t.Fatalf("qntOpenValidatedPathLocked = %d, %v, %v, want zero false", pid, route, ok)
	}
	got, ok := c.qntPopValidatedProbe()
	if !ok || got != addr {
		t.Fatalf("validated probe after allocation error = %v, %v, want %v true", got, ok, addr)
	}
}

func TestQNTOpenValidatedPathRollsBackCIDIssueFailure(t *testing.T) {
	c, frames := newQNTRoutePathTestConn(t)
	c.multipathManager.handleMaxPathID(protocol.PathID(4))
	gen := &failingConnectionIDGenerator{
		generator: &protocol.DefaultConnectionIDGenerator{ConnLen: 4},
		fail:      true,
	}
	c.connIDGenerator.generator = gen
	addr := netip.MustParseAddrPort("198.51.100.1:1234")
	if !c.qntQueueValidatedProbe(addr) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}

	pid, route, ok, err := c.qntOpenValidatedPathLocked()
	if err == nil {
		t.Fatal("qntOpenValidatedPathLocked err = nil, want CID issue error")
	}
	if ok || pid != protocol.PathIDZero || route.IsValid() {
		t.Fatalf("qntOpenValidatedPathLocked = %d, %v, %v, want zero false", pid, route, ok)
	}
	if _, ok := c.sentPacketHandler.PathDebugStats(protocol.PathID(1)); ok {
		t.Fatal("sent path 1 still allocated after CID issue failure")
	}
	if got, ok := c.qntPeekValidatedProbe(); !ok || got != addr {
		t.Fatalf("validated probe after CID issue failure = %v, %v, want %v true", got, ok, addr)
	}
	if len(*frames) != 0 {
		t.Fatalf("queued %d local path CID frames after failed issue, want 0", len(*frames))
	}

	gen.fail = false
	pid, route, ok, err = c.qntOpenValidatedPathLocked()
	if err != nil {
		t.Fatalf("qntOpenValidatedPathLocked retry: %v", err)
	}
	if !ok || pid != protocol.PathID(1) || route != addr {
		t.Fatalf("qntOpenValidatedPathLocked retry = %d, %v, %v, want 1, %v, true", pid, route, ok, addr)
	}
	if len(*frames) != 2 {
		t.Fatalf("queued %d local path CID frames after retry, want 2", len(*frames))
	}
}

func TestQNTOpenValidatedPathRequiresCanOpenPath(t *testing.T) {
	local := uint32(4)
	addr := netip.MustParseAddrPort("198.51.100.1:1234")

	tests := []struct {
		name string
		conn *Conn
	}{
		{name: "multipath off", conn: newMaxPathIDTestConn(nil, nil)},
		{name: "peer transport parameter unset", conn: newMaxPathIDTestConn(&local, nil)},
		{name: "peer max below next path", conn: newMaxPathIDTestConn(&local, ptrTo[uint32](0))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.conn.qntQueueValidatedProbe(addr) {
				t.Fatal("qntQueueValidatedProbe = false, want true")
			}
			pid, route, ok, err := tt.conn.qntOpenValidatedPathLocked()
			if !errors.Is(err, ErrPathLimit) {
				t.Fatalf("qntOpenValidatedPathLocked err = %v, want ErrPathLimit", err)
			}
			if ok || pid != protocol.PathIDZero || route.IsValid() {
				t.Fatalf("qntOpenValidatedPathLocked = %d, %v, %v, want zero false", pid, route, ok)
			}
			got, ok := tt.conn.qntPopValidatedProbe()
			if !ok || got != addr {
				t.Fatalf("validated probe after rejected route = %v, %v, want %v true", got, ok, addr)
			}
		})
	}
}

func TestQNTOpenValidatedPathNoCandidate(t *testing.T) {
	local := uint32(4)
	peer := uint32(8)
	tests := []struct {
		name string
		conn *Conn
	}{
		{name: "can open", conn: func() *Conn {
			c := newMaxPathIDTestConn(&local, &peer)
			c.multipathManager.handleMaxPathID(protocol.PathID(4))
			return c
		}()},
		{name: "cannot open", conn: newMaxPathIDTestConn(nil, nil)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pid, route, ok, err := tt.conn.qntOpenValidatedPathLocked()
			if err != nil {
				t.Fatalf("qntOpenValidatedPathLocked: %v", err)
			}
			if ok || pid != protocol.PathIDZero || route.IsValid() {
				t.Fatalf("qntOpenValidatedPathLocked without candidate = %d, %v, %v, want zero false", pid, route, ok)
			}
			if tt.conn.multipathOut != nil {
				t.Fatal("qntOpenValidatedPathLocked without candidate initialized multipath state")
			}
		})
	}
}

func TestQNTProcessValidatedPathOpenConsumesOneCandidate(t *testing.T) {
	c, _ := newQNTRoutePathTestConn(t)
	c.multipathManager.handleMaxPathID(protocol.PathID(4))
	addr1 := netip.MustParseAddrPort("198.51.100.1:1234")
	addr2 := netip.MustParseAddrPort("198.51.100.2:1234")

	if !c.qntQueueValidatedProbe(addr1) || !c.qntQueueValidatedProbe(addr2) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	if err := c.processQNTValidatedPathOpen(monotime.Now()); err != nil {
		t.Fatalf("processQNTValidatedPathOpen: %v", err)
	}
	st := c.multipathOut.paths[protocol.PathID(1)]
	if st == nil {
		t.Fatal("QNT path 1 not opened")
	}
	if st.qntRoute != addr1 {
		t.Fatalf("QNT path route = %v, want %v", st.qntRoute, addr1)
	}
	if !st.validated {
		t.Fatal("QNT path is not validated after QNT PATH_RESPONSE")
	}
	if c.multipathOut.nextPathID != protocol.PathID(2) {
		t.Fatalf("nextPathID = %d, want 2", c.multipathOut.nextPathID)
	}
	got, ok := c.qntPopValidatedProbe()
	if !ok || got != addr2 {
		t.Fatalf("remaining validated candidate = %v, %v, want %v, true", got, ok, addr2)
	}
}

func TestQNTPathSnapshotReportsRoute(t *testing.T) {
	c, _ := newQNTRoutePathTestConn(t)
	c.multipathManager.handleMaxPathID(protocol.PathID(4))
	addr := netip.MustParseAddrPort("198.51.100.1:1234")

	if !c.qntQueueValidatedProbe(addr) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	if err := c.processQNTValidatedPathOpen(monotime.Now()); err != nil {
		t.Fatalf("processQNTValidatedPathOpen: %v", err)
	}
	c.multipathOut.paths[protocol.PathID(1)].validated = true

	c.pathSnapshotQueue = make(chan *pathSnapshotRequest, 1)
	req := &pathSnapshotRequest{done: make(chan struct{})}
	c.pathSnapshotQueue <- req
	c.processPathSnapshotRequests()
	<-req.done

	if len(req.paths) != 1 {
		t.Fatalf("paths len = %d, want 1; paths=%v", len(req.paths), req.paths)
	}
	if req.paths[0].ID != protocol.PathID(1) || !req.paths[0].Validated || req.paths[0].RemoteAddr != addr {
		t.Fatalf("path = %+v, want id 1 validated route %v", req.paths[0], addr)
	}
	if req.paths[0].HasRTT || req.paths[0].SmoothedRTT != 0 {
		t.Fatalf("path RTT = %v, HasRTT = %v; want zero, false before measurement", req.paths[0].SmoothedRTT, req.paths[0].HasRTT)
	}
	if !req.paths[0].HasBytesInFlight {
		t.Fatalf("path HasBytesInFlight = false, want true: %+v", req.paths[0])
	}
	if !req.paths[0].HasBytesSent {
		t.Fatalf("path HasBytesSent = false, want true: %+v", req.paths[0])
	}
	if !req.paths[0].HasBytesReceived {
		t.Fatalf("path HasBytesReceived = false, want true: %+v", req.paths[0])
	}
	if !req.paths[0].HasCongestionWindow || req.paths[0].CongestionWindow == 0 {
		t.Fatalf("path CongestionWindow = %d, HasCongestionWindow = %v; want non-zero observed cwnd", req.paths[0].CongestionWindow, req.paths[0].HasCongestionWindow)
	}
	if !req.paths[0].HasLoss {
		t.Fatalf("path HasLoss = false, want true: %+v", req.paths[0])
	}
}

func TestQNTProcessValidatedPathOpenKeepsCandidateAtPathLimit(t *testing.T) {
	local := uint32(4)
	peer := uint32(0)
	c := newMaxPathIDTestConn(&local, &peer)
	addr := netip.MustParseAddrPort("198.51.100.1:1234")

	if !c.qntQueueValidatedProbe(addr) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	if err := c.processQNTValidatedPathOpen(monotime.Now()); err != nil {
		t.Fatalf("processQNTValidatedPathOpen: %v", err)
	}
	if c.multipathOut != nil && len(c.multipathOut.paths) != 0 {
		t.Fatalf("processQNTValidatedPathOpen opened %d paths at path limit, want none", len(c.multipathOut.paths))
	}
	got, ok := c.qntPopValidatedProbe()
	if !ok || got != addr {
		t.Fatalf("validated candidate after path limit = %v, %v, want %v, true", got, ok, addr)
	}
}

func TestQNTSentProbeRequiresChallengeAndSource(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	otherChallenge := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	remote := netip.MustParseAddrPort("198.51.100.1:1234")
	otherRemote := netip.MustParseAddrPort("198.51.100.2:1234")

	c.qntRecordSentProbe(challenge, remote)
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, otherRemote); ok || got.IsValid() {
		t.Fatalf("wrong source qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: otherChallenge}, remote); ok || got.IsValid() {
		t.Fatalf("wrong challenge qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	if got, ok := c.qntConsumePathResponse(nil, remote); ok || got.IsValid() {
		t.Fatalf("nil frame qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, netip.AddrPort{}); ok || got.IsValid() {
		t.Fatalf("invalid source qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
	got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, remote)
	if !ok || got != remote {
		t.Fatalf("matching response after misses = %v, %v, want %v, true", got, ok, remote)
	}
}

func TestQNTSentProbeIgnoresInvalidRemote(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remote := netip.MustParseAddrPort("198.51.100.1:1234")

	c.qntRecordSentProbe(challenge, netip.AddrPort{})
	if got, ok := c.qntConsumePathResponse(&wire.PathResponseFrame{Data: challenge}, remote); ok || got.IsValid() {
		t.Fatalf("invalid remote qntConsumePathResponse = %v, %v, want zero, false", got, ok)
	}
}

func TestQNTPathResponseHandlerReceivesSourceAddress(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.perspective = protocol.PerspectiveClient
	challenge := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	frame := &wire.PathResponseFrame{Data: challenge}
	source := netip.MustParseAddrPort("198.51.100.1:1234")
	otherSource := netip.MustParseAddrPort("198.51.100.2:1234")

	c.qntRecordSentProbe(challenge, source)
	_ = c.handlePathResponseFrame(frame, otherSource)
	if _, ok := c.qntConsumePathResponse(frame, source); !ok {
		t.Fatal("PATH_RESPONSE from wrong source consumed QNT probe")
	}

	c.qntRecordSentProbe(challenge, source)
	_ = c.handlePathResponseFrame(frame, source)
	got, ok := c.qntPopValidatedProbe()
	if !ok || got != source {
		t.Fatalf("validated QNT probe = %v, %v, want %v, true", got, ok, source)
	}
	if _, ok := c.qntConsumePathResponse(frame, source); ok {
		t.Fatal("PATH_RESPONSE from matching source was not consumed by QNT hook")
	}
}

func TestQNTUnmatchedPathResponseRequiresQNTSource(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	c.perspective = protocol.PerspectiveClient
	frame := &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	source := netip.MustParseAddrPort("198.51.100.1:1234")

	err := c.handlePathResponseFrame(frame, source)
	if err == nil || !strings.Contains(err.Error(), "unexpected PATH_RESPONSE frame") {
		t.Fatalf("unmatched PATH_RESPONSE err = %v, want unexpected PATH_RESPONSE", err)
	}
}

func TestQNTUnmatchedPathResponseAllowsQNTDuplicateSource(t *testing.T) {
	c, _ := newQNTRoutePathTestConn(t)
	c.perspective = protocol.PerspectiveClient
	limit := uint8(8)
	c.config.MaxRemoteNATTraversalAddresses = &limit
	c.peerParams.Load().MaxRemoteNATTraversalAddresses = &limit
	c.multipathManager.handleMaxPathID(protocol.PathID(4))
	source := netip.MustParseAddrPort("198.51.100.1:1234")

	if !c.qntQueueValidatedProbe(source) {
		t.Fatal("qntQueueValidatedProbe = false, want true")
	}
	if _, _, ok, err := c.qntOpenValidatedPathLocked(); err != nil || !ok {
		t.Fatalf("qntOpenValidatedPathLocked = %v, %v, want opened path", ok, err)
	}
	frame := &wire.PathResponseFrame{Data: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
	if err := c.handlePathResponseFrame(frame, source); err != nil {
		t.Fatalf("duplicate QNT PATH_RESPONSE err = %v, want nil", err)
	}
}

func TestQNTRemoteAddressState(t *testing.T) {
	c := newNegotiatedQNTConn(8, 16)
	mapped := netip.MustParseAddrPort("[::ffff:198.51.100.2]:5678")
	canon := netip.MustParseAddrPort("198.51.100.2:5678")

	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  mapped.Addr(),
		Port:  mapped.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame(mapped): %v", err)
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  canon.Addr(),
		Port:  canon.Port(),
	}); err != nil {
		t.Fatalf("addRemoteNATTraversalAddressFrame(duplicate): %v", err)
	}

	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != canon {
		t.Fatalf("remote addresses = %v, want [%v]", addrs, canon)
	}

	addrs[0] = netip.MustParseAddrPort("203.0.113.3:9999")
	addrs, err = c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses after caller mutation: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != canon {
		t.Fatalf("remote addresses after caller mutation = %v, want [%v]", addrs, canon)
	}
}

func TestQNTRemoteAddressStateUsesSeqNumbers(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	addr1 := netip.MustParseAddrPort("198.51.100.1:1001")
	addr2 := netip.MustParseAddrPort("198.51.100.2:1002")
	addr3 := netip.MustParseAddrPort("198.51.100.3:1003")

	for seq, addr := range map[uint64]netip.AddrPort{1: addr1, 2: addr2} {
		if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
			SeqNo: seq,
			Addr:  addr.Addr(),
			Port:  addr.Port(),
		}); err != nil {
			t.Fatalf("add seq %d: %v", seq, err)
		}
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 3,
		Addr:  addr3.Addr(),
		Port:  addr3.Port(),
	}); !errors.Is(err, errQNTTooManyRemoteAddresses) {
		t.Fatalf("add over limit err = %v, want errQNTTooManyRemoteAddresses", err)
	}

	if err := c.removeRemoteNATTraversalAddressFrame(&wire.RemoveAddressFrame{SeqNo: 99}); err != nil {
		t.Fatalf("remove absent seq: %v", err)
	}
	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses after absent remove: %v", err)
	}
	if len(addrs) != 2 || !slices.Contains(addrs, addr1) || !slices.Contains(addrs, addr2) {
		t.Fatalf("remote addresses after absent remove = %v, want %v and %v", addrs, addr1, addr2)
	}

	if err := c.removeRemoteNATTraversalAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1}); err != nil {
		t.Fatalf("remove seq 1: %v", err)
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 3,
		Addr:  addr3.Addr(),
		Port:  addr3.Port(),
	}); err != nil {
		t.Fatalf("add seq 3 after remove: %v", err)
	}

	addrs, err = c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 2 || !slices.Contains(addrs, addr2) || !slices.Contains(addrs, addr3) {
		t.Fatalf("remote addresses = %v, want %v and %v", addrs, addr2, addr3)
	}
}

func TestQNTInvalidRemoteAddressDoesNotStartRound(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	local := netip.MustParseAddrPort("198.51.100.10:1000")
	if err := c.AddNATTraversalAddress(local); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  netip.MustParseAddr("198.51.100.1"),
		Port:  0,
	}); err != nil {
		t.Fatalf("add invalid remote address: %v", err)
	}
	if addrs, err := c.NATTraversalAddresses(); err != nil || len(addrs) != 0 {
		t.Fatalf("NATTraversalAddresses after invalid ADD_ADDRESS = %v, %v, want none, nil", addrs, err)
	}
	if _, err := c.InitiateNATTraversalRound(context.Background()); !errors.Is(err, ErrNATTraversalNotEnoughAddresses) {
		t.Fatalf("InitiateNATTraversalRound after invalid ADD_ADDRESS = %v, want %v", err, ErrNATTraversalNotEnoughAddresses)
	}
}

func TestQNTRemoteAddressStateLimitOnConn(t *testing.T) {
	c := newNegotiatedQNTConn(1, 16)
	if err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  netip.MustParseAddr("198.51.100.1"),
		Port:  1234,
	}); err != nil {
		t.Fatalf("first addRemoteNATTraversalAddress: %v", err)
	}
	err := c.addRemoteNATTraversalAddressFrame(&wire.AddAddressFrame{
		SeqNo: 2,
		Addr:  netip.MustParseAddr("198.51.100.2"),
		Port:  1234,
	})
	if !errors.Is(err, ErrNATTraversalTooManyAddresses) {
		t.Fatalf("second addRemoteNATTraversalAddress err = %v, want ErrNATTraversalTooManyAddresses", err)
	}
	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddrPort("198.51.100.1:1234") {
		t.Fatalf("remote addresses after limit = %v, want [198.51.100.1:1234]", addrs)
	}
}

func TestQNTConnectionHandlesAddRemoveAddressFrames(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	addr1 := netip.MustParseAddrPort("198.51.100.1:1001")
	addr2 := netip.MustParseAddrPort("198.51.100.2:1002")

	err := c.handleAddAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  addr1.Addr(),
		Port:  addr1.Port(),
	})
	if err != nil {
		t.Fatalf("handle ADD_ADDRESS seq 1: %v", err)
	}
	err = c.handleAddAddressFrame(&wire.AddAddressFrame{
		SeqNo: 2,
		Addr:  addr2.Addr(),
		Port:  addr2.Port(),
	})
	if err != nil {
		t.Fatalf("handle ADD_ADDRESS seq 2: %v", err)
	}
	err = c.handleRemoveAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1})
	if err != nil {
		t.Fatalf("handle REMOVE_ADDRESS seq 1: %v", err)
	}

	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != addr2 {
		t.Fatalf("remote addresses = %v, want [%v]", addrs, addr2)
	}
}

func TestQNTConnectionHandlesReachOutFrameQueuesProbe(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	addr := netip.MustParseAddrPort("198.51.100.1:1001")

	err := c.handleReachOutFrame(&wire.ReachOutFrame{
		Round: 1,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
	if err != nil {
		t.Fatalf("handle REACH_OUT: %v", err)
	}
	if got := c.qntPendingProbeAddresses(); len(got) != 1 || got[0] != addr {
		t.Fatalf("pending probes after REACH_OUT = %v, want [%v]", got, addr)
	}
	if addrs, err := c.NATTraversalAddresses(); err != nil || len(addrs) != 0 {
		t.Fatalf("NATTraversalAddresses after REACH_OUT = %v, %v, want none, nil", addrs, err)
	}
}

func TestQNTConnectionHandlesReachOutFrameRoundsAndDuplicates(t *testing.T) {
	c := newNegotiatedQNTConn(4, 16)
	oldAddr := netip.MustParseAddrPort("198.51.100.1:1001")
	newAddr := netip.MustParseAddrPort("198.51.100.2:1002")

	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 2, Addr: oldAddr.Addr(), Port: oldAddr.Port()}); err != nil {
		t.Fatalf("initial REACH_OUT: %v", err)
	}
	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 2, Addr: oldAddr.Addr(), Port: oldAddr.Port()}); err != nil {
		t.Fatalf("duplicate REACH_OUT: %v", err)
	}
	if got := c.qntPendingProbeAddresses(); len(got) != 1 || got[0] != oldAddr {
		t.Fatalf("pending probes after duplicate = %v, want [%v]", got, oldAddr)
	}
	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: newAddr.Addr(), Port: newAddr.Port()}); err != nil {
		t.Fatalf("old REACH_OUT: %v", err)
	}
	if got := c.qntPendingProbeAddresses(); len(got) != 1 || got[0] != oldAddr {
		t.Fatalf("pending probes after old round = %v, want [%v]", got, oldAddr)
	}
	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 3, Addr: newAddr.Addr(), Port: newAddr.Port()}); err != nil {
		t.Fatalf("new REACH_OUT: %v", err)
	}
	if got := c.qntPendingProbeAddresses(); len(got) != 1 || got[0] != newAddr {
		t.Fatalf("pending probes after new round = %v, want [%v]", got, newAddr)
	}
}

func TestQNTConnectionHandlesReachOutFrameLimit(t *testing.T) {
	c := newNegotiatedQNTConn(1, 16)
	addr1 := netip.MustParseAddrPort("198.51.100.1:1001")
	addr2 := netip.MustParseAddrPort("198.51.100.2:1002")

	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: addr1.Addr(), Port: addr1.Port()}); err != nil {
		t.Fatalf("first REACH_OUT: %v", err)
	}
	err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: addr2.Addr(), Port: addr2.Port()})
	if !errors.Is(err, ErrNATTraversalTooManyAddresses) {
		t.Fatalf("second REACH_OUT err = %v, want ErrNATTraversalTooManyAddresses", err)
	}
	if got := c.qntPendingProbeAddresses(); len(got) != 1 || got[0] != addr1 {
		t.Fatalf("pending probes after limit = %v, want [%v]", got, addr1)
	}
}

func TestQNTConnectionHandlesReachOutFrameInvalid(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	if err := c.handleReachOutFrame(nil); err != nil {
		t.Fatalf("nil REACH_OUT: %v", err)
	}
	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: netip.Addr{}, Port: 1001}); err != nil {
		t.Fatalf("invalid REACH_OUT: %v", err)
	}
	if err := c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: netip.MustParseAddr("198.51.100.1")}); err != nil {
		t.Fatalf("zero-port REACH_OUT: %v", err)
	}
	if got := c.qntPendingProbeAddresses(); len(got) != 0 {
		t.Fatalf("pending probes after invalid REACH_OUT = %v, want none", got)
	}
}

func TestQNTConnectionHandlersFailClosedWhenNotNegotiated(t *testing.T) {
	c := newLocalOnlyQNTConn(2)
	addr := netip.MustParseAddrPort("198.51.100.1:1001")

	err := c.handleAddAddressFrame(&wire.AddAddressFrame{
		SeqNo: 1,
		Addr:  addr.Addr(),
		Port:  addr.Port(),
	})
	if !errors.Is(err, ErrNATTraversalNotNegotiated) {
		t.Fatalf("handle ADD_ADDRESS err = %v, want ErrNATTraversalNotNegotiated", err)
	}
	err = c.handleReachOutFrame(&wire.ReachOutFrame{Round: 1, Addr: addr.Addr(), Port: addr.Port()})
	if !errors.Is(err, ErrNATTraversalNotNegotiated) {
		t.Fatalf("handle REACH_OUT err = %v, want ErrNATTraversalNotNegotiated", err)
	}
	err = c.handleRemoveAddressFrame(&wire.RemoveAddressFrame{SeqNo: 1})
	if !errors.Is(err, ErrNATTraversalNotNegotiated) {
		t.Fatalf("handle REMOVE_ADDRESS err = %v, want ErrNATTraversalNotNegotiated", err)
	}
}

func TestQNTConnectionHandlersIgnoreNilFrames(t *testing.T) {
	c := newNegotiatedQNTConn(2, 16)
	if err := c.handleAddAddressFrame(nil); err != nil {
		t.Fatalf("handle nil ADD_ADDRESS: %v", err)
	}
	if err := c.handleRemoveAddressFrame(nil); err != nil {
		t.Fatalf("handle nil REMOVE_ADDRESS: %v", err)
	}
	addrs, err := c.NATTraversalAddresses()
	if err != nil {
		t.Fatalf("NATTraversalAddresses: %v", err)
	}
	if len(addrs) != 0 {
		t.Fatalf("remote addresses after nil frames = %v, want none", addrs)
	}
}

func newNegotiatedQNTConn(local, peer uint8) *Conn {
	c := &Conn{config: &Config{MaxRemoteNATTraversalAddresses: &local}}
	c.peerParams.Store(&wire.TransportParameters{MaxRemoteNATTraversalAddresses: &peer})
	return c
}

func queuedAddAddressFrames(c *Conn) []*wire.AddAddressFrame {
	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	var frames []*wire.AddAddressFrame
	for _, f := range c.framer.controlFrames {
		if af, ok := f.(*wire.AddAddressFrame); ok {
			frames = append(frames, af)
		}
	}
	return frames
}

func queuedRemoveAddressFrames(c *Conn) []*wire.RemoveAddressFrame {
	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	var frames []*wire.RemoveAddressFrame
	for _, f := range c.framer.controlFrames {
		if rf, ok := f.(*wire.RemoveAddressFrame); ok {
			frames = append(frames, rf)
		}
	}
	return frames
}

func queuedReachOutFrames(c *Conn) []*wire.ReachOutFrame {
	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	var frames []*wire.ReachOutFrame
	for _, f := range c.framer.controlFrames {
		if rf, ok := f.(*wire.ReachOutFrame); ok {
			frames = append(frames, rf)
		}
	}
	return frames
}

func newQNTRoutePathTestConn(t *testing.T) (*Conn, *[]wire.Frame) {
	t.Helper()
	local := uint32(4)
	peer := uint32(8)
	c := newMaxPathIDTestConn(&local, &peer)
	rttStats := utils.NewRTTStats()
	c.sentPacketHandler = ackhandler.NewSentPacketHandler(
		0,
		protocol.InitialPacketSize,
		rttStats,
		&utils.ConnectionStats{},
		true,
		false,
		func(protocol.PacketNumber) {},
		protocol.PerspectiveClient,
		nil,
		utils.DefaultLogger,
	)
	c.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(utils.DefaultLogger)
	g, frames, _ := newTestConnIDGenerator(t)
	c.connIDGenerator = g
	return c, frames
}

type failingConnectionIDGenerator struct {
	generator ConnectionIDGenerator
	fail      bool
}

func (g *failingConnectionIDGenerator) GenerateConnectionID() (ConnectionID, error) {
	if g.fail {
		return ConnectionID{}, errors.New("test cid generation failed")
	}
	return g.generator.GenerateConnectionID()
}

func (g *failingConnectionIDGenerator) ConnectionIDLen() int {
	return g.generator.ConnectionIDLen()
}

func hasReachOut(frames []*wire.ReachOutFrame, addr netip.AddrPort) bool {
	return slices.ContainsFunc(frames, func(f *wire.ReachOutFrame) bool {
		return netip.AddrPortFrom(f.Addr, f.Port) == addr
	})
}

func newLocalOnlyQNTConn(local uint8) *Conn {
	return &Conn{config: &Config{MaxRemoteNATTraversalAddresses: &local}}
}

func newPeerOnlyQNTConn(peer uint8) *Conn {
	c := &Conn{config: &Config{}}
	c.peerParams.Store(&wire.TransportParameters{MaxRemoteNATTraversalAddresses: &peer})
	return c
}
