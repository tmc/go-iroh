package quic

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/udp"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
)

// newQNTMigrationMTUTestConn builds a client Conn whose send conn wraps a real
// UDP socket, so capabilities().DF reports what the platform actually supports.
// It reports the socket's DF capability so callers can skip the cases that need
// it.
func newQNTMigrationMTUTestConn(t *testing.T, disableMTUDiscovery bool) (*Conn, bool) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	raw, err := udp.Wrap(pc)
	if err != nil {
		t.Fatal(err)
	}

	c, _ := newQNTRoutePathTestConn(t)
	c.perspective = protocol.PerspectiveClient
	c.handshakeConfirmed = true
	c.config.DisablePathMTUDiscovery = disableMTUDiscovery
	c.conn = newSendConn(raw, pc.LocalAddr(), udp.PacketInfo{}, utils.DefaultLogger)
	c.mtuDiscoverer = newMTUDiscoverer(
		utils.NewRTTStats(),
		protocol.ByteCount(protocol.InitialPacketSize),
		protocol.ByteCount(protocol.MaxPacketBufferSize),
		nil,
	)
	return c, raw.Capabilities().DF
}

// TestQNTMigrationRespectsMTUDiscoveryGate checks that the QNT migration paths
// do not arm the MTU prober when discovery is not permitted. mtuFinder.Reset
// sets lastProbeTime on its own, and ShouldSendProbe needs nothing else, so an
// ungated Reset would start probing on a connection where
// handleHandshakeConfirmed deliberately never called Start.
func TestQNTMigrationRespectsMTUDiscoveryGate(t *testing.T) {
	route := netip.MustParseAddrPort("127.0.0.1:4242")
	migrate := func(c *Conn, now monotime.Time) {
		c.migrateOrdinarySendToQNTRoute(route, now)
	}
	revert := func(c *Conn, now monotime.Time) {
		c.multipathOut = newMultipathOutgoing()
		c.multipathOut.migratedRemote = route
		c.multipathOut.premigrationRemote = net.UDPAddrFromAddrPort(route)
		c.revertQNTMigration(now)
	}

	for _, tt := range []struct {
		name string
		fn   func(*Conn, monotime.Time)
	}{
		{name: "migrate", fn: migrate},
		{name: "revert", fn: revert},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("discovery disabled", func(t *testing.T) {
				c, _ := newQNTMigrationMTUTestConn(t, true)
				now := monotime.Now()
				tt.fn(c, now)
				if !c.mtuDiscoverer.lastProbeTime.IsZero() {
					t.Errorf("lastProbeTime = %v, want zero", c.mtuDiscoverer.lastProbeTime)
				}
				// Well past the probe delay, so this is a live check: an
				// armed prober says true here.
				if c.mtuDiscoverer.ShouldSendProbe(now.Add(time.Minute)) {
					t.Error("ShouldSendProbe = true, want false")
				}
				// The gate must skip only the Reset, not the migration itself.
				if got := c.conn.RemoteAddr().String(); got != route.String() {
					t.Errorf("RemoteAddr = %s, want %s", got, route)
				}
			})

			t.Run("discovery enabled", func(t *testing.T) {
				c, df := newQNTMigrationMTUTestConn(t, false)
				if !df {
					t.Skip("platform does not support setting the DF bit")
				}
				tt.fn(c, monotime.Now())
				if c.mtuDiscoverer.lastProbeTime.IsZero() {
					t.Error("lastProbeTime is zero, want the migration to have reset the prober")
				}
			})
		})
	}
}

// dfRawConn is a udp.Conn whose only interesting property is its DF capability.
type dfRawConn struct {
	udp.Conn
	df bool
}

func (c *dfRawConn) Capabilities() udp.Capabilities { return udp.Capabilities{DF: c.df} }
func (c *dfRawConn) LocalAddr() net.Addr            { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *dfRawConn) Close() error                   { return nil }

// TestSwitchToNewPathGatesMTUResetOnNewConn checks that switchToNewPath decides
// whether to re-arm the prober from the socket it migrates TO. The new
// Transport carries its own socket with its own DF capability, so a gate
// evaluated before the swap would read the outgoing socket and get the wrong
// answer.
func TestSwitchToNewPathGatesMTUResetOnNewConn(t *testing.T) {
	c, df := newQNTMigrationMTUTestConn(t, false)
	if !df {
		t.Skip("platform does not support setting the DF bit")
	}
	// The old socket supports DF, so gating before the swap would arm the prober.
	if !c.conn.capabilities().DF {
		t.Fatal("test setup: old send conn reports DF = false")
	}
	c.sendQueue = newSendQueue(c.conn)
	go c.sendQueue.Run()
	t.Cleanup(func() { c.sendQueue.Close() })

	c.switchToNewPath(&Transport{conn: &dfRawConn{df: false}}, monotime.Now())

	if !c.mtuDiscoverer.lastProbeTime.IsZero() {
		t.Errorf("lastProbeTime = %v, want zero: the new socket does not support DF", c.mtuDiscoverer.lastProbeTime)
	}
}

// TestResetMTUDiscovererAlwaysForgets checks the half of resetMTUDiscoverer the
// gate must not swallow: an estimate probed on the old path is dropped on every
// migration, permitted or not, because it may be too large for the new path and
// nothing else lowers it.
func TestResetMTUDiscovererAlwaysForgets(t *testing.T) {
	for _, disabled := range []bool{true, false} {
		c, df := newQNTMigrationMTUTestConn(t, disabled)
		if !disabled && !df {
			t.Skip("platform does not support setting the DF bit")
		}
		c.mtuDiscoverer.min = 1400

		c.resetMTUDiscoverer(monotime.Now(), protocol.ByteCount(protocol.InitialPacketSize), protocol.ByteCount(protocol.MaxPacketBufferSize))

		if got := c.mtuDiscoverer.CurrentSize(); got != protocol.ByteCount(protocol.InitialPacketSize) {
			t.Errorf("DisablePathMTUDiscovery=%v: CurrentSize = %d, want %d", disabled, got, protocol.InitialPacketSize)
		}
	}
}
