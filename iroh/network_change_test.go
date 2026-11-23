package iroh

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/netreport"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// TestNetworkChangeWithoutRelaysUpdatesLocalAddrsImmediately mirrors upstream
// n0-computer/iroh#4605 (lan_switch_advertises_new_addr_without_relay): when
// no relays are configured, NetworkChange must immediately advertise the new
// local interface addresses on WatchAddr and stop advertising stale ones.
func TestNetworkChangeWithoutRelaysUpdatesLocalAddrsImmediately(t *testing.T) {
	var mu sync.Mutex
	currentIPs := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	getIPs := func() []netip.Addr {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(currentIPs)
	}
	setIPs := func(ips ...netip.Addr) {
		mu.Lock()
		currentIPs = slices.Clone(ips)
		mu.Unlock()
	}

	ep, err := Bind(t.Context(),
		WithoutRelayTransports(),
		withLocalInterfaceAddrs(getIPs),
	)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer ep.Shutdown(context.Background())

	port := ep.LocalAddr().Port()
	if port == 0 {
		t.Fatal("LocalAddr port = 0")
	}
	w := ep.WatchAddr()

	waitAddr := func(want, forbid []netip.Addr) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		matches := func(addr netaddr.EndpointAddr) bool {
			ips := addr.IPAddrs()
			for _, ip := range want {
				if !slices.Contains(ips, netip.AddrPortFrom(ip, port)) {
					return false
				}
			}
			for _, ip := range forbid {
				if slices.Contains(ips, netip.AddrPortFrom(ip, port)) {
					return false
				}
			}
			return true
		}
		if matches(w.Current()) {
			return
		}
		for {
			addr, err := w.Updated(ctx)
			if err != nil {
				t.Fatalf("WatchAddr did not update to want=%v forbid=%v (current=%v): %v", want, forbid, w.Current().IPAddrs(), err)
			}
			if matches(addr) {
				return
			}
		}
	}

	ipA := netip.MustParseAddr("192.0.2.10")
	ipB := netip.MustParseAddr("198.51.100.20")
	ipC := netip.MustParseAddr("203.0.113.30")
	lo4 := netip.MustParseAddr("127.0.0.1")
	lo6 := netip.MustParseAddr("::1")

	ep.NetworkChange()
	waitAddr([]netip.Addr{ipA}, nil)

	// Switch to lan-b: advertise ipB and retire ipA.
	setIPs(ipB)
	ep.NetworkChange()
	waitAddr([]netip.Addr{ipB}, []netip.Addr{ipA})

	// Switch to lan-c: advertise ipC and retire ipA, ipB.
	setIPs(ipC)
	ep.NetworkChange()
	waitAddr([]netip.Addr{ipC}, []netip.Addr{ipA, ipB})

	// Switch offline (loopback only): advertise loopback and retire ipC.
	setIPs(lo4, lo6)
	ep.NetworkChange()
	waitAddr([]netip.Addr{lo4, lo6}, []netip.Addr{ipA, ipB, ipC})
}

func TestNetworkChangeWithoutIPTransportsIsNoOp(t *testing.T) {
	ep, err := Bind(t.Context(),
		WithoutIPTransports(),
		WithoutRelayTransports(),
		withLocalInterfaceAddrs(func() []netip.Addr {
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}
		}),
	)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer ep.Shutdown(context.Background())

	ep.NetworkChange()
	if got := ep.Addr().IPAddrs(); len(got) != 0 {
		t.Fatalf("IPAddrs = %v, want empty with WithoutIPTransports", got)
	}
}

func TestNetworkChangeWithRelaysTriggersNetReport(t *testing.T) {
	u, err := netaddr.ParseRelayURL("https://relay.example")
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	called := make(chan struct{}, 4)
	ep, err := Bind(t.Context(),
		WithRelayMode(relay.ModeCustomURLs(u)),
		withNetReportRunner(func(context.Context) (*netreport.Report, error) {
			calls.Add(1)
			select {
			case called <- struct{}{}:
			default:
			}
			return &netreport.Report{Full: true, PreferredRelay: u}, nil
		}),
	)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defer ep.Shutdown(context.Background())

	// Wait for the initial report.
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("initial net_report did not run")
	}

	// NetworkChange must trigger an immediate second report without waiting
	// for the 5-minute periodic interval.
	ep.NetworkChange()
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("NetworkChange did not trigger immediate net_report")
	}
	if calls.Load() < 2 {
		t.Fatalf("net_report calls = %d, want >= 2", calls.Load())
	}
}
