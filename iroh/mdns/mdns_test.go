//go:build !js

package mdns

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestAnnouncementRoundTrip(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	user, err := dns.NewUserData("lan")
	if err != nil {
		t.Fatal(err)
	}
	data := dns.NewEndpointData().
		WithIPAddrs(netip.MustParseAddrPort("192.0.2.1:7777"), netip.MustParseAddrPort("[2001:db8::1]:7777")).
		WithRelayURL(relay).
		WithUserData(&user)

	packet, err := buildAnnouncement(DefaultServiceName, announcementData{
		id:       id,
		port:     7777,
		ips:      []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7777"), netip.MustParseAddrPort("[2001:db8::1]:7777")},
		relay:    relay.String(),
		userData: user.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseAnnouncement(packet, DefaultServiceName)
	if !ok {
		t.Fatal("parseAnnouncement failed")
	}
	if got.ID != id {
		t.Fatalf("ID = %v, want %v", got.ID, id)
	}
	if !sameAddrPorts(got.Data.IPAddrs(), data.IPAddrs()) {
		t.Fatalf("IPAddrs = %v, want %v", got.Data.IPAddrs(), data.IPAddrs())
	}
	if relays := got.Data.RelayURLs(); len(relays) != 1 || !relays[0].Equal(relay) {
		t.Fatalf("RelayURLs = %v, want %v", relays, relay)
	}
	if gotUser := got.Data.UserData(); gotUser == nil || gotUser.String() != "lan" {
		t.Fatalf("UserData = %v, want lan", gotUser)
	}
}

func TestDiscoveryResolveFromPacket(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	d := New(id, WithLookupTimeout(20*time.Millisecond))
	packet, err := buildAnnouncement(DefaultServiceName, announcementData{
		id:   id,
		port: 7777,
		ips:  []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7777")},
	})
	if err != nil {
		t.Fatal(err)
	}
	d.handlePacket(packet)
	var gotID key.EndpointID
	for item, err := range d.Resolve(context.Background(), id) {
		if err != nil {
			t.Fatal(err)
		}
		gotID = item.EndpointID()
	}
	if gotID != id {
		t.Fatalf("Resolve ID = %v, want %v", gotID, id)
	}
}

func TestDiscoveryAnnouncementUsesLocalID(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	d := New(id)
	packet, err := d.announcement(dns.NewEndpointData().WithIPAddrs(netip.MustParseAddrPort("192.0.2.1:7777")))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseAnnouncement(packet, DefaultServiceName)
	if !ok {
		t.Fatal("parseAnnouncement failed")
	}
	if got.ID != id {
		t.Fatalf("announcement ID = %v, want %v", got.ID, id)
	}
}

func TestServiceNameIsolation(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	packet, err := buildAnnouncement("other", announcementData{
		id:   id,
		port: 7777,
		ips:  []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7777")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseAnnouncement(packet, DefaultServiceName); ok {
		t.Fatal("parsed announcement for different service")
	}
}

func TestEndpointLabelMatchesRustMDNS(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	parsed, err := parseEndpointLabel(endpointLabel(id))
	if err != nil {
		t.Fatal(err)
	}
	if parsed != id {
		t.Fatalf("endpoint label round trip = %v, want %v", parsed, id)
	}
}

func TestAnnouncementInfoPreservesIPv6Zone(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	d := New(id)
	want := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone("en0"), 7777)
	info, err := d.announcementInfo(dns.NewEndpointData().WithIPAddrs(want))
	if err != nil {
		t.Fatal(err)
	}
	if len(info.ips) != 1 || info.ips[0] != want {
		t.Fatalf("announcementInfo IPs = %v, want [%s]", info.ips, want)
	}
	got := infoFromAnnouncement(info).Data.IPAddrs()
	if len(got) != 1 || got[0] != want {
		t.Fatalf("infoFromAnnouncement IPs = %v, want [%s]", got, want)
	}
}

func sameAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[netip.AddrPort]int)
	for _, addr := range a {
		seen[addr]++
	}
	for _, addr := range b {
		if seen[addr] == 0 {
			return false
		}
		seen[addr]--
	}
	return true
}

func TestAnnouncementPort(t *testing.T) {
	for _, tt := range []struct {
		name  string
		addrs []string
		want  uint16
	}{
		{name: "single", addrs: []string{"192.0.2.1:7777"}, want: 7777},
		{
			name:  "majority wins over first",
			addrs: []string{"192.0.2.1:1111", "192.0.2.2:7777", "[2001:db8::1]:7777"},
			want:  7777,
		},
		{
			name:  "lowest port breaks a tie",
			addrs: []string{"192.0.2.1:9999", "192.0.2.2:7777"},
			want:  7777,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var addrs []netip.AddrPort
			for _, a := range tt.addrs {
				addrs = append(addrs, netip.MustParseAddrPort(a))
			}
			if got := announcementPort(addrs); got != tt.want {
				t.Fatalf("announcementPort(%v) = %d, want %d", tt.addrs, got, tt.want)
			}
		})
	}
}

// TestPublishLogsWhatItCannotAnnounce checks that the two things Publish cannot
// tell its fire-and-forget caller reach the logger instead.
func TestPublishLogsWhatItCannotAnnounce(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	relay, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		data dns.EndpointData
		// announce reaches the same code Publish does without the multicast
		// write, for the case where an announcement is actually built.
		announce bool
		want     string
	}{
		{
			name: "relay only",
			data: dns.NewEndpointData().WithRelayURL(relay),
			want: "not announcing endpoint data",
		},
		{
			name: "addresses on another port",
			data: dns.NewEndpointData().WithIPAddrs(
				netip.MustParseAddrPort("192.0.2.1:7777"),
				netip.MustParseAddrPort("192.0.2.2:7777"),
				netip.MustParseAddrPort("192.0.2.3:9999"),
			),
			announce: true,
			want:     "dropping addresses on others",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			d := New(sk.Public().EndpointID(), WithLogger(logger))
			if tt.announce {
				if _, err := d.announcement(tt.data); err != nil {
					t.Fatalf("announcement: %v", err)
				}
			} else {
				d.Publish(tt.data)
			}
			if !strings.Contains(logs.String(), tt.want) {
				t.Fatalf("logged %q, want it to mention %q", logs.String(), tt.want)
			}
		})
	}
}
