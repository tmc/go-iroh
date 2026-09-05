//go:build !js

package mdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"
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

// buildTypedQuery builds a one-question query of the given type, which
// buildQuery cannot: it asks PTR for every name.
func buildTypedQuery(typ uint16, name string) ([]byte, error) {
	b := dnsBuilder{buf: make([]byte, 12)}
	binary.BigEndian.PutUint16(b.buf[4:6], 1)
	if err := b.name(name); err != nil {
		return nil, err
	}
	b.u16(typ)
	b.u16(dnsClassIN)
	return b.buf, nil
}

// TestAnswerForQuery checks the responder's decision: a Discovery answers a PTR
// query for its service or its own instance, and an SRV or TXT query for its
// own instance, with its last announcement, and answers nothing else.
func TestAnswerForQuery(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	other, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	data := dns.NewEndpointData().WithIPAddrs(netip.MustParseAddrPort("192.0.2.1:7777"))

	serviceQuery, err := buildQuery(serviceName(DefaultServiceName))
	if err != nil {
		t.Fatal(err)
	}
	ownQuery, err := buildQuery(instanceName(DefaultServiceName, id))
	if err != nil {
		t.Fatal(err)
	}
	otherQuery, err := buildQuery(instanceName(DefaultServiceName, other.Public().EndpointID()))
	if err != nil {
		t.Fatal(err)
	}
	ownSRV, err := buildTypedQuery(dnsTypeSRV, instanceName(DefaultServiceName, id))
	if err != nil {
		t.Fatal(err)
	}
	ownTXT, err := buildTypedQuery(dnsTypeTXT, instanceName(DefaultServiceName, id))
	if err != nil {
		t.Fatal(err)
	}
	serviceSRV, err := buildTypedQuery(dnsTypeSRV, serviceName(DefaultServiceName))
	if err != nil {
		t.Fatal(err)
	}
	otherSRV, err := buildTypedQuery(dnsTypeSRV, instanceName(DefaultServiceName, other.Public().EndpointID()))
	if err != nil {
		t.Fatal(err)
	}
	ownA, err := buildTypedQuery(dnsTypeA, instanceName(DefaultServiceName, id))
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name      string
		published bool
		passive   bool
		packet    []byte
		want      bool
	}{
		{name: "service query", published: true, packet: serviceQuery, want: true},
		{name: "own instance query", published: true, packet: ownQuery, want: true},
		{name: "another instance query", published: true, packet: otherQuery},
		{name: "own instance SRV query", published: true, packet: ownSRV, want: true},
		{name: "own instance TXT query", published: true, packet: ownTXT, want: true},
		{name: "service SRV query", published: true, packet: serviceSRV},
		{name: "another instance SRV query", published: true, packet: otherSRV},
		{name: "own instance A query", published: true, packet: ownA},
		{name: "nothing published yet", packet: serviceQuery},
		{name: "passive", published: true, passive: true, packet: serviceQuery},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := New(id, WithPassive(tt.passive))
			if tt.published {
				if _, err := d.announcement(data); err != nil {
					t.Fatalf("announcement: %v", err)
				}
			}
			answer, ok := d.answerFor(tt.packet)
			if ok != tt.want {
				t.Fatalf("answerFor = %v, want %v", ok, tt.want)
			}
			if !ok {
				return
			}
			info, ok := parseAnnouncement(answer, DefaultServiceName)
			if !ok {
				t.Fatal("answer is not a parseable announcement")
			}
			if !info.ID.Equal(id) {
				t.Fatalf("answer announces %s, want %s", info.ID, id)
			}
		})
	}

	// An announcement must not be answered, or two listeners would answer each
	// other forever.
	d := New(id)
	if _, err := d.announcement(data); err != nil {
		t.Fatal(err)
	}
	announcement, err := d.announcement(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.answerFor(announcement); ok {
		t.Fatal("answered an announcement")
	}
}

// TestHandlePacketAnswersQueries checks that the read loop routes a query to
// the responder and an announcement to the cache. The response delay is set
// past the end of the test so nothing is multicast from here.
func TestHandlePacketAnswersQueries(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	d := New(id)
	d.responseDelay = func() time.Duration { return time.Hour }
	if _, err := d.announcement(dns.NewEndpointData().WithIPAddrs(netip.MustParseAddrPort("192.0.2.1:7777"))); err != nil {
		t.Fatal(err)
	}

	query, err := buildQuery(serviceName(DefaultServiceName))
	if err != nil {
		t.Fatal(err)
	}
	if !d.answerQuery(query) {
		t.Fatal("a service query was not answered")
	}
	d.handlePacket(query)
	if _, ok := d.item(id); ok {
		t.Fatal("a query was cached as an announcement")
	}

	peer, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	peerID := peer.Public().EndpointID()
	peerDiscovery := New(peerID)
	announcement, err := peerDiscovery.announcement(dns.NewEndpointData().WithIPAddrs(netip.MustParseAddrPort("192.0.2.9:7777")))
	if err != nil {
		t.Fatal(err)
	}
	d.handlePacket(announcement)
	if _, ok := d.item(peerID); !ok {
		t.Fatal("an announcement was not cached")
	}
	if d.answerQuery(announcement) {
		t.Fatal("an announcement was answered")
	}
}

// TestListenIPv6MDNS checks that the IPv6 listener binds the mDNS port and
// joins ff02::fb. A host without IPv6, or one whose mDNS port is taken, cannot
// run it, and the Discovery it belongs to falls back to IPv4 there.
func TestListenIPv6MDNS(t *testing.T) {
	conn, err := listenIPv6MDNS(context.Background())
	if err != nil {
		t.Skipf("no ipv6 mdns listener: %v", err)
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	if addr.Port != mdnsPort {
		t.Fatalf("listening on port %d, want %d", addr.Port, mdnsPort)
	}
}

// TestReadLoopCachesAnnouncementOverIPv6 checks that the read loop Start runs
// on the IPv6 socket caches what it hears, so a peer found over ff02::fb
// resolves like one found over 224.0.0.251.
func TestReadLoopCachesAnnouncementOverIPv6(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	packet, err := buildAnnouncement(DefaultServiceName, announcementData{
		id:   id,
		port: 7777,
		ips:  []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::1]:7777")},
	})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no ipv6 loopback: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := New(key.EndpointID{})
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- d.readLoop(ctx, conn) }()

	sender, err := net.DialUDP("udp6", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write(packet); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := d.item(id); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("announcement not cached")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("readLoop: %v", err)
	}
}
