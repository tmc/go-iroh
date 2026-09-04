package iroh

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/internal/netreport"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

func withNetReportRunner(run netReportRunner) Option {
	return func(c *config) error {
		c.disableNetReport = false
		c.netReport = run
		return nil
	}
}

func withNetReportInterval(d time.Duration) Option {
	return func(c *config) error {
		c.netReportEvery = d
		return nil
	}
}

type endpointNATPMPServer struct {
	conn    *net.UDPConn
	port    uint16
	deleted chan struct{}
	once    sync.Once
}

func newEndpointNATPMPServer(t *testing.T) *endpointNATPMPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	s := &endpointNATPMPServer{
		conn:    conn,
		port:    conn.LocalAddr().(*net.UDPAddr).AddrPort().Port(),
		deleted: make(chan struct{}),
	}
	t.Cleanup(func() { _ = conn.Close() })
	go s.serve()
	return s
}

func (s *endpointNATPMPServer) serve() {
	buf := make([]byte, 64)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		switch {
		case len(req) == 2 && req[0] == 0 && req[1] == 0:
			resp := make([]byte, 12)
			resp[1] = 0x80
			copy(resp[8:12], []byte{203, 0, 113, 20})
			_, _ = s.conn.WriteToUDP(resp, addr)
		case len(req) == 12 && req[0] == 0 && req[1] == 1:
			lifetime := binary.BigEndian.Uint32(req[8:12])
			if lifetime == 0 {
				s.once.Do(func() { close(s.deleted) })
			}
			resp := make([]byte, 16)
			resp[1] = 0x81
			copy(resp[8:10], req[4:6])
			binary.BigEndian.PutUint16(resp[10:12], 4321)
			binary.BigEndian.PutUint32(resp[12:16], lifetime)
			_, _ = s.conn.WriteToUDP(resp, addr)
		}
	}
}

type endpointFakeCustomTransport struct {
	mu      sync.Mutex
	sends   []endpointFakeCustomSend
	recv    chan CustomDatagram
	addrs   []netaddr.CustomAddr
	addrErr error
}

type endpointFakeCustomSend struct {
	remote netaddr.CustomAddr
	data   []byte
}

func newEndpointFakeCustomTransport() *endpointFakeCustomTransport {
	return &endpointFakeCustomTransport{recv: make(chan CustomDatagram, 4)}
}

func (t *endpointFakeCustomTransport) Serve(ctx context.Context, recv func(CustomDatagram) bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-t.recv:
			recv(d)
		}
	}
}

func (t *endpointFakeCustomTransport) Send(remote netaddr.CustomAddr, local *netaddr.CustomAddr, p []byte) bool {
	_ = local
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sends = append(t.sends, endpointFakeCustomSend{remote: remote, data: append([]byte(nil), p...)})
	return true
}

func (t *endpointFakeCustomTransport) LocalCustomAddrs(ctx context.Context) ([]netaddr.CustomAddr, error) {
	_ = ctx
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netaddr.CustomAddr(nil), t.addrs...), t.addrErr
}

func (t *endpointFakeCustomTransport) lastSend() (endpointFakeCustomSend, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.sends) == 0 {
		return endpointFakeCustomSend{}, false
	}
	return t.sends[len(t.sends)-1], true
}

// TestEndpointSecretKey verifies SecretKey returns the configured key and that
// its public half matches the endpoint id.
// TestBindPacketConnFamily pins that the socket family follows the bind
// address. net.ListenUDP("udp", "0.0.0.0:0") returns a dual-stack socket whose
// LocalAddr reports [::], which made Endpoint.LocalAddr contradict WithBindAddr.
func TestBindPacketConnFamily(t *testing.T) {
	tests := []struct {
		name    string
		bind    string
		wantIs4 bool
	}{
		{"ipv4 unspecified", "0.0.0.0:0", true},
		{"ipv4 loopback", "127.0.0.1:0", true},
		{"ipv6 unspecified is dual-stack", "[::]:0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := bindPacketConn(config{}, netip.MustParseAddrPort(tt.bind))
			if err != nil {
				t.Fatalf("bindPacketConn(%s): %v", tt.bind, err)
			}
			defer conn.Close()
			got := conn.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
			if got.Is4() != tt.wantIs4 {
				t.Errorf("bind %s: LocalAddr %v, Is4 = %v, want %v", tt.bind, got, got.Is4(), tt.wantIs4)
			}
		})
	}
}

func TestEndpointSecretKey(t *testing.T) {
	ctx := context.Background()
	sk, _ := key.GenerateSecretKey()
	ep, err := Bind(ctx, WithSecretKey(sk))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	if !ep.SecretKey().Public().Equal(sk.Public()) {
		t.Errorf("SecretKey().Public() = %s, want %s", ep.SecretKey().Public(), sk.Public())
	}
	if !ep.SecretKey().Public().EndpointID().Equal(ep.ID()) {
		t.Errorf("SecretKey().Public() = %s, but ID() = %s", ep.SecretKey().Public(), ep.ID())
	}
}

// TestRelayOnlyAdvertisesNoIP checks that an endpoint with no IP transport
// (nil udp socket) never advertises an IP address, even when disableIP was not
// requested directly. bindPacketConn returns a nil socket both for
// WithoutIPTransports and on the js build; disableIP is coupled to that so the
// endpoint does not advertise a zero LocalAddr to peers.
func TestRelayOnlyAdvertisesNoIP(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithoutIPTransports())
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	if got := ep.LocalAddr(); got.IsValid() {
		t.Errorf("LocalAddr = %v, want zero value for a relay-only endpoint", got)
	}
	if ips := ep.Addr().IPAddrs(); len(ips) != 0 {
		t.Errorf("Addr advertised %d IP(s) %v, want none for a relay-only endpoint", len(ips), ips)
	}
}

func TestEndpointLifecycleAddressSurface(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	if got := ep.LocalAddr(); !got.IsValid() {
		t.Fatalf("LocalAddr = %v, want valid address", got)
	}
	select {
	case <-ep.Closed():
		t.Fatal("Closed channel fired before Close")
	default:
	}

	w := ep.WatchAddr()
	if got := w.Current(); len(got.IPAddrs()) != 1 || got.IPAddrs()[0] != ep.LocalAddr() {
		t.Fatalf("WatchAddr initial = %v, want local %v", got.IPAddrs(), ep.LocalAddr())
	}
	if got, err := w.Updated(ctx); err != nil || len(got.IPAddrs()) != 1 || got.IPAddrs()[0] != ep.LocalAddr() {
		t.Fatalf("WatchAddr first Updated = %v, %v", got.IPAddrs(), err)
	}

	external := netip.MustParseAddrPort("203.0.113.44:4444")
	ep.AddExternalAddr(external)
	got, err := w.Updated(ctx)
	if err != nil {
		t.Fatalf("WatchAddr update: %v", err)
	}
	if !containsAddrPort(got.IPAddrs(), external) {
		t.Fatalf("WatchAddr IPs = %v, want external %v", got.IPAddrs(), external)
	}
	if !containsAddrPort(ep.Addr().IPAddrs(), external) {
		t.Fatalf("Addr IPs = %v, want external %v", ep.Addr().IPAddrs(), external)
	}
	if got := ep.localNATTraversalCandidates(); !containsAddrPort(got, external) {
		t.Fatalf("localNATTraversalCandidates = %v, want external %v", got, external)
	}
	if ep.RemoveExternalAddr(netip.MustParseAddrPort("203.0.113.45:4444")) {
		t.Fatal("RemoveExternalAddr(unadded) = true, want false")
	}
	if ep.RemoveExternalAddr(netip.AddrPort{}) {
		t.Fatal("RemoveExternalAddr(invalid) = true, want false")
	}
	if !ep.RemoveExternalAddr(external) {
		t.Fatal("RemoveExternalAddr(added) = false, want true")
	}
	got, err = w.Updated(ctx)
	if err != nil {
		t.Fatalf("WatchAddr remove update: %v", err)
	}
	if containsAddrPort(got.IPAddrs(), external) {
		t.Fatalf("WatchAddr IPs after remove = %v, still contains external %v", got.IPAddrs(), external)
	}
	if containsAddrPort(ep.Addr().IPAddrs(), external) {
		t.Fatalf("Addr IPs after remove = %v, still contains external %v", ep.Addr().IPAddrs(), external)
	}
	if got := ep.localNATTraversalCandidates(); containsAddrPort(got, external) {
		t.Fatalf("localNATTraversalCandidates after remove = %v, still contains external %v", got, external)
	}
	if ep.RemoveExternalAddr(external) {
		t.Fatal("RemoveExternalAddr(removed) = true, want false")
	}

	if err := ep.Shutdown(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-ep.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed channel did not fire")
	}
}

func TestEndpointNATPMPPublishesExternalAddr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gateway := newEndpointNATPMPServer(t)
	ep, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithNATPMP(netip.MustParseAddr("127.0.0.1")),
		withNATPMPPort(gateway.port),
	)
	if err != nil {
		t.Fatal(err)
	}
	w := ep.WatchAddr()
	want := netip.MustParseAddrPort("203.0.113.20:4321")
	for {
		addr, err := w.Updated(ctx)
		if err != nil {
			t.Fatalf("WatchAddr: %v", err)
		}
		if containsAddrPort(addr.IPAddrs(), want) {
			break
		}
	}
	if err := ep.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-gateway.deleted:
	case <-ctx.Done():
		t.Fatal("nat-pmp delete request not observed")
	}
}

func TestEndpointNATPMPRejectsInvalidGateway(t *testing.T) {
	if err := WithNATPMP(netip.MustParseAddr("2001:db8::1"))(&config{}); err == nil {
		t.Fatal("WithNATPMP IPv6 gateway error = nil")
	}
}

func TestEndpointWithKeyLogWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-keylog/0"
	var serverKeys bytes.Buffer
	server, err := Bind(ctx,
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithKeyLogWriter(&serverKeys),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	accepted := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err == nil {
			err = conn.CloseWithError(0, "")
		}
		accepted <- err
	}()

	var clientKeys bytes.Buffer
	client, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithKeyLogWriter(&clientKeys),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatal(err)
	}
	conn.CloseWithError(0, "")
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
	if clientKeys.Len() == 0 {
		t.Fatal("client key log writer was not written")
	}
	if serverKeys.Len() == 0 {
		t.Fatal("server key log writer was not written")
	}
}

func TestEndpointTransportModeOptions(t *testing.T) {
	ctx := context.Background()

	rurl := relayURL(t, "https://relay.example/")
	ep, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithRelayMode(relay.ModeCustom(relay.MapFromURLs(rurl))),
		WithoutIPTransports(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	if got := ep.Addr().IPAddrs(); len(got) != 0 {
		t.Fatalf("WithoutIPTransports Addr IPs = %v, want none", got)
	}
	if got := ep.localNATTraversalCandidates(); len(got) != 0 {
		t.Fatalf("WithoutIPTransports NAT candidates = %v, want none", got)
	}
	ep.AddExternalAddr(netip.MustParseAddrPort("203.0.113.1:9999"))
	if ep.RemoveExternalAddr(netip.MustParseAddrPort("203.0.113.1:9999")) {
		t.Fatal("WithoutIPTransports RemoveExternalAddr = true, want false")
	}
	if got := ep.Addr().IPAddrs(); len(got) != 0 {
		t.Fatalf("WithoutIPTransports external Addr IPs = %v, want none", got)
	}
	remoteKey, _ := key.GenerateSecretKey()
	addr := netaddr.NewEndpointAddr(remoteKey.Public().EndpointID()).WithIP(netip.MustParseAddrPort("127.0.0.1:1")).WithRelayURL(rurl)
	targets := ep.dialTargets(addr)
	if len(targets) != 1 {
		t.Fatalf("WithoutIPTransports dialTargets = %v, want relay-only target", targets)
	}

	relayFirst, err := Bind(ctx,
		WithRelayMode(relay.ModeCustom(relay.MapFromURLs(rurl))),
		WithRelayFirstDial(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer relayFirst.Shutdown(ctx)
	targets = relayFirst.dialTargets(addr)
	if len(targets) != 2 {
		t.Fatalf("WithRelayFirstDial dialTargets len = %d, want 2: %v", len(targets), targets)
	}
	first, ok := targets[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("WithRelayFirstDial first target = %T, want *net.UDPAddr", targets[0])
	}
	if got := socket.Classify(netip.MustParseAddrPort(first.String()).Addr()); got != socket.KindRelay {
		t.Fatalf("WithRelayFirstDial first target kind = %v, want relay", got)
	}
	second, ok := targets[1].(*net.UDPAddr)
	if !ok {
		t.Fatalf("WithRelayFirstDial second target = %T, want *net.UDPAddr", targets[1])
	}
	if got := socket.Classify(netip.MustParseAddrPort(second.String()).Addr()); got != socket.KindIP {
		t.Fatalf("WithRelayFirstDial second target kind = %v, want ip", got)
	}

	noRelay, err := Bind(ctx,
		WithRelayMode(relay.ModeCustom(relay.MapFromURLs(rurl))),
		WithoutRelayTransports(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer noRelay.Shutdown(ctx)
	if err := noRelay.Online(ctx); !errors.Is(err, ErrNoRelay) {
		t.Fatalf("WithoutRelayTransports Online = %v, want ErrNoRelay", err)
	}
}

func TestEndpointInsertRemoveRelay(t *testing.T) {
	ctx := context.Background()
	relayServer := newEchoRelayServer(t)
	relayURL := relayServer.url(t)

	ep, err := Bind(ctx, WithRelayMode(relay.ModeCustom(relay.MapFromURLs(relayURL))))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	cfg := RelayConfig{AuthToken: "token"}
	prev, err := ep.InsertRelay(relayURL, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || !prev.URL.Equal(relayURL) {
		t.Fatalf("InsertRelay previous = %v, want %v", prev, relayURL)
	}

	removed := ep.RemoveRelay(relayURL)
	if removed == nil || removed.AuthToken != "token" {
		t.Fatalf("RemoveRelay = %+v, want token config", removed)
	}
	if got := ep.RemoveRelay(relayURL); got != nil {
		t.Fatalf("second RemoveRelay = %+v, want nil", got)
	}

	prev, err = ep.InsertRelay(relayURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		t.Fatalf("InsertRelay previous after remove = %+v, want nil", prev)
	}
}

func TestEndpointInsertRelayNoRelayTransport(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	relayURL := relay.StagingMap().URLs()[0]
	if _, err := ep.InsertRelay(relayURL, nil); !errors.Is(err, ErrNoRelay) {
		t.Fatalf("InsertRelay error = %v, want ErrNoRelay", err)
	}
	if got := ep.RemoveRelay(relayURL); got != nil {
		t.Fatalf("RemoveRelay = %+v, want nil", got)
	}
}

func TestEndpointWithBindAddrOpts(t *testing.T) {
	ctx := context.Background()
	defaultRoute := true
	ep, err := Bind(ctx, WithBindAddrOpts(netip.AddrPortFrom(netip.IPv6Loopback(), 0), BindOpts{
		PrefixLen:      128,
		IsRequired:     true,
		IsDefaultRoute: &defaultRoute,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	if got := ep.LocalAddr(); !got.IsValid() {
		t.Fatalf("LocalAddr = %v, want valid address", got)
	}
	if !ep.LocalAddr().Addr().Is6() {
		t.Fatalf("LocalAddr = %v, want IPv6", ep.LocalAddr())
	}
}

func TestEndpointWithBindAddrOptsRejectsBadPrefix(t *testing.T) {
	ctx := context.Background()
	if _, err := Bind(ctx, WithBindAddrOpts(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0), BindOpts{PrefixLen: 33})); err == nil {
		t.Fatal("Bind IPv4 /33 succeeded")
	}
	if _, err := Bind(ctx, WithBindAddrOpts(netip.AddrPortFrom(netip.IPv6Loopback(), 0), BindOpts{PrefixLen: 129})); err == nil {
		t.Fatal("Bind IPv6 /129 succeeded")
	}
}

func containsAddrPort(addrs []netip.AddrPort, want netip.AddrPort) bool {
	for _, addr := range addrs {
		if addr == want {
			return true
		}
	}
	return false
}

// TestEndpointWithAddressLookup verifies the option wires the lookup services
// into the endpoint's resolve hook: with a lookup configured the hook resolves
// a registered id to its addresses, and without one no hook is installed.
func TestEndpointWithAddressLookup(t *testing.T) {
	ctx := context.Background()

	// Without WithAddressLookup, the endpoint installs no resolve hook.
	plain, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Shutdown(ctx)
	if plain.resolveFunc() != nil {
		t.Error("resolveFunc() != nil without WithAddressLookup, want nil")
	}

	// With WithAddressLookup, the hook resolves through the registered services.
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	ip := netip.MustParseAddrPort("1.2.3.4:1234")

	mem := NewMemoryLookup()
	mem.AddEndpointInfo(endpointInfoWithIP(id, ip))
	var svcs AddressLookupServices
	svcs.AddResolver(mem)

	ep, err := Bind(ctx, WithAddressLookup(&svcs))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	resolve := ep.resolveFunc()
	if resolve == nil {
		t.Fatal("resolveFunc() = nil with WithAddressLookup, want non-nil")
	}
	addrs, err := drainResolved(ctx, resolve, id)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var found bool
	for _, a := range addrs {
		if ipa, ok := a.Addr.(netaddr.IPAddr); ok && ipa.Addr == ip {
			found = true
			if a.Provenance != MemoryProvenance {
				t.Fatalf("resolved provenance = %q, want %q", a.Provenance, MemoryProvenance)
			}
		}
	}
	if !found {
		t.Errorf("resolved addrs = %v, want one containing %s", addrs, ip)
	}
}

type relayPreferredPathSelector struct{}

func (relayPreferredPathSelector) Select(current netaddr.TransportAddr, candidates []PathCandidate) (netaddr.TransportAddr, bool) {
	for _, c := range candidates {
		if c.Addr.Network() == "relay" {
			return c.Addr, true
		}
	}
	return current, current != nil
}

func TestEndpointWithPathSelector(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithPathSelector(relayPreferredPathSelector{}))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	remote, _ := key.GenerateSecretKey()
	remoteID := remote.Public().EndpointID()
	relayURL := relayURL(t, "https://relay.example/")
	ip := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("127.0.0.1:9")),
		done: make(chan struct{}),
	}
	relay := &endpointQNTFakeConn{
		addr: socket.RelayAddr(relayURL, remoteID),
		done: make(chan struct{}),
	}
	_, actor := ep.remotes.AddConnectionActor(remoteID, ip)
	ep.remotes.AddConnection(remoteID, relay)

	waitForSelectedPath(t, ctx, actor, socket.RelayAddr(relayURL, remoteID))
}

func TestEndpointWithDNSResolver(t *testing.T) {
	ctx := context.Background()
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	info := endpointInfoWithIP(id, netip.MustParseAddrPort("127.0.0.1:1234"))

	ep, err := Bind(ctx, WithDNSResolver(&dns.Resolver{Lookuper: &fakeTXTLookuper{values: info.ToTXTStrings()}}))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	resolve := ep.resolveFunc()
	if resolve == nil {
		t.Fatal("resolveFunc() = nil with WithDNSResolver")
	}
	addrs, err := drainResolved(ctx, resolve, id)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("resolved addrs = %v, want one", addrs)
	}
}

func drainResolved(ctx context.Context, resolve socket.ResolveFunc, id key.EndpointID) ([]socket.ResolvedAddr, error) {
	var addrs []socket.ResolvedAddr
	var lastErr error
	for addr, err := range resolve(ctx, id) {
		if err != nil {
			lastErr = err
			continue
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return addrs, nil
}

func TestEndpointWithTransportConfig(t *testing.T) {
	ctx := context.Background()
	const keepAlive = 2 * time.Second
	const idle = 9 * time.Second
	const initialPacketSize = 1200
	const maxIncomingStreams = 64
	ep, err := Bind(ctx, WithTransportConfig(&QUICTransportConfig{
		KeepAlivePeriod:    keepAlive,
		MaxIdleTimeout:     idle,
		InitialPacketSize:  initialPacketSize,
		MaxIncomingStreams: maxIncomingStreams,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)
	if ep.quicConf.KeepAlivePeriod != keepAlive {
		t.Fatalf("KeepAlivePeriod = %v, want %v", ep.quicConf.KeepAlivePeriod, keepAlive)
	}
	if ep.quicConf.MaxIdleTimeout != idle {
		t.Fatalf("MaxIdleTimeout = %v, want %v", ep.quicConf.MaxIdleTimeout, idle)
	}
	if ep.quicConf.InitialPacketSize != initialPacketSize {
		t.Fatalf("InitialPacketSize = %d, want %d", ep.quicConf.InitialPacketSize, initialPacketSize)
	}
	if ep.quicConf.MaxIncomingStreams != maxIncomingStreams {
		t.Fatalf("MaxIncomingStreams = %d, want %d", ep.quicConf.MaxIncomingStreams, maxIncomingStreams)
	}
}

func TestEndpointWithCustomTransport(t *testing.T) {
	ctx := context.Background()
	custom := newEndpointFakeCustomTransport()
	ep, err := Bind(ctx, WithCustomTransport(custom))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	remote := netaddr.NewCustomAddr(42, []byte("endpoint-custom"))
	mapped := ep.sock.CustomMappedAddrFor(remote)
	const payload = "endpoint-custom-send"
	n, err := ep.magic.WriteTo([]byte(payload), net.UDPAddrFromAddrPort(mapped.AddrPort()))
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo n = %d, want %d", n, len(payload))
	}

	deadline := time.After(2 * time.Second)
	for {
		send, ok := custom.lastSend()
		if ok {
			if send.remote.String() != remote.String() {
				t.Fatalf("send remote = %v, want %v", send.remote, remote)
			}
			if string(send.data) != payload {
				t.Fatalf("send data = %q, want %q", send.data, payload)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for custom send")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestEndpointAddrIncludesCustomTransportAddrs(t *testing.T) {
	ctx := context.Background()
	local := netaddr.NewCustomAddr(42, []byte("local-custom"))
	custom := newEndpointFakeCustomTransport()
	custom.addrs = []netaddr.CustomAddr{local}
	ep, err := Bind(ctx, WithCustomTransport(custom))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	addr := ep.Addr()
	if !slices.ContainsFunc(addr.Addrs(), func(a netaddr.TransportAddr) bool {
		c, ok := a.(netaddr.CustomAddr)
		return ok && c.String() == local.String()
	}) {
		t.Fatalf("Endpoint.Addr addrs = %v, want custom %v", addr.Addrs(), local)
	}

	w := ep.WatchAddr()
	waddr, err := w.Updated(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(waddr.Addrs(), func(a netaddr.TransportAddr) bool {
		c, ok := a.(netaddr.CustomAddr)
		return ok && c.String() == local.String()
	}) {
		t.Fatalf("WatchAddr addrs = %v, want custom %v", waddr.Addrs(), local)
	}
}

func TestEndpointDialTargetsIncludeCustomAddrs(t *testing.T) {
	ctx := context.Background()
	custom := newEndpointFakeCustomTransport()
	ep, err := Bind(ctx, WithCustomTransport(custom), WithoutIPTransports(), WithoutRelayTransports())
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	remoteKey, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	remote := netaddr.NewCustomAddr(99, []byte("peer-fast"))
	targets := ep.dialTargets(netaddr.NewEndpointAddr(remoteKey.Public().EndpointID()).WithAddrs(remote))
	if len(targets) != 1 {
		t.Fatalf("dialTargets len = %d, want 1: %v", len(targets), targets)
	}
	udp, ok := targets[0].(*net.UDPAddr)
	if !ok {
		t.Fatalf("dial target type = %T, want *net.UDPAddr", targets[0])
	}
	if socket.Classify(udp.AddrPort().Addr()) != socket.KindCustom {
		t.Fatalf("dial target = %v, want custom mapped address", udp)
	}
	if got, ok := ep.sock.LookupCustom(socket.CustomMappedAddrFromAddr(udp.AddrPort().Addr())); !ok || got.String() != remote.String() {
		t.Fatalf("LookupCustom = %v, %v; want %v, true", got, ok, remote)
	}
}

func TestEndpointIDMappedSendFansOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	dst, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	remote, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	fake := &endpointQNTFakeConn{
		addr: socket.IPAddr(dst.LocalAddr().(*net.UDPAddr).AddrPort()),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public().EndpointID(), fake)
	select {
	case <-events:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	mapped := ep.sock.EndpointIDMappedAddrFor(remote.Public().EndpointID())
	const payload = "endpoint-id-fanout"
	n, err := ep.magic.WriteTo([]byte(payload), net.UDPAddrFromAddrPort(mapped.AddrPort()))
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo n = %d, want %d", n, len(payload))
	}

	if err := dst.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	rn, _, err := dst.ReadFrom(buf)
	if err != nil {
		t.Fatalf("dst.ReadFrom: %v", err)
	}
	if string(buf[:rn]) != payload {
		t.Fatalf("payload = %q, want %q", buf[:rn], payload)
	}
}

func TestEndpointLocalNATTraversalCandidates(t *testing.T) {
	ctx := context.Background()

	unspecified, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unspecified.Shutdown(ctx)
	if got := unspecified.localNATTraversalCandidates(); len(got) != 0 {
		t.Fatalf("default localNATTraversalCandidates = %v, want none for unspecified bind", got)
	}

	loopback, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer loopback.Shutdown(ctx)
	got := loopback.localNATTraversalCandidates()
	if len(got) != 1 {
		t.Fatalf("loopback localNATTraversalCandidates len = %d, want 1; got %v", len(got), got)
	}
	if got[0] != loopback.LocalAddr() {
		t.Fatalf("loopback localNATTraversalCandidates = %v, want [%v]", got, loopback.LocalAddr())
	}

	external4 := netip.MustParseAddrPort("203.0.113.10:4444")
	external6 := netip.MustParseAddrPort("[2001:db8::10]:5555")
	if !loopback.setExternalNATTraversalCandidates(external4, external6) {
		t.Fatal("setExternalNATTraversalCandidates = false, want true")
	}
	got = loopback.localNATTraversalCandidates()
	want := []netip.AddrPort{loopback.LocalAddr(), external4, external6}
	if !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates with externals = %v, want %v", got, want)
	}
	if loopback.setExternalNATTraversalCandidates(external4, external6) {
		t.Fatal("same setExternalNATTraversalCandidates = true, want false")
	}
}

func TestEndpointExternalNATTraversalCandidatesCanonicalize(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	bound := ep.LocalAddr()
	mapped := netip.AddrPortFrom(netip.AddrFrom16(bound.Addr().As16()), bound.Port())
	externalMapped := netip.MustParseAddrPort("[::ffff:198.51.100.10]:4444")
	externalCanon := netip.MustParseAddrPort("198.51.100.10:4444")
	if !ep.setExternalNATTraversalCandidates(
		mapped,
		externalMapped,
		externalCanon,
		netip.AddrPort{},
		netip.MustParseAddrPort("0.0.0.0:4444"),
		netip.MustParseAddrPort("198.51.100.11:0"),
	) {
		t.Fatal("setExternalNATTraversalCandidates = false, want true")
	}
	want := []netip.AddrPort{
		bound,
		externalCanon,
	}
	if got := ep.localNATTraversalCandidates(); !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates = %v, want %v", got, want)
	}
}

func TestEndpointExternalNATTraversalCandidatesReadvertiseActiveRemotes(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	remote, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public().EndpointID(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	external := netip.MustParseAddrPort("203.0.113.10:4444")
	if !ep.setExternalNATTraversalCandidates(external) {
		t.Fatal("setExternalNATTraversalCandidates = false, want true")
	}
	want := []netip.AddrPort{ep.LocalAddr(), external}
	if !equalAddrPorts(conn.natAddrs, want) {
		t.Fatalf("advertised candidates = %v, want %v", conn.natAddrs, want)
	}
}

func TestEndpointExternalNATTraversalCandidatesRemoveStaleRemoteCandidate(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	remote, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public().EndpointID(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	oldExternal := netip.MustParseAddrPort("203.0.113.10:4444")
	newExternal := netip.MustParseAddrPort("203.0.113.11:5555")
	if !ep.setExternalNATTraversalCandidates(oldExternal) {
		t.Fatal("first setExternalNATTraversalCandidates = false, want true")
	}
	if !ep.setExternalNATTraversalCandidates(newExternal) {
		t.Fatal("replacement setExternalNATTraversalCandidates = false, want true")
	}

	wantCurrent := []netip.AddrPort{ep.LocalAddr(), newExternal}
	if !equalAddrPorts(conn.currentNAT, wantCurrent) {
		t.Fatalf("current QNT candidates = %v, want %v", conn.currentNAT, wantCurrent)
	}
	if len(conn.removedNAT) != 1 || conn.removedNAT[0] != oldExternal {
		t.Fatalf("removed QNT candidates = %v, want [%v]", conn.removedNAT, oldExternal)
	}
}

func TestEndpointApplyNetReportNATTraversalCandidates(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	global4 := netip.MustParseAddrPort("[::ffff:198.51.100.10]:4444")
	global4Canon := netip.MustParseAddrPort("198.51.100.10:4444")
	global6 := netip.MustParseAddrPort("[2001:db8::10]:5555")
	if !ep.applyNetReport(netreport.Report{GlobalV4: global4, GlobalV6: global6}) {
		t.Fatal("applyNetReport = false, want true")
	}
	want := []netip.AddrPort{ep.LocalAddr(), global4Canon, global6}
	if got := ep.localNATTraversalCandidates(); !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates = %v, want %v", got, want)
	}
	if ep.applyNetReport(netreport.Report{GlobalV4: global4Canon, GlobalV6: global6}) {
		t.Fatal("same applyNetReport = true, want false")
	}
}

func TestEndpointApplyNetReportPreferredRelay(t *testing.T) {
	ctx := context.Background()
	fallback := relayURL(t, "https://a.relay.example/")
	preferred := relayURL(t, "https://b.relay.example/")
	ep, err := Bind(ctx, WithRelayMode(relay.ModeCustom(relay.MapFromURLs(fallback, preferred))))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	if st := ep.HomeRelayStatus().Current(); st == nil || !st.URL.Equal(fallback) {
		t.Fatalf("initial home relay = %v, want %v", st, fallback)
	}
	if !ep.applyNetReport(netreport.Report{PreferredRelay: preferred}) {
		t.Fatal("applyNetReport preferred relay = false, want true")
	}
	if st := ep.HomeRelayStatus().Current(); st == nil || !st.URL.Equal(preferred) {
		t.Fatalf("home relay after net_report = %v, want %v", st, preferred)
	}
	if ep.applyNetReport(netreport.Report{PreferredRelay: preferred}) {
		t.Fatal("same preferred relay applyNetReport = true, want false")
	}
}

func TestEndpointApplyEmptyNetReportClearsExternalNATTraversalCandidates(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	remote, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public().EndpointID(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	external := netip.MustParseAddrPort("203.0.113.10:4444")
	if !ep.applyNetReport(netreport.Report{GlobalV4: external}) {
		t.Fatal("applyNetReport with global = false, want true")
	}
	if !ep.applyNetReport(netreport.Report{}) {
		t.Fatal("empty applyNetReport = false, want true")
	}
	if got, want := ep.localNATTraversalCandidates(), []netip.AddrPort{ep.LocalAddr()}; !equalAddrPorts(got, want) {
		t.Fatalf("localNATTraversalCandidates after empty report = %v, want %v", got, want)
	}
	if got, want := conn.currentNAT, []netip.AddrPort{ep.LocalAddr()}; !equalAddrPorts(got, want) {
		t.Fatalf("current QNT candidates = %v, want %v", got, want)
	}
	if len(conn.removedNAT) != 1 || conn.removedNAT[0] != external {
		t.Fatalf("removed QNT candidates = %v, want [%v]", conn.removedNAT, external)
	}
}

func TestEndpointWithNetReportAdvertisesCandidates(t *testing.T) {
	ctx := context.Background()
	started := make(chan struct{})
	release := make(chan struct{})
	external := netip.MustParseAddrPort("203.0.113.10:4444")
	ep, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		withNetReportRunner(func(ctx context.Context) (*netreport.Report, error) {
			close(started)
			select {
			case <-release:
				return &netreport.Report{GlobalV4: external}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("netreport runner did not start")
	}

	remote, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	conn := &endpointQNTFakeConn{
		addr: socket.IPAddr(netip.MustParseAddrPort("192.0.2.20:5678")),
		done: make(chan struct{}),
	}
	events := ep.remotes.AddConnection(remote.Public().EndpointID(), conn)
	select {
	case <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for initial path event")
	}

	close(release)
	want := []netip.AddrPort{ep.LocalAddr(), external}
	deadline := time.After(2 * time.Second)
	for !equalAddrPorts(conn.currentNATTraversalCandidates(), want) {
		select {
		case <-deadline:
			t.Fatalf("current QNT candidates = %v, want %v", conn.currentNATTraversalCandidates(), want)
		case <-time.After(time.Millisecond):
		}
	}
}

func TestEndpointWithNetReportRefreshes(t *testing.T) {
	ctx := context.Background()
	first := netip.MustParseAddrPort("203.0.113.10:4444")
	second := netip.MustParseAddrPort("203.0.113.11:5555")
	reports := make(chan netreport.Report, 2)
	reports <- netreport.Report{GlobalV4: first}
	reports <- netreport.Report{GlobalV4: second}

	ep, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		withNetReportInterval(time.Millisecond),
		withNetReportRunner(func(ctx context.Context) (*netreport.Report, error) {
			select {
			case report := <-reports:
				return &report, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	want := []netip.AddrPort{ep.LocalAddr(), second}
	deadline := time.After(2 * time.Second)
	for !equalAddrPorts(ep.localNATTraversalCandidates(), want) {
		select {
		case <-deadline:
			t.Fatalf("local QNT candidates = %v, want %v", ep.localNATTraversalCandidates(), want)
		case <-time.After(time.Millisecond):
		}
	}
}

func TestEndpointSetALPNsReplacesRunningListener(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ep, err := Bind(ctx,
		WithALPNs("first/1"),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)
	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	firstAccepted := make(chan error, 1)
	go func() {
		conn, err := ep.Accept(ctx)
		if err == nil {
			if conn.ALPN() != "first/1" {
				err = errors.New("first accept negotiated wrong ALPN")
			}
			conn.CloseWithError(0, "")
		}
		firstAccepted <- err
	}()
	addr := netaddr.NewEndpointAddr(ep.ID()).WithIP(ep.LocalAddr())
	first, err := client.Connect(ctx, addr, "first/1")
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	first.CloseWithError(0, "")
	if err := <-firstAccepted; err != nil {
		t.Fatalf("first accept: %v", err)
	}

	if err := ep.SetALPNs([]string{"second/1"}); err != nil {
		t.Fatalf("SetALPNs second: %v", err)
	}
	secondAccepted := make(chan error, 1)
	go func() {
		conn, err := ep.Accept(ctx)
		if err == nil {
			if conn.ALPN() != "second/1" {
				err = errors.New("second accept negotiated wrong ALPN")
			}
			conn.CloseWithError(0, "")
		}
		secondAccepted <- err
	}()
	second, err := client.Connect(ctx, addr, "second/1")
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}
	second.CloseWithError(0, "")
	if err := <-secondAccepted; err != nil {
		t.Fatalf("second accept: %v", err)
	}
}

func TestEndpointQADCandidatesOpenSelectedQNTRouteDataPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	relayServer := newEchoRelayServer(t)
	relayURL := relayServer.url(t)
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))

	const alpn = "iroh-qad-qnt-data-path/0"
	server, err := Bind(ctx, WithALPNs(alpn), WithRelayMode(mode))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	client, err := Bind(ctx, WithRelayMode(mode))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}
	if err := client.Online(ctx); err != nil {
		t.Fatalf("client online: %v", err)
	}

	serverQAD := loopbackQADCandidate(server)
	clientQAD := loopbackQADCandidate(client)
	if !server.applyNetReport(netreport.Report{GlobalV6: serverQAD}) {
		t.Fatal("server applyNetReport = false, want QAD candidate change")
	}
	if !client.applyNetReport(netreport.Report{GlobalV6: clientQAD}) {
		t.Fatal("client applyNetReport = false, want QAD candidate change")
	}
	if got, want := server.localNATTraversalCandidates(), []netip.AddrPort{serverQAD}; !equalAddrPorts(got, want) {
		t.Fatalf("server localNATTraversalCandidates = %v, want QAD-only %v", got, want)
	}
	if got, want := client.localNATTraversalCandidates(), []netip.AddrPort{clientQAD}; !equalAddrPorts(got, want) {
		t.Fatalf("client localNATTraversalCandidates = %v, want QAD-only %v", got, want)
	}

	type acceptResult struct {
		conn *Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, err := server.Accept(ctx)
		accepted <- acceptResult{conn: conn, err: err}
	}()

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithRelayURL(relayURL), alpn)
	if err != nil {
		t.Fatalf("relay Connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	res := <-accepted
	if res.err != nil {
		t.Fatalf("server Accept: %v", res.err)
	}
	serverConn := res.conn
	defer serverConn.CloseWithError(0, "")

	if !conn.MultipathNegotiated() || !serverConn.MultipathNegotiated() {
		t.Fatalf("MultipathNegotiated client=%v server=%v, want both true", conn.MultipathNegotiated(), serverConn.MultipathNegotiated())
	}

	clientActor := client.remotes.Actor(server.ID())
	waitForSelectedPath(t, ctx, clientActor, socket.RelayAddr(relayURL, server.ID()))
	waitForConnNATAddress(t, ctx, conn.qc, serverQAD)
	if addrs, err := serverConn.qc.NATTraversalAddresses(); err != nil {
		t.Fatalf("server NATTraversalAddresses: %v", err)
	} else if slices.Contains(addrs, clientQAD) {
		t.Fatalf("server learned client QAD from ADD_ADDRESS: %v", addrs)
	}

	if err := clientActor.TriggerHolepunch(); err != nil {
		t.Fatalf("TriggerHolepunch: %v", err)
	}
	path := waitForQNTRoutePath(t, ctx, conn.qc, serverQAD)
	waitForSelectedPath(t, ctx, clientActor, socket.IPAddr(serverQAD))

	const msg = "qad-qnt-route-datagram"
	if err := conn.qc.SendDatagramOnPath(path.ID, []byte(msg)); err != nil {
		t.Fatalf("SendDatagramOnPath(%d): %v", path.ID, err)
	}
	got, err := serverConn.ReadDatagram(ctx)
	if err != nil {
		t.Fatalf("server ReadDatagram: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("server datagram = %q, want %q", got, msg)
	}
}

func loopbackQADCandidate(e *Endpoint) netip.AddrPort {
	return netip.AddrPortFrom(netip.IPv6Loopback(), e.LocalAddr().Port())
}

func waitForConnNATAddress(t *testing.T, ctx context.Context, c *quic.Conn, want netip.AddrPort) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		addrs, err := c.NATTraversalAddresses()
		if err != nil {
			t.Fatalf("NATTraversalAddresses: %v", err)
		}
		for _, addr := range addrs {
			if addr == want {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for remote NAT address %v; last addrs=%v", want, addrs)
		case <-ticker.C:
		}
	}
}

func waitForQNTRoutePath(t *testing.T, ctx context.Context, c *quic.Conn, want netip.AddrPort) quic.PathInfo {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		paths := c.Paths()
		for _, p := range paths {
			if p.ID != 0 && p.Validated && p.RemoteAddr == want {
				return p
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for validated QNT route path %v; last paths=%v closeCause=%v", want, paths, context.Cause(c.Context()))
		case <-ticker.C:
		}
	}
}

func waitForSelectedPath(t *testing.T, ctx context.Context, a *socket.RemoteStateActor, want socket.Addr) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if got, ok := a.SelectedPath(); ok && got.String() == want.String() {
			return
		}
		select {
		case <-ctx.Done():
			got, ok := a.SelectedPath()
			t.Fatalf("timed out waiting for selected path %s; last selected=%v ok=%v", want, got, ok)
		case <-ticker.C:
		}
	}
}

type endpointQNTFakeConn struct {
	addr       socket.Addr
	done       chan struct{}
	mu         sync.Mutex
	natAddrs   []netip.AddrPort
	removedNAT []netip.AddrPort
	currentNAT []netip.AddrPort
}

func (c *endpointQNTFakeConn) SmoothedRTT() time.Duration { return time.Millisecond }
func (c *endpointQNTFakeConn) Done() <-chan struct{}      { return c.done }
func (c *endpointQNTFakeConn) RemoteAddr() socket.Addr    { return c.addr }
func (c *endpointQNTFakeConn) MultipathNegotiated() bool  { return true }
func (c *endpointQNTFakeConn) AddNATTraversalAddress(addr netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.natAddrs = append(c.natAddrs, addr)
	c.currentNAT = appendUniqueNATTraversalCandidate(c.currentNAT, addr)
	return nil
}
func (c *endpointQNTFakeConn) RemoveNATTraversalAddress(addr netip.AddrPort) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removedNAT = append(c.removedNAT, addr)
	var next []netip.AddrPort
	for _, cur := range c.currentNAT {
		if cur != addr {
			next = append(next, cur)
		}
	}
	c.currentNAT = next
	return nil
}
func (c *endpointQNTFakeConn) currentNATTraversalCandidates() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]netip.AddrPort(nil), c.currentNAT...)
}

func TestEndpointRegisterConnSeedsQNTCandidatesOpportunistically(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const alpn = "iroh-qnt-handoff-test/0"
	server, err := Bind(ctx,
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	candidates := client.localNATTraversalCandidates()
	if len(candidates) == 0 {
		t.Fatal("client localNATTraversalCandidates = nil, want concrete loopback candidate")
	}

	accepted := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			accepted <- err
			return
		}
		accepted <- conn.CloseWithError(0, "")
	}()

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	if !conn.MultipathNegotiated() {
		t.Fatal("MultipathNegotiated = false, want true so registerConn attempts QNT handoff")
	}
	if err := conn.qc.AddNATTraversalAddress(candidates[0]); err != nil {
		t.Fatalf("AddNATTraversalAddress: %v", err)
	}

	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("Accept close: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// TestEndpointHomeRelayStatusNoRelay verifies that with relays disabled (the
// default), the home-relay watcher reports a nil status.
func TestEndpointHomeRelayStatusNoRelay(t *testing.T) {
	ctx := context.Background()
	ep, err := Bind(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ep.Shutdown(ctx)

	w := ep.HomeRelayStatus()
	if st := w.Current(); st != nil {
		t.Errorf("HomeRelayStatus().Current() = %v with relays disabled, want nil", st)
	}

	// Online returns ErrNoRelay immediately when relays are disabled.
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ep.Online(tctx); err != ErrNoRelay {
		t.Errorf("Online() = %v, want ErrNoRelay", err)
	}
}

func TestEndpointRemoteInfo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-remote-info/0"
	server, err := Bind(ctx,
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	accepted := make(chan *Conn, 1)
	go func() {
		conn, _ := server.Accept(ctx)
		accepted <- conn
	}()

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	defer (<-accepted).CloseWithError(0, "")

	info, ok := client.RemoteInfo(server.ID())
	if !ok {
		t.Fatal("RemoteInfo = false, want true")
	}
	if info.ID != server.ID() {
		t.Fatalf("RemoteInfo ID = %v, want %v", info.ID, server.ID())
	}
	if len(info.Addrs) == 0 {
		t.Fatal("RemoteInfo addrs empty")
	}
	var active bool
	for _, addr := range info.Addrs {
		if addr.Usage == TransportAddrActive {
			active = true
		}
	}
	if !active {
		t.Fatalf("RemoteInfo addrs = %+v, want an active address", info.Addrs)
	}

	unknown, _ := key.GenerateSecretKey()
	if _, ok := client.RemoteInfo(unknown.Public().EndpointID()); ok {
		t.Fatal("RemoteInfo unknown = true, want false")
	}
}

func TestEndpointRemoteInfoNil(t *testing.T) {
	var ep *Endpoint
	id, _ := key.GenerateSecretKey()
	if _, ok := ep.RemoteInfo(id.Public().EndpointID()); ok {
		t.Fatal("nil Endpoint RemoteInfo = true, want false")
	}
}

// countingSink is a WithQLOG sink that records what it was asked for and how
// often each writer was closed.
type countingSink struct {
	mu     sync.Mutex
	conns  []QLOGConnection
	closes map[string]int
	bufs   map[string]*bytes.Buffer
	nilFor func(QLOGConnection) bool
}

type countingSinkWriter struct {
	s  *countingSink
	id string
}

func (w countingSinkWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.s.bufs[w.id].Write(p)
}

func (w countingSinkWriter) Close() error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	w.s.closes[w.id]++
	return nil
}

func (s *countingSink) sink(_ context.Context, conn QLOGConnection) io.WriteCloser {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns = append(s.conns, conn)
	if s.nilFor != nil && s.nilFor(conn) {
		return nil
	}
	if s.bufs == nil {
		s.bufs = make(map[string]*bytes.Buffer)
		s.closes = make(map[string]int)
	}
	id := conn.ConnectionID
	s.bufs[id] = &bytes.Buffer{}
	return countingSinkWriter{s: s, id: id}
}

func (s *countingSink) snapshot() ([]QLOGConnection, map[string]int, map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sizes := make(map[string]int, len(s.bufs))
	for id, buf := range s.bufs {
		sizes[id] = buf.Len()
	}
	closes := make(map[string]int, len(s.closes))
	for id, n := range s.closes {
		closes[id] = n
	}
	return slices.Clone(s.conns), sizes, closes
}

// TestWithQLOGSink checks that a per-endpoint qlog sink receives that
// endpoint's traces and nobody else's, that its connection ids are hex, and
// that each writer is closed exactly once when the endpoint shuts down without
// closing the connection first.
func TestWithQLOGSink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-qlog-sink/0"
	serverSink := &countingSink{}
	server, err := Bind(ctx,
		WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithQLOG(serverSink.sink),
	)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(ctx)
		accepted <- err
	}()

	clientSink := &countingSink{}
	client, err := Bind(ctx,
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithQLOG(clientSink.sink),
	)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = conn

	clientConns, clientSizes, _ := clientSink.snapshot()
	if len(clientConns) != 1 {
		t.Fatalf("client sink called %d times, want 1", len(clientConns))
	}
	if !clientConns[0].Client {
		t.Error("client sink saw Client = false")
	}
	if _, err := hex.DecodeString(clientConns[0].ConnectionID); err != nil {
		t.Errorf("connection id %q is not hex: %v", clientConns[0].ConnectionID, err)
	}
	if n := clientSizes[clientConns[0].ConnectionID]; n == 0 {
		t.Error("client sink writer received no trace")
	}
	serverConns, _, _ := serverSink.snapshot()
	if len(serverConns) != 1 {
		t.Fatalf("server sink called %d times, want 1", len(serverConns))
	}
	if serverConns[0].Client {
		t.Error("server sink saw Client = true")
	}
	// Each endpoint's traces go to its own sink: the two sides of one
	// connection share an original destination connection id.
	if serverConns[0].ConnectionID != clientConns[0].ConnectionID {
		t.Errorf("server odcid %q, client odcid %q, want the same", serverConns[0].ConnectionID, clientConns[0].ConnectionID)
	}

	// Shut the endpoints down without closing the connection first.
	server.Shutdown(ctx)
	client.Shutdown(ctx)
	for _, s := range []*countingSink{clientSink, serverSink} {
		conns, _, _ := s.snapshot()
		id := conns[0].ConnectionID
		deadline := time.Now().Add(10 * time.Second)
		for {
			_, _, closes := s.snapshot()
			if closes[id] > 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("qlog writer for %s was never closed", id)
			}
			time.Sleep(10 * time.Millisecond)
		}
		// Once is once: give a second close time to arrive before asserting.
		time.Sleep(200 * time.Millisecond)
		if _, _, closes := s.snapshot(); closes[id] != 1 {
			t.Errorf("qlog writer for %s closed %d times, want exactly 1", id, closes[id])
		}
	}
}

// TestWithQLOGSinkNil checks that a sink returning nil traces nothing and does
// not break the connection.
func TestWithQLOGSinkNil(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-qlog-nil/0"
	sink := &countingSink{nilFor: func(QLOGConnection) bool { return true }}
	server, err := Bind(ctx, WithALPNs(alpn), WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)), WithQLOG(sink.sink))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(ctx)
		accepted <- err
	}()

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)), WithQLOG(sink.sink))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatalf("connect with a nil qlog sink: %v", err)
	}
	defer conn.CloseWithError(0, "")
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
	conns, sizes, closes := sink.snapshot()
	if len(conns) == 0 {
		t.Fatal("sink was never called")
	}
	if len(sizes) != 0 || len(closes) != 0 {
		t.Fatalf("a nil sink produced writers: sizes=%v closes=%v", sizes, closes)
	}
}

// TestQLOGDir checks that the QLOGDir sink writes the file layout its doc
// promises: <connection id>_<client|server>.sqlog under the given directory.
func TestQLOGDir(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-qlog-dir/0"
	serverDir, clientDir := t.TempDir(), t.TempDir()
	server, err := Bind(ctx, WithALPNs(alpn), WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)), WithQLOG(QLOGDir(serverDir)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	go server.Accept(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)), WithQLOG(QLOGDir(clientDir)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	for _, tc := range []struct{ dir, side string }{{clientDir, "client"}, {serverDir, "server"}} {
		names, err := filepath.Glob(filepath.Join(tc.dir, "*_"+tc.side+".sqlog"))
		if err != nil {
			t.Fatal(err)
		}
		if len(names) != 1 {
			t.Fatalf("%s traces = %v, want exactly one", tc.side, names)
		}
		stem := strings.TrimSuffix(filepath.Base(names[0]), "_"+tc.side+".sqlog")
		if _, err := hex.DecodeString(stem); err != nil {
			t.Errorf("trace name stem %q is not hex: %v", stem, err)
		}
	}
}
