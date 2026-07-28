package iroh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	itls "github.com/tmc/go-iroh/internal/itls/tls"
	"github.com/tmc/go-iroh/internal/netreport"
	"github.com/tmc/go-iroh/internal/portmapper"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/qng/qlog"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/watch"
)

// Endpoint is a bound iroh node: it owns a secret key, a UDP socket, and the
// QUIC transport used to dial and accept connections. Create one with [Bind].
//
// An Endpoint is safe for concurrent use. Close it with [Endpoint.Shutdown].
type Endpoint struct {
	secretKey key.SecretKey
	alpns     []string

	udp          *net.UDPConn
	sock         *socket.Socket
	magic        *socket.MagicConn
	relay        *socket.RelayTransport // nil when relays are disabled
	serveStop    context.CancelFunc
	transport    *quic.Transport
	listener     *quic.EarlyListener
	quicConf     *quic.Config
	keyLogWriter io.Writer
	sessionCache *SessionCache
	disableIP    bool
	relayFirst   bool
	verifySource func(net.Addr) bool
	hooks        []EndpointHooks
	custom       []CustomTransport

	// remotes is the per-remote state registry. The endpoint owns it: it
	// registers every established connection so the actor for that remote can
	// track paths and select between them. The actor never holds a reference
	// back to the endpoint, so there is no import cycle.
	remotes *socket.RemoteMap
	lookup  *AddressLookupServices

	mu          sync.Mutex
	closed      bool
	closedCh    chan struct{}
	acceptOwner acceptOwner
	addrWatch   *watch.Value[netaddr.EndpointAddr]
	// externalPinned holds addresses pinned via AddExternalAddr until
	// RemoveExternalAddr. externalDiscovered holds the latest net report's
	// reflexive addresses, replaced wholesale per report. Kept apart so a
	// report cannot drop pinned candidates, nor pinning keep stale ones.
	externalPinned     []netip.AddrPort
	externalDiscovered []netip.AddrPort
	netReport          netReportRunner
	lastReport         *NetReport
	nextStable         uint64
	stableIDs          map[*quic.Conn]uint64
	metrics            endpointMetrics
}

type acceptOwner int

const (
	acceptOwnerNone acceptOwner = iota
	acceptOwnerAccept
	acceptOwnerListenStreams
	acceptOwnerRouter
)

// config holds the options assembled by [Option] values before [Bind].
type config struct {
	secretKey       key.SecretKey
	haveKey         bool
	alpns           []string
	bindAddr        netip.AddrPort
	bindOpts        BindOpts
	haveBindAddr    bool
	disableIP       bool
	relayMode       relay.Mode
	lookup          *AddressLookupServices
	enableNetReport bool
	netReport       netReportRunner
	netReportEvery  time.Duration
	natPMP          bool
	natPMPGateway   netip.Addr
	natPMPPort      uint16
	keyLogWriter    io.Writer
	transportConfig *QUICTransportConfig
	pathSelector    socket.PathSelector
	relayFirst      bool
	verifySource    func(net.Addr) bool
	hooks           []EndpointHooks
	custom          []CustomTransport
}

// Option configures an [Endpoint] at [Bind] time.
type Option func(*config) error

type netReportRunner func(context.Context) (*netreport.Report, error)

// BindOpts configures how a bound IP socket participates in route selection.
//
// PrefixLen is the network prefix length matched by this socket. IsRequired
// keeps parity with Rust's bind options: a required bind fails the endpoint when
// the socket cannot be opened, which is also the behavior of this single-socket
// Go build. IsDefaultRoute marks the socket as a default route when non-nil.
//
// The zero value is usable and means "host route, required, default inferred".
type BindOpts struct {
	PrefixLen      uint8
	IsRequired     bool
	IsDefaultRoute *bool
}

// QUICTransportConfig configures stable QUIC transport settings used by
// endpoints. A zero field keeps the default.
type QUICTransportConfig struct {
	KeepAlivePeriod time.Duration
	MaxIdleTimeout  time.Duration
}

// WithSecretKey sets the endpoint's identity. If unset, [Bind] generates a
// random key.
func WithSecretKey(sk key.SecretKey) Option {
	return func(c *config) error {
		c.secretKey = sk
		c.haveKey = true
		return nil
	}
}

// WithALPNs sets the ALPN protocols this endpoint accepts on incoming
// connections. ALPN is Application-Layer Protocol Negotiation, the TLS
// extension QUIC uses to agree on the application protocol carried by a
// connection.
//
// Each ALPN is an arbitrary byte string represented as a Go string, matching
// crypto/tls and quic-go. Printable ASCII such as "example/1" is common, but
// strings may contain arbitrary bytes.
func WithALPNs(alpns ...string) Option {
	return func(c *config) error {
		c.alpns = append(c.alpns, alpns...)
		return nil
	}
}

// WithSourceAddressValidation sets the QUIC Retry policy for unvalidated
// incoming source addresses. The function receives the unvalidated remote
// address and returns true when qng should send a Retry packet before allowing
// the connection through to AcceptIncoming.
func WithSourceAddressValidation(f func(net.Addr) bool) Option {
	return func(c *config) error {
		c.verifySource = f
		return nil
	}
}

// WithBindAddr sets the local UDP address to bind. The default is an
// OS-assigned port on the unspecified address.
func WithBindAddr(addr netip.AddrPort) Option {
	return func(c *config) error {
		c.bindAddr = addr
		c.bindOpts = BindOpts{}
		c.haveBindAddr = true
		return nil
	}
}

// WithBindAddrOpts sets the local UDP address to bind with route-selection
// metadata. PrefixLen must fit the address family: at most 32 for IPv4 and at
// most 128 for IPv6.
func WithBindAddrOpts(addr netip.AddrPort, opts BindOpts) Option {
	return func(c *config) error {
		if err := validateBindOpts(addr, opts); err != nil {
			return err
		}
		c.bindAddr = addr
		c.bindOpts = opts
		c.haveBindAddr = true
		return nil
	}
}

func validateBindOpts(addr netip.AddrPort, opts BindOpts) error {
	if !addr.IsValid() {
		return errors.New("iroh: invalid bind address")
	}
	if addr.Addr().Is4() {
		if opts.PrefixLen > 32 {
			return fmt.Errorf("iroh: invalid IPv4 bind prefix length %d", opts.PrefixLen)
		}
		return nil
	}
	if opts.PrefixLen > 128 {
		return fmt.Errorf("iroh: invalid IPv6 bind prefix length %d", opts.PrefixLen)
	}
	return nil
}

// WithoutIPTransports prevents the endpoint from binding, advertising, or
// dialing direct IP addresses. Relay and custom transports still use the magic
// connection machinery.
func WithoutIPTransports() Option {
	return func(c *config) error {
		c.disableIP = true
		return nil
	}
}

// WithoutRelayTransports disables relay connectivity.
func WithoutRelayTransports() Option {
	return func(c *config) error {
		c.relayMode = relay.ModeDisabled()
		return nil
	}
}

// WithRelayFirstDial makes Connect try relay addresses before direct IP
// addresses when both are present. Direct IP addresses are still registered as
// QNT candidates after the handshake, so a connection can establish through a
// relay and then migrate ordinary traffic to a validated direct path.
func WithRelayFirstDial() Option {
	return func(c *config) error {
		c.relayFirst = true
		return nil
	}
}

// WithAddressLookup sets the address-lookup services the endpoint uses to
// resolve additional addresses for a remote endpoint (pkarr, DNS, in-memory).
// The per-remote state machine consults them through its resolve hook. When
// unset, the endpoint does no lookup-driven address resolution and connects only
// to the addresses passed to [Endpoint.Connect].
func WithAddressLookup(s *AddressLookupServices) Option {
	return func(c *config) error {
		c.lookup = s
		return nil
	}
}

// WithDNSResolver configures DNS endpoint discovery through the number0
// production origin. It is a convenience wrapper around [WithAddressLookup].
func WithDNSResolver(r *dns.Resolver) Option {
	return func(c *config) error {
		if c.lookup == nil {
			c.lookup = &AddressLookupServices{}
		}
		c.lookup.AddResolver(NewDNSAddressLookup(dns.N0DNSEndpointOriginProd, r))
		return nil
	}
}

// WithRelayMode selects which relay servers the endpoint uses. The default is
// [relay.ModeDisabled] (no relays), matching this build's direct-only default.
// Pass [relay.ModeDefault], [relay.ModeStaging], or [relay.ModeCustom] to enable
// relay connectivity.
func WithRelayMode(mode relay.Mode) Option {
	return func(c *config) error {
		c.relayMode = mode
		return nil
	}
}

// WithNetReport enables background net_report refreshes after [Bind]. When
// relays are configured, the report's QAD-derived global addresses are
// advertised as local QNT candidates for active remotes.
func WithNetReport() Option {
	return func(c *config) error {
		c.enableNetReport = true
		return nil
	}
}

// WithNATPMP enables NAT-PMP UDP port mapping through gateway.
//
// NAT-PMP does not define a portable default-gateway discovery mechanism; pass
// the IPv4 address of the gateway that should receive NAT-PMP requests.
func WithNATPMP(gateway netip.Addr) Option {
	return func(c *config) error {
		if !gateway.IsValid() || !gateway.Is4() {
			return errors.New("iroh: invalid nat-pmp gateway")
		}
		c.natPMP = true
		c.natPMPGateway = gateway
		return nil
	}
}

func withNATPMPPort(port uint16) Option {
	return func(c *config) error {
		c.natPMPPort = port
		return nil
	}
}

// WithKeyLogWriter writes TLS traffic secrets for direct peer QUIC handshakes
// in NSS SSLKEYLOGFILE format. It is for debugging only; writing these secrets
// compromises connection confidentiality.
func WithKeyLogWriter(w io.Writer) Option {
	return func(c *config) error {
		c.keyLogWriter = w
		return nil
	}
}

// WithHooks registers endpoint hooks. Hooks run in registration order and may
// reject outgoing dials or completed handshakes.
func WithHooks(h EndpointHooks) Option {
	return func(c *config) error {
		if h != nil {
			c.hooks = append(c.hooks, h)
		}
		return nil
	}
}

// WithTransportConfig overrides stable QUIC transport settings. Unsupported
// qng internals remain private to the endpoint.
func WithTransportConfig(tc *QUICTransportConfig) Option {
	return func(c *config) error {
		c.transportConfig = tc
		return nil
	}
}

// WithPathSelector sets the policy used to choose among candidate network paths
// to a remote endpoint. When unset, the endpoint uses [BiasedRttPathSelector].
func WithPathSelector(selector PathSelector) Option {
	return func(c *config) error {
		if selector != nil {
			c.pathSelector = pathSelectorAdapter{selector: selector}
		}
		return nil
	}
}

// WithCustomTransport adds a custom transport backend to the magic socket.
// Custom transports own their wire format and exchange datagrams using
// [netaddr.CustomAddr] values advertised in endpoint addresses.
func WithCustomTransport(t CustomTransport) Option {
	return func(c *config) error {
		if t != nil {
			c.custom = append(c.custom, t)
		}
		return nil
	}
}

// Bind binds a UDP socket and returns a ready [Endpoint].
//
// By default the endpoint enables qng datagrams and advertises the iroh
// multipath path limit. Direct UDP works without relays; relay transport,
// address discovery, and QNT hole-punching are separate connectivity features.
func Bind(ctx context.Context, opts ...Option) (*Endpoint, error) {
	var c config
	for _, opt := range opts {
		if err := opt(&c); err != nil {
			return nil, err
		}
	}
	if c.netReportEvery == 0 {
		c.netReportEvery = 5 * time.Minute
	}
	if !c.haveKey {
		sk, err := key.GenerateSecretKey()
		if err != nil {
			return nil, fmt.Errorf("iroh: generate key: %w", err)
		}
		c.secretKey = sk
	}

	bind := c.bindAddr
	if !c.haveBindAddr {
		bind = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
	}
	udp, err := bindPacketConn(c, bind)
	if err != nil {
		return nil, fmt.Errorf("iroh: bind udp: %w", err)
	}

	quicConf := &quic.Config{
		KeepAlivePeriod:                HeartbeatInterval,
		MaxIdleTimeout:                 RelayPathMaxIdleTimeout,
		EnableDatagrams:                true,
		InitialMaxPathID:               initialMaxPathID(),
		MaxRemoteNATTraversalAddresses: maxRemoteNATTraversalAddresses(),
		Tracer:                         qlog.DefaultConnectionTracer,
		// Accept 0-RTT early data on incoming connections that resume a prior
		// session. Allow0RTT is ignored for dialed connections, so sharing this
		// config with Connect is safe. Mirrors the Rust server enabling early
		// data with max_early_data_size = u32::MAX (iroh/src/tls.rs:118).
		Allow0RTT: true,
		// Remember the server's NEW_TOKEN frames so a resuming dial can present a
		// validation token. Without it the server cannot validate the client's
		// address ahead of the handshake and rejects 0-RTT. Tokens are keyed by
		// the TLS server name (ServerName(id)), the same per-peer bucketing the
		// session cache uses. The capacity matches maxTLSTickets.
		TokenStore: quic.NewLRUTokenStore(32, 8),
	}
	if c.transportConfig != nil {
		if c.transportConfig.KeepAlivePeriod != 0 {
			quicConf.KeepAlivePeriod = c.transportConfig.KeepAlivePeriod
		}
		if c.transportConfig.MaxIdleTimeout != 0 {
			quicConf.MaxIdleTimeout = c.transportConfig.MaxIdleTimeout
		}
	}
	// The QUIC transport is driven over the magic socket rather than the raw
	// UDP socket: a single net.PacketConn that multiplexes every iroh path. The
	// magic socket always carries the direct-IP transport and, when relays are
	// configured, a relay transport.
	sock := socket.NewSocket()

	var relayActor *socket.RelayActor
	relayMap := c.relayMode.Map()
	if !relayMap.IsEmpty() {
		relayActor = socket.NewRelayActor(socket.RelayActorConfig{
			SecretKey: c.secretKey,
			Map:       relayMap,
		})
	}

	custom := customTransportAdapters(c.custom)
	var magic *socket.MagicConn
	if udp == nil {
		magic = socket.NewMagicConnRelayOnly(sock, relayActor, custom...)
	} else {
		magic = socket.NewMagicConnWithTransports(sock, udp, relayActor, custom...)
	}
	serveCtx, serveStop := context.WithCancel(context.Background())
	go magic.Serve(serveCtx)

	ep := &Endpoint{
		secretKey: c.secretKey,
		alpns:     slices.Clone(c.alpns),
		udp:       udp,
		sock:      sock,
		magic:     magic,
		relay:     magic.Relay(),
		serveStop: serveStop,
		transport: &quic.Transport{
			Conn:                magic,
			ConnectionIDLength:  8,
			VerifySourceAddress: c.verifySource,
		},
		quicConf:     quicConf,
		keyLogWriter: c.keyLogWriter,
		sessionCache: NewSessionCache(),
		// A nil udp means there is no IP transport (relay-only bind, or the js
		// build where bindPacketConn never returns a socket), so IP addresses
		// must not be advertised regardless of the requested disableIP.
		disableIP:    c.disableIP || udp == nil,
		relayFirst:   c.relayFirst,
		verifySource: c.verifySource,
		hooks:        append([]EndpointHooks(nil), c.hooks...),
		custom:       append([]CustomTransport(nil), c.custom...),
		lookup:       c.lookup,
		closedCh:     make(chan struct{}),
		stableIDs:    make(map[*quic.Conn]uint64),
	}
	// Assigned after the literal: the runner needs ep.transport so QAD
	// probes ride the endpoint's own socket (see qadDialer).
	ep.netReport = endpointNetReportRunner(c, relayMap, ep.qadDialer())
	// The per-remote state registry shares the serve context: its actors stop
	// when the endpoint's recv loop stops. Its resolve hook is backed by the
	// endpoint's address-lookup services (slice G), passed down as a func value
	// so internal/socket does not import iroh.
	ep.remotes = socket.NewRemoteMapWithMetrics(serveCtx, c.pathSelector, ep.resolveFunc(), magic.MetricsSet())
	ep.magic.SetEndpointSender(func(id key.EndpointID, p []byte) bool {
		err := ep.remotes.Actor(id).SendDatagram(p, func(addr socket.Addr, data []byte) bool {
			return ep.magic.SendAddr(addr, data)
		})
		return err == nil
	})

	// Select an initial home relay so relay connectivity starts before the first
	// net_report finishes. applyNetReport switches to net_report's preferred
	// relay once latency data is available.
	if ep.relay != nil {
		if urls := relayMap.URLs(); len(urls) > 0 {
			ep.relay.SetHomeRelay(urls[0])
		}
	}

	if len(c.alpns) > 0 {
		if err := ep.startListener(); err != nil {
			serveStop()
			if udp != nil {
				udp.Close()
			}
			return nil, err
		}
	}
	ep.addrWatch = watch.NewValueFunc(ep.Addr(), endpointAddrEqual)
	if ep.netReport != nil {
		go ep.runNetReport(serveCtx, c.netReportEvery)
	}
	if c.natPMP {
		go ep.runNATPMP(serveCtx, c.natPMPGateway, c.natPMPPort)
	}
	return ep, nil
}

func (e *Endpoint) setSourceAddressValidation(f func(net.Addr) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.verifySource = f
	e.transport.VerifySourceAddress = f
}

func (e *Endpoint) sourceAddressValidation() func(net.Addr) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.verifySource
}

func endpointNetReportRunner(c config, relayMap *relay.Map, dialer netreport.QADDialer) netReportRunner {
	if c.netReport != nil {
		return c.netReport
	}
	if !c.enableNetReport || relayMap.IsEmpty() {
		return nil
	}
	client := netreport.NewClient(relayMap)
	if dialer != nil {
		client = client.WithQADDialer(dialer)
	}
	return func(ctx context.Context) (*netreport.Report, error) {
		return client.GetReport(ctx, netreport.IfStateDetails{HaveV4: true, HaveV6: true}, false)
	}
}

// qadDialer returns the dialer net_report uses for QAD probes. Dials on the
// endpoint's own transport share its UDP socket, so the address a relay
// observes is the endpoint's real public mapping — a usable dial and
// hole-punch candidate. Nil when there is no IP transport; net_report then
// falls back to a private per-probe socket.
func (e *Endpoint) qadDialer() netreport.QADDialer {
	if e.udp == nil {
		return nil
	}
	return func(ctx context.Context, addr netip.AddrPort, tlsConf *itls.Config, cfg *quic.Config) (*quic.Conn, error) {
		return e.transport.Dial(ctx, net.UDPAddrFromAddrPort(addr), tlsConf, cfg)
	}
}

func initialMaxPathID() *uint32 {
	v := uint32(MaxMultipathPaths)
	return &v
}

func maxRemoteNATTraversalAddresses() *uint8 {
	v := uint8(MaxQNTAddresses)
	return &v
}

// startListener begins accepting incoming connections with the current ALPNs.
// It uses an early listener so the QUIC stack can accept 0-RTT early data from
// peers that resume a prior session.
func (e *Endpoint) startListener() error {
	serverTLS, err := serverTLSConfig(e.secretKey, e.alpns)
	if err != nil {
		return err
	}
	serverTLS.KeyLogWriter = e.keyLogWriter
	ln, err := e.transport.ListenEarly(serverTLS, e.quicConf)
	if err != nil {
		return fmt.Errorf("iroh: listen: %w", err)
	}
	e.listener = ln
	return nil
}

// SetALPNs sets the ALPN protocols the endpoint accepts and begins (or
// continues) listening for incoming connections. It is the Go analog of the Rust
// Endpoint::set_alpns (iroh/src/endpoint.rs), used by [Router.Spawn] to register
// every protocol's ALPN at once.
//
// SetALPNs replaces the accepted ALPN set. If a listener is already running, it
// is closed first; established connections are unaffected. SetALPNs returns an
// error while an accept loop owner such as [Endpoint.Accept], [Endpoint.AcceptIncoming],
// [Endpoint.ListenStreams], or [Router] is active. Pass each ALPN as an arbitrary
// byte string represented as a Go string; see [WithALPNs].
func (e *Endpoint) SetALPNs(alpns []string) error {
	return e.setALPNs(alpns, acceptOwnerNone)
}

func (e *Endpoint) setALPNs(alpns []string, allowedOwner acceptOwner) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEndpointClosed
	}
	if e.acceptOwner != acceptOwnerNone && e.acceptOwner != allowedOwner {
		return ErrEndpointAcceptLoopInUse
	}
	next := slices.Clone(alpns)
	if e.listener != nil {
		if err := e.listener.Close(); err != nil {
			return fmt.Errorf("iroh: close listener: %w", err)
		}
		e.listener = nil
	}
	prev := e.alpns
	e.alpns = next
	if err := e.startListener(); err != nil {
		e.alpns = prev
		return err
	}
	return nil
}

// ID returns the endpoint's network identifier.
func (e *Endpoint) ID() key.EndpointID { return e.secretKey.Public().EndpointID() }

// SecretKey returns the endpoint's secret key.
func (e *Endpoint) SecretKey() key.SecretKey { return e.secretKey }

// LocalAddr returns the bound UDP address.
func (e *Endpoint) LocalAddr() netip.AddrPort {
	if e.udp == nil {
		return netip.AddrPort{}
	}
	return e.udp.LocalAddr().(*net.UDPAddr).AddrPort()
}

// externalNATLocked returns the pinned and net-report-discovered external
// candidates, pinned first, deduplicated. e.mu must be held.
func (e *Endpoint) externalNATLocked() []netip.AddrPort {
	out := append([]netip.AddrPort(nil), e.externalPinned...)
	for _, addr := range e.externalDiscovered {
		out = appendUniqueNATTraversalCandidate(out, addr)
	}
	return out
}

// localNATTraversalCandidates returns concrete local direct addresses this
// endpoint can hand to qng's QNT state. The default bind address is unspecified
// ([::]:port), which is not a usable candidate and must not be advertised.
// QAD-derived external addresses are appended after the same canonicalization
// and validity checks.
func (e *Endpoint) localNATTraversalCandidates() []netip.AddrPort {
	var addrs []netip.AddrPort
	if e.disableIP {
		return addrs
	}
	if addr, ok := canonicalNATTraversalCandidate(e.LocalAddr()); ok {
		addrs = appendUniqueNATTraversalCandidate(addrs, addr)
	}
	e.mu.Lock()
	external := e.externalNATLocked()
	e.mu.Unlock()
	for _, addr := range external {
		addrs = appendUniqueNATTraversalCandidate(addrs, addr)
	}
	return addrs
}

// setExternalNATTraversalCandidates replaces the discovered external
// candidate set: net reports are authoritative, and replacement retires
// mappings the NAT rebound. Pinned addresses are a separate set.
func (e *Endpoint) setExternalNATTraversalCandidates(addrs ...netip.AddrPort) bool {
	var next []netip.AddrPort
	for _, addr := range addrs {
		next = appendUniqueNATTraversalCandidate(next, addr)
	}

	e.mu.Lock()
	if equalAddrPorts(e.externalDiscovered, next) {
		e.mu.Unlock()
		return false
	}
	e.externalDiscovered = next
	e.updateAddrWatchLocked()
	e.mu.Unlock()

	e.advertiseNATTraversalCandidates()
	return true
}

// AddExternalAddr pins addr as an externally reachable address and advertises
// it as a QNT NAT traversal candidate until RemoveExternalAddr; net reports
// never drop it. Invalid, unspecified, or zero-port addresses are ignored.
func (e *Endpoint) AddExternalAddr(addr netip.AddrPort) {
	if e.disableIP {
		return
	}
	e.mu.Lock()
	next := appendUniqueNATTraversalCandidate(append([]netip.AddrPort(nil), e.externalPinned...), addr)
	if equalAddrPorts(e.externalPinned, next) {
		e.mu.Unlock()
		return
	}
	e.externalPinned = next
	e.updateAddrWatchLocked()
	e.mu.Unlock()
	e.advertiseNATTraversalCandidates()
}

// RemoveExternalAddr removes addr from the endpoint's externally reachable
// addresses and stops advertising it as a QNT NAT traversal candidate. It
// returns true if addr was present. Invalid, unspecified, or zero-port addresses
// are ignored.
func (e *Endpoint) RemoveExternalAddr(addr netip.AddrPort) bool {
	if e.disableIP {
		return false
	}
	addr, ok := canonicalNATTraversalCandidate(addr)
	if !ok {
		return false
	}

	e.mu.Lock()
	i := slices.Index(e.externalPinned, addr)
	if i < 0 {
		e.mu.Unlock()
		return false
	}
	e.externalPinned = slices.Delete(e.externalPinned, i, i+1)
	e.updateAddrWatchLocked()
	e.mu.Unlock()
	e.advertiseNATTraversalCandidates()
	return true
}

func (e *Endpoint) applyNetReport(report netreport.Report) bool {
	publicReport := netReportFromInternal(report)
	e.mu.Lock()
	e.lastReport = &publicReport
	e.mu.Unlock()

	changed := e.setExternalNATTraversalCandidates(report.GlobalV4, report.GlobalV6)
	if e.relay != nil && !report.PreferredRelay.IsZero() {
		current := e.relay.HomeRelayStatus().Current()
		if current == nil || !current.URL.Equal(report.PreferredRelay) {
			e.relay.SetHomeRelay(report.PreferredRelay)
			if e.magic != nil {
				e.magic.RecordRelayHomeChange()
			}
			e.mu.Lock()
			e.updateAddrWatchLocked()
			e.mu.Unlock()
			changed = true
		}
	}
	return changed
}

// NetReport returns the most recent network report applied to the endpoint.
// The boolean result is false when no report has completed yet.
func (e *Endpoint) NetReport() (NetReport, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.lastReport == nil {
		return NetReport{}, false
	}
	return e.lastReport.clone(), true
}

// RemoteInfo returns a snapshot of known addressing information for remote.
// It returns false if the endpoint has no recent state for remote.
func (e *Endpoint) RemoteInfo(remote key.EndpointID) (RemoteInfo, bool) {
	if e == nil || e.remotes == nil {
		return RemoteInfo{}, false
	}
	info, ok := e.remotes.RemoteInfo(remote)
	if !ok {
		return RemoteInfo{}, false
	}
	return remoteInfoFromSocket(info), true
}

func (e *Endpoint) refreshNetReport(ctx context.Context) error {
	if e.netReport == nil {
		return nil
	}
	report, err := e.netReport(ctx)
	if report != nil {
		e.metrics.netReportReports.Add(1)
		if report.Full {
			e.metrics.netReportReportsFull.Add(1)
			e.metrics.netReportPortmapAttempts.Add(1)
		}
		if e.applyNetReport(*report) {
			e.metrics.netReportPortmapExternalAddressUpdated.Add(1)
		}
	}
	if err != nil {
		e.metrics.netReportFailed.Add(1)
		return fmt.Errorf("iroh: netreport: %w", err)
	}
	return nil
}

func (e *Endpoint) runNetReport(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	_ = e.refreshNetReport(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = e.refreshNetReport(ctx)
		}
	}
}

func (e *Endpoint) runNATPMP(ctx context.Context, gateway netip.Addr, port uint16) {
	if e.disableIP {
		return
	}
	local := e.LocalAddr()
	if !local.IsValid() || local.Port() == 0 {
		return
	}
	client := portmapper.NATPMPClient{
		Gateway: gateway,
		Port:    port,
		Timeout: 2 * time.Second,
	}
	const requestedLifetime = time.Hour
	internalPort := local.Port()
	var current netip.AddrPort
	defer func() {
		if current.IsValid() {
			e.RemoveExternalAddr(current)
			deleteCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _ = client.MapUDP(deleteCtx, internalPort, current.Port(), 0)
		}
	}()

	for {
		mapping, err := client.MapUDP(ctx, internalPort, internalPort, requestedLifetime)
		if err == nil && mapping.ExternalAddr.IsValid() {
			if current.IsValid() && current != mapping.ExternalAddr {
				e.RemoveExternalAddr(current)
			}
			current = mapping.ExternalAddr
			e.AddExternalAddr(current)
			e.metrics.netReportPortmapAttempts.Add(1)
			e.metrics.netReportPortmapExternalAddressUpdated.Add(1)
		} else if err != nil {
			e.metrics.netReportFailed.Add(1)
		}
		wait := requestedLifetime / 2
		if err == nil && mapping.Lifetime > 0 {
			wait = mapping.Lifetime / 2
		}
		if wait < 30*time.Second {
			wait = 30 * time.Second
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (e *Endpoint) advertiseNATTraversalCandidates() {
	if e.remotes == nil {
		return
	}
	candidates := e.localNATTraversalCandidates()
	e.remotes.AddNATTraversalAddresses(candidates)
}

func canonicalNATTraversalCandidate(addr netip.AddrPort) (netip.AddrPort, bool) {
	if !addr.IsValid() || addr.Port() == 0 || addr.Addr().IsUnspecified() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), true
}

func appendUniqueNATTraversalCandidate(addrs []netip.AddrPort, addr netip.AddrPort) []netip.AddrPort {
	addr, ok := canonicalNATTraversalCandidate(addr)
	if !ok {
		return addrs
	}
	for _, a := range addrs {
		if a == addr {
			return addrs
		}
	}
	return append(addrs, addr)
}

func equalAddrPorts(a, b []netip.AddrPort) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Addr returns the endpoint's [netaddr.EndpointAddr] from currently-known local
// information: its id, the bound direct address, any custom transport
// addresses, and (when relays are enabled and a home relay is connected) its
// home relay URL. Later slices add reflexive addresses.
func (e *Endpoint) Addr() netaddr.EndpointAddr {
	a := netaddr.NewEndpointAddr(e.ID())
	if !e.disableIP {
		a = a.WithIP(e.LocalAddr())
	}
	e.mu.Lock()
	external := e.externalNATLocked()
	e.mu.Unlock()
	if !e.disableIP {
		for _, addr := range external {
			a = a.WithIP(addr)
		}
	}
	for _, addr := range e.localCustomAddrs(context.Background()) {
		a = a.WithAddrs(addr)
	}
	if e.relay != nil {
		if st := e.relay.HomeRelayStatus().Current(); st != nil {
			a = a.WithRelayURL(st.URL)
		}
	}
	return a
}

// WatchAddr returns a watcher over the endpoint's current advertised address.
// It updates when local external NAT candidates are added or replaced.
func (e *Endpoint) WatchAddr() watch.Observer[netaddr.EndpointAddr] {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.addrWatch == nil {
		e.addrWatch = watch.NewValueFunc(e.addrLocked(), endpointAddrEqual)
	}
	return e.addrWatch.Watch()
}

func (e *Endpoint) updateAddrWatchLocked() {
	if e.addrWatch != nil {
		e.addrWatch.Set(e.addrLocked())
	}
}

func endpointAddrEqual(a, b netaddr.EndpointAddr) bool {
	return a.ID.Equal(b.ID) && equalTransportAddrs(a.Addrs(), b.Addrs())
}

func (e *Endpoint) addrLocked() netaddr.EndpointAddr {
	a := netaddr.NewEndpointAddr(e.ID())
	if !e.disableIP {
		a = a.WithIP(e.LocalAddr())
		for _, addr := range e.externalNATLocked() {
			a = a.WithIP(addr)
		}
	}
	for _, addr := range e.localCustomAddrs(context.Background()) {
		a = a.WithAddrs(addr)
	}
	if e.relay != nil {
		if st := e.relay.HomeRelayStatus().Current(); st != nil {
			a = a.WithRelayURL(st.URL)
		}
	}
	return a
}

func (e *Endpoint) localCustomAddrs(ctx context.Context) []netaddr.CustomAddr {
	return customTransportLocalAddrs(ctx, e.custom)
}

func equalTransportAddrs(a, b []netaddr.TransportAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Compare(b[i]) != 0 {
			return false
		}
	}
	return true
}

// RelayStatus is the connection status of the endpoint's home relay, observed
// through [Endpoint.HomeRelayStatus].
type RelayStatus = socket.RelayStatus

// RelayConfig configures a relay server used by an endpoint.
type RelayConfig = relay.Config

// HomeRelayStatus returns a watcher over the endpoint's home relay connection
// status. The watched value is nil until a home relay is selected; it updates
// whenever the home relay or its connection state changes. When relays are
// disabled the watcher always reports nil.
//
// It is the Go analog of the Rust Endpoint::home_relay_status
// (iroh/src/endpoint.rs:1324).
func (e *Endpoint) HomeRelayStatus() watch.Observer[*RelayStatus] {
	if e.relay == nil {
		return watch.NewValue[*RelayStatus](nil).Watch()
	}
	return e.relay.HomeRelayStatus()
}

// Online blocks until the endpoint has a connected home relay, or until ctx is
// done. It returns nil once connected, or ctx.Err() if the context ends first.
// When relays are disabled it returns [ErrNoRelay] immediately.
//
// It is the Go analog of the Rust Endpoint::online (iroh/src/endpoint.rs:1295).
func (e *Endpoint) Online(ctx context.Context) error {
	if e.relay == nil {
		return ErrNoRelay
	}
	w := e.relay.HomeRelayStatus()
	for {
		if st := w.Current(); st != nil && st.IsConnected() {
			return nil
		}
		if _, err := w.Updated(ctx); err != nil {
			return err
		}
	}
}

// ErrNoRelay is returned by [Endpoint.Online] when the endpoint has no relays
// configured (relays disabled), so it can never come online via a relay.
var ErrNoRelay = errors.New("iroh: no relays configured")

// InsertRelay adds or replaces a relay server configuration. It returns the
// previous config for url when one existed.
func (e *Endpoint) InsertRelay(url netaddr.RelayURL, cfg *RelayConfig) (*RelayConfig, error) {
	if e.isClosed() {
		return nil, ErrEndpointClosed
	}
	if e.relay == nil {
		return nil, ErrNoRelay
	}
	next := RelayConfig{URL: url}
	if cfg != nil {
		next = *cfg
		next.URL = url
	}
	prev, ok := e.relay.InsertRelay(url, next)
	e.mu.Lock()
	e.updateAddrWatchLocked()
	e.mu.Unlock()
	if !ok {
		return nil, nil
	}
	return &prev, nil
}

// RemoveRelay removes a relay server configuration. It returns the removed
// config, or nil if url was not configured.
func (e *Endpoint) RemoveRelay(url netaddr.RelayURL) *RelayConfig {
	if e.isClosed() || e.relay == nil {
		return nil
	}
	prev, ok := e.relay.RemoveRelay(url)
	e.mu.Lock()
	e.updateAddrWatchLocked()
	e.mu.Unlock()
	if !ok {
		return nil
	}
	return &prev
}

// ErrEndpointClosed is returned by operations on a closed [Endpoint].
var ErrEndpointClosed = errors.New("iroh: endpoint closed")

// ErrEndpointAcceptLoopInUse is returned when an operation would start or
// reconfigure an endpoint accept loop while another accept owner is active.
var ErrEndpointAcceptLoopInUse = errors.New("iroh: endpoint accept loop in use")

// ErrSelfConnect is returned by [Endpoint.Connect] when asked to dial the
// endpoint's own id.
var ErrSelfConnect = errors.New("iroh: cannot connect to self")

// ErrNoAddress is returned when an [netaddr.EndpointAddr] has no usable address:
// no direct IP and no relay URL (or relays are disabled on this endpoint).
var ErrNoAddress = errors.New("iroh: no reachable address for endpoint")

// ErrConnectRejected is returned when an endpoint hook rejects a dial before
// any packet is sent.
var ErrConnectRejected = errors.New("iroh: connect rejected by hook")

// ErrHandshakeRejected is returned when an endpoint hook rejects a completed
// handshake.
var ErrHandshakeRejected = errors.New("iroh: handshake rejected by hook")

// ErrConnClosedDuringHandshake is returned when an incoming connection attempt
// dies before completing its handshake (for example, a handshake timeout).
// [Endpoint.Accept] skips such attempts and keeps accepting.
var ErrConnClosedDuringHandshake = errors.New("iroh: connection closed during handshake")

// Connect dials the endpoint identified by addr and negotiates alpn, returning
// an established [Conn]. It tries the direct IP addresses in addr in order, then
// (if relays are enabled) the relay URLs in addr. A relay path carries the QUIC
// handshake over a relay mapped address that routes through the relay transport.
//
// Connect blocks until the handshake completes and the peer identity is
// verified. To send 0-RTT early data before the handshake completes, use
// [Endpoint.ConnectEarly] and [Connecting.Into0RTT].
func (e *Endpoint) Connect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (*Conn, error) {
	e.metrics.connectsStarted.Add(1)
	ok := false
	defer func() {
		if !ok {
			e.metrics.connectsFailed.Add(1)
		}
	}()
	// Bound the whole connect, including the handshake hooks run by Connection,
	// by ConnectTimeout. connectEarly sees this deadline and does not re-wrap.
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
	}
	c, err := e.connectEarly(ctx, addr, alpn)
	if err != nil {
		return nil, err
	}
	conn, err := c.Connection(ctx)
	if err != nil {
		return nil, err
	}
	e.metrics.connectsAccepted.Add(1)
	ok = true
	return conn, nil
}

// ConnectEarly begins dialing the endpoint identified by addr for alpn and
// returns immediately with a [Connecting] handle, without waiting for the
// handshake. It tries the same dial targets as [Endpoint.Connect].
//
// Await [Connecting.Connection] for the verified [Conn] (the same result
// [Endpoint.Connect] returns), or call [Connecting.Into0RTT] to send 0-RTT early
// data before the handshake completes when a resumable session is cached.
func (e *Endpoint) ConnectEarly(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (*Connecting, error) {
	return e.connectEarly(ctx, addr, alpn)
}

// connectEarly performs the shared dial setup for Connect and ConnectEarly: it
// validates the endpoint, runs the BeforeConnect hooks, resolves dial targets,
// builds the client TLS config, and dials with 0-RTT enabled. It returns a
// Connecting holding the early QUIC connection, before afterHandshake runs.
//
// DialEarly attempts 0-RTT: if the session cache holds a valid ticket for
// addr.ID (bucketed by its SNI), the QUIC stack restores the session and
// DialEarly returns before the handshake completes, with the connection ready
// for 0-RTT early data. Without a ticket, DialEarly returns only once the
// handshake completes, exactly like Dial.
//
// The peer identity is the dialed addr.ID; the RFC 7250 VerifyConnection check
// enforces it once the handshake completes, so an early connection carries an
// asserted-but-not-yet-authenticated identity. Callers that sent 0-RTT data wait
// on [Conn.HandshakeComplete] and check [Conn.Used0RTT] to learn whether the
// server accepted the early data; on rejection the data must be resent.
func (e *Endpoint) connectEarly(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (*Connecting, error) {
	if e.isClosed() {
		return nil, ErrEndpointClosed
	}
	if addr.ID.Equal(e.ID()) {
		return nil, ErrSelfConnect
	}
	if err := e.beforeConnect(ctx, addr, alpn); err != nil {
		return nil, err
	}

	dials := e.dialTargets(addr)
	if len(dials) == 0 {
		return nil, ErrNoAddress
	}

	clientTLS, err := clientTLSConfig(e.secretKey, addr.ID, []string{alpn}, e.sessionCache)
	if err != nil {
		return nil, err
	}
	clientTLS.KeyLogWriter = e.keyLogWriter

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ConnectTimeout)
		defer cancel()
	}

	var firstErr error
	for _, target := range dials {
		qc, err := e.transport.DialEarly(ctx, target, clientTLS, e.quicConf)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return &Connecting{ep: e, qc: qc, remoteID: addr.ID, addr: addr, alpn: alpn}, nil
	}
	return nil, fmt.Errorf("iroh: connect to %s: %w", addr.ID, firstErr)
}

// Dial dials addr, negotiates alpn, opens a bidirectional stream, and returns it
// as a [net.Conn].
func (e *Endpoint) Dial(ctx context.Context, addr netaddr.EndpointAddr, alpn string) (net.Conn, error) {
	conn, err := e.Connect(ctx, addr, alpn)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamConn(ctx)
	if err != nil {
		conn.CloseWithError(0, "")
		return nil, err
	}
	return stream, nil
}

// dialTargets returns the ordered net.Addr dial targets for addr: real UDP
// addresses for direct IPs, custom mapped addresses, then relay mapped
// addresses (when relays are enabled). Each mapped target is registered in the
// mapped-address table so the magic socket routes its QUIC packets to the
// selected transport.
func (e *Endpoint) dialTargets(addr netaddr.EndpointAddr) []net.Addr {
	var ips, customs, relays []net.Addr
	if !e.disableIP {
		for _, ip := range addr.IPAddrs() {
			ips = append(ips, net.UDPAddrFromAddrPort(ip))
		}
	}
	for _, ta := range addr.Addrs() {
		c, ok := ta.(netaddr.CustomAddr)
		if !ok {
			continue
		}
		m := e.sock.CustomMappedAddrFor(c)
		customs = append(customs, net.UDPAddrFromAddrPort(m.AddrPort()))
	}
	if e.relay != nil {
		for _, u := range addr.RelayURLs() {
			m := e.sock.RelayMappedAddrFor(u, addr.ID)
			relays = append(relays, net.UDPAddrFromAddrPort(m.AddrPort()))
		}
	}
	var targets []net.Addr
	if e.relayFirst {
		targets = append(targets, relays...)
		targets = append(targets, ips...)
	} else {
		targets = append(targets, ips...)
	}
	targets = append(targets, customs...)
	if !e.relayFirst {
		targets = append(targets, relays...)
	}
	return targets
}

// AcceptIncoming blocks until an incoming connection attempt arrives. The
// returned [Incoming] can be accepted, refused, retried, or ignored.
func (e *Endpoint) AcceptIncoming(ctx context.Context) (*Incoming, error) {
	if err := e.acquireAcceptOwner(acceptOwnerAccept); err != nil {
		return nil, err
	}
	defer e.releaseAcceptOwner(acceptOwnerAccept)
	return e.acceptIncoming(ctx)
}

func (e *Endpoint) acceptIncoming(ctx context.Context) (*Incoming, error) {
	e.mu.Lock()
	closed := e.closed
	ln := e.listener
	e.mu.Unlock()
	if closed {
		return nil, ErrEndpointClosed
	}
	if ln == nil {
		return nil, errors.New("iroh: no ALPNs configured; nothing to accept")
	}
	qc, err := ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &Incoming{ep: e, qc: qc}, nil
}

// Accept blocks until an incoming connection completes its handshake, then
// returns it as a [Conn]. It returns an error if the endpoint is closed or has
// no configured ALPNs. ctx cancels the wait.
func (e *Endpoint) Accept(ctx context.Context) (*Conn, error) {
	e.metrics.acceptsStarted.Add(1)
	if err := e.acquireAcceptOwner(acceptOwnerAccept); err != nil {
		e.metrics.acceptsFailed.Add(1)
		return nil, err
	}
	defer e.releaseAcceptOwner(acceptOwnerAccept)
	conn, err := e.accept(ctx)
	if err != nil {
		e.metrics.acceptsFailed.Add(1)
		return nil, err
	}
	e.metrics.acceptsAccepted.Add(1)
	return conn, nil
}

func (e *Endpoint) accept(ctx context.Context) (*Conn, error) {
	for {
		in, err := e.acceptIncoming(ctx)
		if err != nil {
			return nil, err
		}
		accepting, err := in.Accept()
		if err != nil {
			return nil, err
		}
		conn, err := accepting.Connection(ctx)
		if errors.Is(err, ErrConnClosedDuringHandshake) {
			// A connection attempt dying before its handshake completes must
			// not tear down the acceptor; wait for the next incoming
			// connection instead.
			continue
		}
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

func (e *Endpoint) finishAccepting(ctx context.Context, qc *quic.Conn) (*Conn, error) {
	// The early listener returns connections before the handshake completes so
	// the QUIC stack can buffer 0-RTT early data. The peer's identity is only
	// authenticated once the handshake finishes, so wait for it before reading
	// the verified peer id and negotiated ALPN. Any 0-RTT streams are preserved
	// and surface through Accept{,Uni}Stream after this returns.
	select {
	case <-qc.HandshakeComplete():
		return e.connFromHandshake(ctx, qc)
	default:
	}
	select {
	case <-qc.HandshakeComplete():
	case <-qc.Context().Done():
		// The connection attempt died before completing its handshake
		// (e.g. handshake timeout). HandshakeComplete only closes on
		// success, so without this case the accept would block forever.
		return nil, fmt.Errorf("%w: %w", ErrConnClosedDuringHandshake, context.Cause(qc.Context()))
	case <-ctx.Done():
		qc.CloseWithError(0, "")
		return nil, ctx.Err()
	}
	return e.connFromHandshake(ctx, qc)
}

func (e *Endpoint) connFromHandshake(ctx context.Context, qc *quic.Conn) (*Conn, error) {
	remote, err := peerEndpointID(qc.ConnectionState().TLS)
	if err != nil {
		qc.CloseWithError(0, "bad peer certificate")
		return nil, err
	}
	alpn := qc.ConnectionState().TLS.NegotiatedProtocol
	conn, err := newConn(qc, remote, alpn, SideServer, e.connStableID(qc))
	if err != nil {
		return nil, err
	}
	conn.pathState, conn.pathConn = e.registerConn(remote, qc, netaddr.NewEndpointAddr(remote))
	if err := e.afterHandshake(ctx, conn); err != nil {
		conn.CloseWithError(0, "rejected by hook")
		return nil, err
	}
	return conn, nil
}

func (e *Endpoint) beforeConnect(ctx context.Context, addr netaddr.EndpointAddr, alpn string) error {
	for _, h := range e.hooks {
		if err := h.BeforeConnect(ctx, addr, alpn); err != nil {
			return err
		}
	}
	return nil
}

func (e *Endpoint) afterHandshake(ctx context.Context, conn *Conn) error {
	for _, h := range e.hooks {
		err := h.AfterHandshake(ctx, conn)
		if err != nil {
			var reject *HandshakeRejectError
			if errors.As(err, &reject) {
				if closeErr := conn.CloseWithError(reject.Code, reject.Reason); closeErr != nil {
					return closeErr
				}
				return fmt.Errorf("%w: %w", ErrHandshakeRejected, err)
			}
			return err
		}
	}
	return nil
}

// registerConn registers an established QUIC connection with the per-remote
// state actor for remote, so the actor tracks its path and selects between
// available paths. Registration failures are non-fatal: the connection still
// works; it just is not path-managed. It mirrors the Rust RemoteMap::add_connection
// (iroh/src/socket/remote_map.rs:273).
func (e *Endpoint) registerConn(remote key.EndpointID, qc *quic.Conn, remoteAddr netaddr.EndpointAddr) (*socket.RemoteStateActor, *connAdapter) {
	if e.remotes == nil {
		return nil, nil
	}
	if remoteAddr.ID.IsZero() || !remoteAddr.ID.Equal(remote) {
		remoteAddr = netaddr.NewEndpointAddr(remote)
	}
	pathAddr := e.sock.PathAddr(remote, qc.RemoteAddr())
	adapter := newConnAdapter(qc, pathAddr)
	if pathAddr.Kind() == socket.AddrIP {
		for _, u := range remoteAddr.RelayURLs() {
			m := e.sock.RelayMappedAddrFor(u, remote)
			qc.SetMigrationFallbackRemote(net.UDPAddrFromAddrPort(m.AddrPort()))
			break
		}
	}
	_, actor := e.remotes.AddConnectionActor(remote, adapter)
	go func() {
		_ = e.remotes.ResolveRemote(remoteAddr)
	}()
	if !qc.ConnectionState().MultipathNegotiated {
		return actor, adapter
	}
	// Candidate seeding is opportunistic: QNT may still be disabled or
	// incomplete, and path management must not make an otherwise-established
	// connection fail. The actor/qng layers keep the failure visible to explicit
	// hole-punch calls.
	_ = actor.AddNATTraversalAddresses(e.localNATTraversalCandidates())
	_ = actor.AddRemoteNATTraversalAddresses(remoteAddr.IPAddrs())
	// Punch as soon as a remote candidate is known instead of waiting for
	// the 60s upgrade tick: immediately when the dial carried IP addresses
	// (the seed above closed the channel), or when the server's first
	// ADD_ADDRESS lands after a relay-won dial. The server side of QNT
	// receives no ADD_ADDRESS and parks here until the connection closes.
	go func() {
		select {
		case <-qc.NATTraversalRemoteAddrsReady():
			_ = actor.TriggerHolepunch()
		case <-qc.Context().Done():
		}
	}()
	return actor, adapter
}

func (e *Endpoint) connStableID(qc *quic.Conn) uint64 {
	if qc == nil {
		return 0
	}
	e.mu.Lock()
	if id, ok := e.stableIDs[qc]; ok {
		e.mu.Unlock()
		return id
	}
	e.nextStable++
	id := e.nextStable
	e.stableIDs[qc] = id
	e.mu.Unlock()
	go e.removeStableIDWhenClosed(qc)
	return id
}

func (e *Endpoint) removeStableIDWhenClosed(qc *quic.Conn) {
	<-qc.Context().Done()
	e.mu.Lock()
	delete(e.stableIDs, qc)
	e.mu.Unlock()
}

// resolveFunc returns the address-lookup hook the RemoteMap actors use to
// resolve additional addresses for a remote, or nil when no lookup services are
// configured. It adapts the iroh AddressLookupServices stream to the socket
// package's ResolveFunc, so internal/socket does not import iroh.
func (e *Endpoint) resolveFunc() socket.ResolveFunc {
	lookup := e.lookup
	if lookup == nil {
		return nil
	}
	return func(ctx context.Context, id key.EndpointID) iter.Seq2[socket.ResolvedAddr, error] {
		return func(yield func(socket.ResolvedAddr, error) bool) {
			for item, err := range lookup.Resolve(ctx, id) {
				if err != nil {
					if !yield(socket.ResolvedAddr{}, err) {
						return
					}
					continue
				}
				for _, addr := range item.Addr().Addrs() {
					if !yield(socket.ResolvedAddr{
						Addr:       addr,
						Provenance: item.Provenance(),
					}, nil) {
						return
					}
				}
			}
		}
	}
}

// Shutdown shuts down the endpoint: it stops accepting, closes the QUIC
// transport, and releases the UDP socket. In-flight connections are not
// forcibly closed.
func (e *Endpoint) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.closedCh)
	e.mu.Unlock()

	var firstErr error
	if e.listener != nil {
		if err := e.listener.Close(); err != nil {
			firstErr = err
		}
	}
	// Stop the magic socket's recv loop, then close the QUIC transport (which
	// closes the MagicConn and, through it, the UDP socket).
	e.serveStop()
	if err := e.transport.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	if e.udp != nil {
		if err := e.udp.Close(); err != nil && firstErr == nil && !errors.Is(err, net.ErrClosed) {
			firstErr = err
		}
	}
	return firstErr
}

// Closed returns a channel closed when the endpoint is closed.
func (e *Endpoint) Closed() <-chan struct{} { return e.closedCh }

func (e *Endpoint) isClosed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

func (e *Endpoint) acquireAcceptOwner(owner acceptOwner) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrEndpointClosed
	}
	if e.acceptOwner != acceptOwnerNone {
		return ErrEndpointAcceptLoopInUse
	}
	e.acceptOwner = owner
	return nil
}

func (e *Endpoint) releaseAcceptOwner(owner acceptOwner) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.acceptOwner == owner {
		e.acceptOwner = acceptOwnerNone
	}
}
