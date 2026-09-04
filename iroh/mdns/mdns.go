//go:build !js

package mdns

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	iroh "github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"golang.org/x/net/ipv4"
)

const (
	// DefaultServiceName is the Rust iroh-mdns-address-lookup service name.
	DefaultServiceName = "irohv1"
	// Provenance is the provenance reported on resolved mDNS items.
	Provenance = "mdns"

	defaultLookupTimeout = 10 * time.Second
	mdnsPort             = 5353
)

var (
	ipv4Multicast = netip.MustParseAddrPort("224.0.0.251:5353")

	errNoAddresses = errors.New("mdns: endpoint data has no IP addresses")
)

// Discovery publishes and resolves iroh endpoint addressing information over
// multicast DNS. The zero value is not usable; create one with [New].
//
// One DNS-SD instance carries one SRV record and so one port. An endpoint whose
// direct addresses do not all share a port is announced on the port most of
// them use, lowest port first on a tie, and the rest are dropped; see
// [Discovery.Publish] for how that is reported.
type Discovery struct {
	id          key.EndpointID
	serviceName string
	passive     bool
	timeout     time.Duration
	logger      *slog.Logger
	// responseDelay is how long to wait before answering a query. RFC 6762
	// section 6 asks for a random 20-120ms so that simultaneous responders
	// do not collide. Tests replace it.
	responseDelay func() time.Duration

	mu        sync.RWMutex
	peers     map[key.EndpointID]peerInfo
	conn      *net.UDPConn
	announced []byte // last announcement built by Publish, replayed to queries
}

type peerInfo struct {
	data        dns.EndpointData
	lastUpdated uint64
}

// Option configures a Discovery.
type Option func(*Discovery)

// WithServiceName changes the DNS-SD service name. The default is "irohv1",
// yielding records under _irohv1._udp.local.
func WithServiceName(name string) Option {
	return func(d *Discovery) {
		if name != "" {
			d.serviceName = name
		}
	}
}

// WithPassive disables publishing. The Discovery still listens and resolves.
func WithPassive(passive bool) Option {
	return func(d *Discovery) {
		d.passive = passive
	}
}

// WithLookupTimeout sets how long Resolve waits for a multicast response after
// a cache miss. Non-positive values use the default.
func WithLookupTimeout(timeout time.Duration) Option {
	return func(d *Discovery) {
		if timeout > 0 {
			d.timeout = timeout
		}
	}
}

// WithLogger sets the logger for events a fire-and-forget [Discovery.Publish]
// cannot report to its caller, such as endpoint data it cannot announce. The
// default is [slog.Default].
func WithLogger(logger *slog.Logger) Option {
	return func(d *Discovery) {
		if logger != nil {
			d.logger = logger
		}
	}
}

// New returns a Discovery for id using the default iroh local-network service
// name.
func New(id key.EndpointID, opts ...Option) *Discovery {
	d := &Discovery{
		id:          id,
		serviceName: DefaultServiceName,
		timeout:     defaultLookupTimeout,
		logger:      slog.Default(),
		responseDelay: func() time.Duration {
			return 20*time.Millisecond + time.Duration(rand.Int64N(int64(100*time.Millisecond)))
		},
		peers: make(map[key.EndpointID]peerInfo),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Start listens for mDNS packets until ctx is cancelled. It caches the
// announcements it sees and answers queries for the service, or for this
// endpoint's instance, with the endpoint's most recent announcement, after the
// random delay RFC 6762 section 6 requires. It is safe to call Publish before
// Start, but a Discovery answers queries and observes remote responses only
// while Start is running.
func (d *Discovery) Start(ctx context.Context) error {
	if d == nil {
		return errors.New("mdns: nil Discovery")
	}
	conn, err := listenIPv4MDNS(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	d.mu.Lock()
	if d.conn == nil {
		d.conn = conn
	}
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		if d.conn == conn {
			d.conn = nil
		}
		d.mu.Unlock()
	}()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("mdns: read: %w", err)
		}
		d.handlePacket(buf[:n])
	}
}

func listenIPv4MDNS(ctx context.Context) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: reusePortControl}
	pc, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", fmt.Sprint(mdnsPort)))
	if err != nil {
		return nil, fmt.Errorf("mdns: listen udp4: %w", err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("mdns: listen did not return UDPConn")
	}
	p := ipv4.NewPacketConn(conn)
	group := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251)}
	joined := false
	ifaces, _ := net.Interfaces()
	for i := range ifaces {
		if ifaces[i].Flags&net.FlagUp == 0 || ifaces[i].Flags&net.FlagMulticast == 0 {
			continue
		}
		if err := p.JoinGroup(&ifaces[i], group); err == nil {
			joined = true
		}
	}
	if !joined {
		if err := p.JoinGroup(nil, group); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("mdns: join ipv4 multicast: %w", err)
		}
	}
	return conn, nil
}

// Publish advertises data on the local network. It is fire-and-forget and
// returns immediately, matching iroh.AddressPublisher, so what it cannot
// announce it reports to the logger given to [WithLogger] instead of to the
// caller: endpoint data with no direct IP address (a relay-only endpoint
// announces nothing) and addresses dropped by the single-port rule described on
// [Discovery].
func (d *Discovery) Publish(data dns.EndpointData) {
	if d == nil || d.passive {
		return
	}
	packet, err := d.announcement(data)
	if err != nil {
		d.log().Warn("mdns: not announcing endpoint data", "endpoint", d.id, "err", err)
		return
	}
	go d.writeMulticast(packet)
}

// log returns the configured logger, or the default one for a Discovery built
// before WithLogger existed or by a zero value.
func (d *Discovery) log() *slog.Logger {
	if d.logger == nil {
		return slog.Default()
	}
	return d.logger
}

// Resolve returns the cached item for id, if present, and otherwise sends a
// multicast query and waits for a matching response until ctx or the lookup
// timeout fires. The response comes from the peer's own [Discovery.Start] loop,
// so the peer must be running one; a peer that only published once and stopped
// listening cannot answer.
func (d *Discovery) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
	if d == nil {
		return nil
	}
	return func(yield func(iroh.Item, error) bool) {
		if item, ok := d.item(id); ok {
			yield(item, nil)
			return
		}
		d.query(id)
		timer := time.NewTimer(d.timeout)
		defer timer.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				yield(iroh.Item{}, ctx.Err())
				return
			case <-timer.C:
				return
			case <-tick.C:
				if item, ok := d.item(id); ok {
					yield(item, nil)
					return
				}
			}
		}
	}
}

func (d *Discovery) item(id key.EndpointID) (iroh.Item, bool) {
	d.mu.RLock()
	peer, ok := d.peers[id]
	d.mu.RUnlock()
	if !ok {
		return iroh.Item{}, false
	}
	info := dns.EndpointInfo{ID: id, Data: cloneEndpointData(peer.data)}
	return iroh.NewItem(info, Provenance, &peer.lastUpdated), true
}

func (d *Discovery) handlePacket(packet []byte) {
	info, ok := parseAnnouncement(packet, d.serviceName)
	if !ok {
		d.answerQuery(packet)
		return
	}
	d.mu.Lock()
	if d.peers == nil {
		d.peers = make(map[key.EndpointID]peerInfo)
	}
	d.peers[info.ID] = peerInfo{
		data:        cloneEndpointData(info.Data),
		lastUpdated: uint64(time.Now().UnixMicro()),
	}
	d.mu.Unlock()
}

// answerFor returns the announcement to multicast in reply to packet, and
// whether packet is a query this Discovery should answer: one asking for the
// service, or for this endpoint's own instance. A Discovery that publishes
// nothing answers nothing.
//
// The announcement carries the PTR, SRV and TXT records together, so any
// question they answer gets the whole set. A PTR question names the service or
// the instance; SRV and TXT name the instance alone, since they describe one
// instance and the service name does not identify which.
func (d *Discovery) answerFor(packet []byte) ([]byte, bool) {
	if d.passive {
		return nil, false
	}
	d.mu.RLock()
	announced := d.announced
	d.mu.RUnlock()
	if len(announced) == 0 {
		return nil, false
	}
	questions, ok := parseQuestions(packet)
	if !ok {
		return nil, false
	}
	service := serviceName(d.serviceName)
	instance := instanceName(d.serviceName, d.id)
	for _, q := range questions {
		switch q.typ {
		case dnsTypePTR, dnsTypeANY:
			if strings.EqualFold(q.name, service) || strings.EqualFold(q.name, instance) {
				return announced, true
			}
		case dnsTypeSRV, dnsTypeTXT:
			if strings.EqualFold(q.name, instance) {
				return announced, true
			}
		}
	}
	return nil, false
}

// answerQuery multicasts this endpoint's announcement if packet is a query it
// should answer, and reports whether it started a response.
func (d *Discovery) answerQuery(packet []byte) bool {
	answer, ok := d.answerFor(packet)
	if !ok {
		return false
	}
	go d.respond(answer)
	return true
}

// respond multicasts answer after the response delay.
func (d *Discovery) respond(answer []byte) {
	timer := time.NewTimer(d.responseDelay())
	defer timer.Stop()
	<-timer.C
	// Answer only on the socket Start opened. writeMulticast falls back to a
	// fresh socket when there is none, which would multicast a response after
	// Start has returned.
	d.mu.RLock()
	conn := d.conn
	d.mu.RUnlock()
	if conn == nil {
		return
	}
	_, _ = conn.WriteToUDPAddrPort(answer, ipv4Multicast)
}

func (d *Discovery) query(id key.EndpointID) {
	name := instanceName(d.serviceName, id)
	packet, err := buildQuery(serviceName(d.serviceName), name)
	if err != nil {
		return
	}
	go d.writeMulticast(packet)
}

func (d *Discovery) writeMulticast(packet []byte) {
	if len(packet) == 0 {
		return
	}
	d.mu.RLock()
	conn := d.conn
	d.mu.RUnlock()
	if conn != nil {
		_, _ = conn.WriteToUDPAddrPort(packet, ipv4Multicast)
		return
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.WriteToUDPAddrPort(packet, ipv4Multicast)
}

// announcement builds the announcement packet for data and records it as the
// answer to later queries.
func (d *Discovery) announcement(data dns.EndpointData) ([]byte, error) {
	info, err := d.announcementInfo(data)
	if err != nil {
		return nil, err
	}
	packet, err := buildAnnouncement(d.serviceName, info)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.announced = packet
	d.mu.Unlock()
	return packet, nil
}

type announcementData struct {
	id       key.EndpointID
	port     uint16
	ips      []netip.AddrPort
	relay    string
	userData string
}

func (d *Discovery) announcementInfo(data dns.EndpointData) (announcementData, error) {
	ipAddrs := data.IPAddrs()
	if len(ipAddrs) == 0 {
		return announcementData{}, errNoAddresses
	}
	out := announcementData{id: d.id}
	out.port = announcementPort(ipAddrs)
	var dropped []netip.AddrPort
	for _, addr := range ipAddrs {
		if !addr.Addr().IsValid() {
			continue
		}
		if addr.Port() != out.port {
			dropped = append(dropped, addr)
			continue
		}
		out.ips = append(out.ips, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()))
	}
	if len(out.ips) == 0 {
		return announcementData{}, errNoAddresses
	}
	if len(dropped) > 0 {
		d.log().Warn("mdns: announcing one port only, dropping addresses on others",
			"endpoint", d.id, "port", out.port, "dropped", dropped)
	}
	if relays := data.RelayURLs(); len(relays) != 0 {
		if s := relays[0].String(); len(s) <= 249 {
			out.relay = s
		}
	}
	if u := data.UserData(); u != nil {
		out.userData = u.String()
	}
	return out, nil
}

// announcementPort returns the port to announce for addrs. One DNS-SD instance
// has one SRV record and so one port; the port shared by the most addresses
// keeps the most of them, and the lowest such port breaks ties so that repeated
// announcements of the same address set are identical.
func announcementPort(addrs []netip.AddrPort) uint16 {
	counts := make(map[uint16]int, len(addrs))
	for _, addr := range addrs {
		if addr.Addr().IsValid() {
			counts[addr.Port()]++
		}
	}
	var best uint16
	bestCount := 0
	for _, port := range slices.Sorted(maps.Keys(counts)) {
		if counts[port] > bestCount {
			best, bestCount = port, counts[port]
		}
	}
	return best
}

func cloneEndpointData(data dns.EndpointData) dns.EndpointData {
	out := dns.NewEndpointData(data.Addrs()...)
	if u := data.UserData(); u != nil {
		c := *u
		out.SetUserData(&c)
	}
	return out
}

func endpointLabel(id key.EndpointID) string {
	b := id.Bytes()
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

func parseEndpointLabel(label string) (key.EndpointID, error) {
	return key.ParseEndpointID(label)
}

func serviceName(service string) string {
	service = strings.Trim(service, ".")
	if !strings.HasPrefix(service, "_") {
		service = "_" + service
	}
	return service + "._udp.local"
}

func instanceName(service string, id key.EndpointID) string {
	return endpointLabel(id) + "." + serviceName(service)
}

func hostName(id key.EndpointID) string {
	return endpointLabel(id) + ".local"
}

func infoFromAnnouncement(a announcementData) dns.EndpointInfo {
	data := dns.NewEndpointData()
	addrs := append([]netip.AddrPort(nil), a.ips...)
	data.AddIPAddrs(addrs...)
	if a.relay != "" {
		if relay, err := netaddr.ParseRelayURL(a.relay); err == nil {
			data.AddRelayURL(relay)
		}
	}
	if a.userData != "" {
		if u, err := dns.NewUserData(a.userData); err == nil {
			data.SetUserData(&u)
		}
	}
	return dns.EndpointInfo{ID: a.id, Data: data}
}

var (
	_ iroh.AddressPublisher = (*Discovery)(nil)
	_ iroh.AddressResolver  = (*Discovery)(nil)
)
