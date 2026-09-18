package iroh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/watch"
)

// PkarrProvenance is the provenance string for [PkarrResolver] items.
const PkarrProvenance = "pkarr"

// pkarr relay URLs and publishing defaults.
//
// iroh/src/address_lookup/pkarr.rs.
const (
	// N0DNSPkarrRelayProd is the number0 production pkarr relay, which also
	// serves the records over DNS.
	N0DNSPkarrRelayProd = "https://dns.iroh.link/pkarr"
	// N0DNSPkarrRelayStaging is the number0 staging pkarr relay.
	N0DNSPkarrRelayStaging = "https://staging-dns.iroh.link/pkarr"

	// DefaultPkarrTTL is the default record TTL, in seconds, of published pkarr
	// signed packets.
	DefaultPkarrTTL uint32 = 30
	// DefaultRepublishInterval is how often the publisher republishes the
	// endpoint info even when unchanged.
	DefaultRepublishInterval = 5 * time.Minute
)

// PkarrPublisher publishes endpoint addressing information to a pkarr relay
// over HTTP. Pair it with a [PkarrResolver] or [DNSAddressLookup] to resolve.
//
// Publishing is fire-and-forget: [PkarrPublisher.Publish] updates an internal
// value and returns immediately while a background goroutine performs the HTTP
// PUT. The publisher republishes every [DefaultRepublishInterval] even when the
// data is unchanged, and retries with backoff on failure. By default only relay
// addresses are published (see [RelayOnlyFilter]).
//
// The zero value is not usable; create one with [NewPkarrPublisher] or
// [N0PkarrPublisher]. Stop the background goroutine with [PkarrPublisher.Close].
//
// It is the Go analog of iroh's PkarrPublisher.
type PkarrPublisher struct {
	endpointID key.EndpointID
	addrFilter AddrFilter
	value      *watch.Value[*dns.EndpointInfo]
	cancel     context.CancelFunc
	done       chan struct{}
}

// PkarrPublisherConfig configures a [PkarrPublisher].
type PkarrPublisherConfig struct {
	// TTL is the record TTL, in seconds, of published packets. If zero,
	// [DefaultPkarrTTL] is used.
	TTL uint32
	// RepublishInterval is how often packets are republished even when
	// unchanged. If zero, [DefaultRepublishInterval] is used.
	RepublishInterval time.Duration
	// AddrFilter controls which addresses are published. If nil,
	// [RelayOnlyFilter] is used. Use a filter that returns its input unchanged
	// to publish all addresses.
	AddrFilter AddrFilter
	// HTTPClient is used for relay requests. If nil, a client with a per-request
	// timeout is used.
	HTTPClient *http.Client
}

// NewPkarrPublisher creates a publisher that signs packets with secretKey,
// publishes to the pkarr relay at relayURL, and starts its background publish
// goroutine.
func NewPkarrPublisher(secretKey key.SecretKey, relayURL string, cfg *PkarrPublisherConfig) (*PkarrPublisher, error) {
	ttl := DefaultPkarrTTL
	republishInterval := DefaultRepublishInterval
	filter := RelayOnlyFilter
	var httpClient *http.Client
	if cfg != nil {
		if cfg.TTL != 0 {
			ttl = cfg.TTL
		}
		if cfg.RepublishInterval != 0 {
			republishInterval = cfg.RepublishInterval
		}
		if cfg.AddrFilter != nil {
			filter = cfg.AddrFilter
		}
		httpClient = cfg.HTTPClient
	}

	client, err := newPkarrRelayClient(relayURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("pkarr publisher: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &PkarrPublisher{
		endpointID: secretKey.Public().EndpointID(),
		addrFilter: filter,
		value:      watch.NewValue[*dns.EndpointInfo](nil),
		cancel:     cancel,
		done:       make(chan struct{}),
	}
	svc := &publisherService{
		secretKey:         secretKey,
		client:            client,
		watcher:           p.value.Watch(),
		ttl:               ttl,
		republishInterval: republishInterval,
	}
	go func() {
		defer close(p.done)
		svc.run(ctx)
	}()
	return p, nil
}

// N0PkarrPublisher creates a publisher using the number0 production pkarr relay
// ([N0DNSPkarrRelayProd]).
func N0PkarrPublisher(secretKey key.SecretKey, cfg *PkarrPublisherConfig) (*PkarrPublisher, error) {
	return NewPkarrPublisher(secretKey, N0DNSPkarrRelayProd, cfg)
}

// Publish records data to publish to the pkarr relay. It applies the
// publisher's address filter and returns immediately; the HTTP PUT runs in the
// background.
func (p *PkarrPublisher) Publish(data dns.EndpointData) {
	filtered := applyFilter(data, p.addrFilter)
	info := dns.EndpointInfo{ID: p.endpointID, Data: filtered}
	p.value.Set(&info)
}

// Close stops the background publish goroutine and waits for it to exit.
func (p *PkarrPublisher) Close() error {
	p.cancel()
	<-p.done
	return nil
}

// publisherService runs the publisher's background loop: it publishes whenever
// the endpoint info changes and republishes on a fixed interval, with backoff
// on failure.
type publisherService struct {
	secretKey         key.SecretKey
	client            *pkarrRelayClient
	watcher           watch.Observer[*dns.EndpointInfo]
	ttl               uint32
	republishInterval time.Duration
}

func (s *publisherService) run(ctx context.Context) {
	// A single goroutine watches for endpoint-info changes and signals them on
	// changed, so the loop below never spawns a watcher goroutine per iteration.
	changed := make(chan struct{}, 1)
	go func() {
		for {
			if _, err := s.watcher.Updated(ctx); err != nil {
				return // ctx cancelled
			}
			select {
			case changed <- struct{}{}:
			default: // a pending signal already covers this change
			}
		}
	}()

	var failedAttempts int
	republish := time.NewTimer(time.Duration(1 << 62))
	defer republish.Stop()
	for {
		if info := s.watcher.Current(); info != nil {
			if err := s.publishCurrent(ctx, *info); err != nil {
				if ctx.Err() != nil {
					return
				}
				failedAttempts++
				resetTimer(republish, time.Duration(failedAttempts)*time.Second)
			} else {
				failedAttempts = 0
				resetTimer(republish, s.republishInterval)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-republish.C:
		case <-changed:
		}
	}
}

func (s *publisherService) publishCurrent(ctx context.Context, info dns.EndpointInfo) error {
	packet, err := info.ToSignedPacket(s.secretKey, s.ttl)
	if err != nil {
		return fmt.Errorf("encode signed packet: %w", err)
	}
	return s.client.publish(ctx, packet)
}

// resetTimer stops and resets t to fire after d, draining any pending tick.
func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// PkarrResolver resolves endpoint addressing information from a pkarr relay over
// HTTP.
//
// The zero value is not usable; create one with [NewPkarrResolver] or
// [N0PkarrResolver].
//
// It is the Go analog of iroh's PkarrResolver.
type PkarrResolver struct {
	client *pkarrRelayClient
}

// PkarrResolverConfig configures a [PkarrResolver].
type PkarrResolverConfig struct {
	// HTTPClient is used for relay requests. If nil, a client with a per-request
	// timeout is used.
	HTTPClient *http.Client
}

// NewPkarrResolver creates a resolver that resolves from the pkarr relay at
// relayURL.
func NewPkarrResolver(relayURL string, cfg *PkarrResolverConfig) (*PkarrResolver, error) {
	var httpClient *http.Client
	if cfg != nil {
		httpClient = cfg.HTTPClient
	}
	client, err := newPkarrRelayClient(relayURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("pkarr resolver: %w", err)
	}
	return &PkarrResolver{client: client}, nil
}

// N0PkarrResolver creates a resolver using the number0 production pkarr relay
// ([N0DNSPkarrRelayProd]).
func N0PkarrResolver(cfg *PkarrResolverConfig) (*PkarrResolver, error) {
	return NewPkarrResolver(N0DNSPkarrRelayProd, cfg)
}

// Resolve fetches the signed packet for id from the pkarr relay and decodes its
// endpoint info.
func (r *PkarrResolver) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[Item, error] {
	return func(yield func(Item, error) bool) {
		packet, err := r.client.resolve(ctx, id)
		if err != nil {
			if ctx.Err() == nil {
				yield(Item{}, lookupErr(PkarrProvenance, err))
			}
			return
		}
		info, err := dns.EndpointInfoFromSignedPacket(packet)
		if err != nil {
			if ctx.Err() == nil {
				yield(Item{}, lookupErr(PkarrProvenance, err))
			}
			return
		}
		if ctx.Err() == nil {
			yield(NewItem(info, PkarrProvenance, nil), nil)
		}
	}
}

// pkarrRelayClient publishes and resolves pkarr signed packets to a pkarr relay
// using HTTP PUT and GET on "<relay>/<z32-endpoint-id>".
//
// iroh/src/address_lookup/pkarr.rs PkarrRelayClient; the route and body match
// iroh-dns-server/src/http/pkarr.rs (put/get).
type pkarrRelayClient struct {
	httpClient *http.Client
	relayURL   *url.URL
}

func newPkarrRelayClient(relayURL string, client *http.Client) (*pkarrRelayClient, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("parse relay url: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &pkarrRelayClient{httpClient: client, relayURL: u}, nil
}

// keyURL returns "<relay>/<z32>" for the endpoint id's z-base-32 encoding.
func (c *pkarrRelayClient) keyURL(z32 string) string {
	u := *c.relayURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + z32
	return u.String()
}

// publish PUTs the signed packet's relay payload (signature + timestamp + DNS
// wire bytes, i.e. everything after the public key) to "<relay>/<z32>".
func (c *pkarrRelayClient) publish(ctx context.Context, packet *dns.SignedPacket) error {
	body := packet.RelayPayload()
	target := c.keyURL(packet.PublicKey().EndpointID().Z32())
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http put: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pkarr relay returned status %d", resp.StatusCode)
	}
	return nil
}

// resolve GETs the relay payload from "<relay>/<z32>" and reconstructs (and
// verifies) the signed packet from the public key and payload.
func (c *pkarrRelayClient) resolve(ctx context.Context, id key.EndpointID) (*dns.SignedPacket, error) {
	target := c.keyURL(id.Z32())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("pkarr relay returned status %d", resp.StatusCode)
	}
	// The payload is a signed packet without its 32-byte public key, so a
	// valid one is shorter than MaxSignedPacketSize. Limiting to the full
	// packet size leaves enough headroom that an oversized body still fails
	// the length check in SignedPacketFromBytes rather than being silently
	// truncated to a plausible length.
	payload, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxSignedPacketSize))
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	pubBytes := id.PublicKey().Bytes()
	wire := make([]byte, 0, len(pubBytes)+len(payload))
	wire = append(wire, pubBytes[:]...)
	wire = append(wire, payload...)
	packet, err := dns.SignedPacketFromBytes(wire)
	if err != nil {
		return nil, fmt.Errorf("decode signed packet: %w", err)
	}
	return packet, nil
}
