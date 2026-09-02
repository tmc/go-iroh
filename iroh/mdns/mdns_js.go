//go:build js

package mdns

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"time"

	"github.com/tmc/go-iroh/dns"
	iroh "github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
)

const (
	// DefaultServiceName is the Rust iroh-mdns-address-lookup service name.
	DefaultServiceName = "irohv1"
	// Provenance is the provenance reported on resolved mDNS items.
	Provenance = "mdns"

	defaultLookupTimeout = 10 * time.Second
)

// Discovery publishes and resolves iroh endpoint addressing information over
// multicast DNS. mDNS is not available in js/wasm.
type Discovery struct {
	id          key.EndpointID
	serviceName string
	passive     bool
	timeout     time.Duration
	logger      *slog.Logger
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

// WithPassive disables publishing.
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
// cannot report to its caller. Nothing is published in js/wasm, so nothing is
// logged; the option exists so code builds for both targets.
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
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Start reports that mDNS is unavailable in js/wasm.
func (d *Discovery) Start(ctx context.Context) error {
	if d == nil {
		return errors.New("mdns: nil Discovery")
	}
	return errors.ErrUnsupported
}

// Publish is a no-op in js/wasm.
func (d *Discovery) Publish(data dns.EndpointData) {}

// Resolve returns no items in js/wasm.
func (d *Discovery) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
	return func(yield func(iroh.Item, error) bool) {}
}
