// Package relay provides the public configuration types for iroh relay servers:
// relay URLs grouped into a [Map], per-relay [Config], and the [Mode] selecting
// which relays an endpoint uses.
//
// It is the public surface of the Rust crate iroh-relay (the client connection
// and wire protocol live in internal packages).
package relay

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tmc/go-iroh/netaddr"
)

// DefaultQUICPort is the default port for relay QUIC address discovery.
const DefaultQUICPort = 7842

// number0 production relay hostnames.
const (
	naEastRelayHostname = "use1-1.relay.n0.iroh-canary.iroh.link."
	naWestRelayHostname = "usw1-1.relay.n0.iroh-canary.iroh.link."
	euRelayHostname     = "euc1-1.relay.n0.iroh-canary.iroh.link."
	apRelayHostname     = "aps1-1.relay.n0.iroh-canary.iroh.link."
)

// number0 staging relay hostname.
const stagingEURelayHostname = "staging-euw1-1.relay.iroh.network."

// QUICConfig configures relay-based QUIC address discovery.
type QUICConfig struct {
	// Port is the QUIC port on the relay server.
	Port uint16
}

// Config is the configuration for a single relay server.
type Config struct {
	// URL is the relay server URL.
	URL netaddr.RelayURL
	// QUIC, if non-nil, enables QUIC address discovery via this relay.
	QUIC *QUICConfig
	// AuthToken, if non-empty, is sent to authenticate with the relay.
	AuthToken string
}

// NewConfig returns a Config for url with the given optional QUIC config.
func NewConfig(url netaddr.RelayURL, quic *QUICConfig) Config {
	return Config{URL: url, QUIC: quic}
}

// WithAuthToken returns a copy of c with the auth token set.
func (c Config) WithAuthToken(token string) Config {
	c.AuthToken = token
	return c
}

func (c Config) String() string { return c.URL.String() }

// MarshalText implements encoding.TextMarshaler using the relay URL string.
func (c Config) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

// Map is a set of relay servers keyed by URL.
//
// The zero Map is empty and ready to use, but is not safe for concurrent
// mutation; build it up before sharing.
type Map struct {
	relays map[string]Config // key: RelayURL.String()
}

// NewMap builds a Map from the given relay configs.
func NewMap(configs ...Config) *Map {
	m := &Map{relays: make(map[string]Config, len(configs))}
	for _, c := range configs {
		m.Insert(c)
	}
	return m
}

// MapFromURLs builds a Map from relay URLs, each with a default config that
// enables QUIC address discovery on [DefaultQUICPort]. net_report only probes
// relays whose config has a QUIC section, so a nil default would disable
// address discovery for every URL-built map, including [DefaultMap]. A relay
// without QAD just fails the probe, which stays latency-only.
func MapFromURLs(urls ...netaddr.RelayURL) *Map {
	configs := make([]Config, len(urls))
	for i, u := range urls {
		configs[i] = Config{URL: u, QUIC: &QUICConfig{Port: DefaultQUICPort}}
	}
	return NewMap(configs...)
}

// Insert adds or replaces the config for its URL, returning the previous config
// and whether one was present.
func (m *Map) Insert(c Config) (Config, bool) {
	if m.relays == nil {
		m.relays = map[string]Config{}
	}
	key := c.URL.String()
	prev, ok := m.relays[key]
	m.relays[key] = c
	return prev, ok
}

// Remove deletes the config for url, returning it and whether it was present.
func (m *Map) Remove(url netaddr.RelayURL) (Config, bool) {
	c, ok := m.relays[url.String()]
	delete(m.relays, url.String())
	return c, ok
}

// Get returns the config for url and whether it is present.
func (m *Map) Get(url netaddr.RelayURL) (Config, bool) {
	c, ok := m.relays[url.String()]
	return c, ok
}

// Contains reports whether url is in the map.
func (m *Map) Contains(url netaddr.RelayURL) bool {
	_, ok := m.relays[url.String()]
	return ok
}

// Len returns the number of relays.
func (m *Map) Len() int { return len(m.relays) }

// IsEmpty reports whether the map has no relays.
func (m *Map) IsEmpty() bool { return len(m.relays) == 0 }

// URLs returns the relay URLs in sorted order.
func (m *Map) URLs() []netaddr.RelayURL {
	keys := slices.Sorted(maps.Keys(m.relays))
	out := make([]netaddr.RelayURL, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.relays[k].URL)
	}
	return out
}

// Configs returns the relay configs in URL-sorted order.
func (m *Map) Configs() []Config {
	keys := slices.Sorted(maps.Keys(m.relays))
	out := make([]Config, 0, len(keys))
	for _, k := range keys {
		out = append(out, m.relays[k])
	}
	return out
}

// Clone returns a deep copy of the map.
func (m *Map) Clone() *Map {
	return &Map{relays: maps.Clone(m.relays)}
}

func (m *Map) String() string {
	var b strings.Builder
	b.WriteString("RelayMap{")
	b.WriteString(strings.Join(func() []string {
		urls := m.URLs()
		ss := make([]string, len(urls))
		for i, u := range urls {
			ss[i] = u.String()
		}
		return ss
	}(), ", "))
	b.WriteString("}")
	return b.String()
}

// Mode selects which relay servers an endpoint uses.
type Mode struct {
	kind   modeKind
	custom *Map
}

type modeKind int

const (
	modeDisabled modeKind = iota
	modeDefault
	modeStaging
	modeCustom
)

// ModeDisabled disables relay servers entirely.
func ModeDisabled() Mode { return Mode{kind: modeDisabled} }

// ModeDefault uses the number0 production relay servers.
func ModeDefault() Mode { return Mode{kind: modeDefault} }

// ModeStaging uses the number0 staging relay servers.
func ModeStaging() Mode { return Mode{kind: modeStaging} }

// ModeCustom uses a custom relay map.
func ModeCustom(m *Map) Mode { return Mode{kind: modeCustom, custom: m} }

// ModeCustomURLs uses a custom relay map built from the given URLs.
func ModeCustomURLs(urls ...netaddr.RelayURL) Mode {
	return ModeCustom(MapFromURLs(urls...))
}

// Map returns the relay map for this mode.
func (m Mode) Map() *Map {
	switch m.kind {
	case modeDefault:
		return DefaultMap()
	case modeStaging:
		return StagingMap()
	case modeCustom:
		if m.custom == nil {
			return NewMap()
		}
		return m.custom
	default:
		return NewMap()
	}
}

// DefaultMap returns the number0 production relay map.
func DefaultMap() *Map {
	return MapFromURLs(
		mustURL("https://"+naEastRelayHostname),
		mustURL("https://"+naWestRelayHostname),
		mustURL("https://"+euRelayHostname),
		mustURL("https://"+apRelayHostname),
	)
}

// StagingMap returns the number0 staging relay map.
func StagingMap() *Map {
	return MapFromURLs(mustURL("https://" + stagingEURelayHostname))
}

func mustURL(s string) netaddr.RelayURL {
	u, err := netaddr.ParseRelayURL(s)
	if err != nil {
		panic(fmt.Sprintf("relay: invalid default url %q: %v", s, err))
	}
	return u
}
