package netaddr

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// RelayURL is a URL identifying a relay server.
//
// It wraps a parsed URL and is cheap to copy. It is encouraged to use a
// fully-qualified DNS domain name (one ending in a ".", e.g. "relay.example.com.")
// so that local DNS search domains do not interfere with resolution.
//
// The zero value is not usable; construct a RelayURL with [ParseRelayURL] or
// [RelayURLFromURL].
type RelayURL struct {
	url *url.URL
	s   string
}

// ParseRelayURL parses s into a RelayURL. It returns an error wrapping
// [ErrParseRelayURL] if s is not a valid URL.
func ParseRelayURL(s string) (RelayURL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return RelayURL{}, fmt.Errorf("%w: %v", ErrParseRelayURL, err)
	}
	return RelayURLFromURL(u), nil
}

// RelayURLFromURL wraps an already-parsed URL as a RelayURL, normalizing it so
// that equivalent URLs compare equal (see [RelayURL.String]).
func RelayURLFromURL(u *url.URL) RelayURL {
	c := *u
	n := normalizeURL(&c)
	return RelayURL{url: n, s: n.String()}
}

// ErrParseRelayURL is returned (wrapped) when a relay URL cannot be parsed.
var ErrParseRelayURL = errors.New("failed to parse relay URL")

// URL returns a copy of the underlying parsed URL.
func (r RelayURL) URL() *url.URL {
	if r.url == nil {
		return nil
	}
	c := *r.url
	return &c
}

// String returns the normalized string form of the URL. Special schemes
// (http/https/ws/wss) normalize to a trailing "/" on the path, matching the
// Rust reference implementation (e.g. "https://example.com" ->
// "https://example.com/", "https://example.com/prefix" ->
// "https://example.com/prefix/").
func (r RelayURL) String() string { return r.s }

// Host returns the host (without port) of the relay URL.
func (r RelayURL) Host() string {
	if r.url == nil {
		return ""
	}
	return r.url.Hostname()
}

// IsZero reports whether r is the unusable zero value.
func (r RelayURL) IsZero() bool { return r.url == nil }

// Equal reports whether r and other are the same relay URL.
func (r RelayURL) Equal(other RelayURL) bool { return r.String() == other.String() }

// Compare returns -1, 0, or +1 comparing r and other by their normalized
// string form, giving RelayURL a total order.
func (r RelayURL) Compare(other RelayURL) int {
	return strings.Compare(r.String(), other.String())
}

// MarshalText implements encoding.TextMarshaler.
func (r RelayURL) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (r *RelayURL) UnmarshalText(text []byte) error {
	parsed, err := ParseRelayURL(string(text))
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// normalizeURL applies the small subset of WHATWG URL normalization that the
// reference implementation relies on: a special scheme (http/https/ws/wss)
// ends its path with "/" so relative relay paths join under any path prefix,
// and the host is lower-cased.
func normalizeURL(u *url.URL) *url.URL {
	u.Host = strings.ToLower(u.Host)
	if u.Opaque == "" && isSpecialScheme(u.Scheme) && !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
		if u.RawPath != "" && !strings.HasSuffix(u.RawPath, "/") {
			u.RawPath += "/"
		}
	}
	return u
}

func isSpecialScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "ws", "wss", "ftp", "file":
		return true
	}
	return false
}
