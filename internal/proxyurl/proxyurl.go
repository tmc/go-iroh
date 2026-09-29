// Package proxyurl validates HTTP proxy URLs used by iroh transports.
package proxyurl

import (
	"errors"
	"net/url"
	"strings"
)

// Validate reports whether u can be used as an HTTP proxy URL.
func Validate(u *url.URL) error {
	if u == nil {
		return errors.New("invalid proxy URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || u.Hostname() == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid proxy URL")
	}
	return nil
}
