package proxyurl

import (
	"net/url"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		url  *url.URL
		want bool
	}{
		{name: "http", url: &url.URL{Scheme: "http", Host: "proxy.example:8080"}, want: true},
		{name: "https", url: &url.URL{Scheme: "https", Host: "proxy.example:8443"}, want: true},
		{name: "nil"},
		{name: "unsupported scheme", url: &url.URL{Scheme: "socks5", Host: "proxy.example:1080"}},
		{name: "missing host", url: &url.URL{Scheme: "http"}},
		{name: "path", url: &url.URL{Scheme: "http", Host: "proxy.example", Path: "/proxy"}},
		{name: "query", url: &url.URL{Scheme: "http", Host: "proxy.example", RawQuery: "x=y"}},
		{name: "fragment", url: &url.URL{Scheme: "http", Host: "proxy.example", Fragment: "part"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.url)
			if got := err == nil; got != tt.want {
				t.Fatalf("Validate(%v) error = %v, want valid %v", tt.url, err, tt.want)
			}
		})
	}
}
