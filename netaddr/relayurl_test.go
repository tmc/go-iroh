package netaddr

import (
	"net/url"
	"testing"
)

func TestRelayURLPathTrailingSlash(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://example.com", "https://example.com/"},
		{"https://example.com/", "https://example.com/"},
		{"https://example.com/prefix", "https://example.com/prefix/"},
		{"https://example.com/prefix/", "https://example.com/prefix/"},
		{"https://example.com/a/b?x=1", "https://example.com/a/b/?x=1"},
		{"http://[::1]:8443/prefix", "http://[::1]:8443/prefix/"},
	}
	for _, tt := range tests {
		u, err := ParseRelayURL(tt.in)
		if err != nil {
			t.Fatalf("ParseRelayURL(%q): %v", tt.in, err)
		}
		if got := u.String(); got != tt.want {
			t.Errorf("ParseRelayURL(%q).String() = %q, want %q", tt.in, got, tt.want)
		}

		parsed, err := url.Parse(tt.in)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", tt.in, err)
		}
		if got := RelayURLFromURL(parsed).String(); got != tt.want {
			t.Errorf("RelayURLFromURL(%q).String() = %q, want %q", tt.in, got, tt.want)
		}

		var unmarshaled RelayURL
		if err := unmarshaled.UnmarshalText([]byte(tt.in)); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", tt.in, err)
		}
		if got := unmarshaled.String(); got != tt.want {
			t.Errorf("UnmarshalText(%q).String() = %q, want %q", tt.in, got, tt.want)
		}
	}
}
