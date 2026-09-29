package iroh

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestProxyFromEnvironmentSubprocess(t *testing.T) {
	for _, mode := range []string{"normal", "cgi"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestProxyFromEnvironmentHelper$")
			cmd.Env = proxyTestEnv(mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("proxy helper: %v\n%s", err, output)
			}
		})
	}
}

func TestProxyFromEnvironmentHelper(t *testing.T) {
	mode := os.Getenv("GO_IROH_PROXY_TEST_MODE")
	if mode == "" {
		return
	}
	if mode == "cgi" {
		_, err := ProxyFromEnvironment(&url.URL{Scheme: "http", Host: "public.test"})
		if err == nil || !strings.Contains(err.Error(), "refusing to use HTTP_PROXY") {
			t.Fatalf("ProxyFromEnvironment under CGI error = %v, want HTTP_PROXY rejection", err)
		}
		return
	}
	tests := []struct {
		name   string
		target url.URL
		want   string
	}{
		{name: "http uses HTTP_PROXY", target: url.URL{Scheme: "http", Host: "public.test"}, want: "http://http-proxy.test:8080"},
		{name: "https uses HTTPS_PROXY", target: url.URL{Scheme: "https", Host: "public.test"}, want: "http://https-proxy.test:8443"},
		{name: "no proxy domain", target: url.URL{Scheme: "https", Host: "service.excluded.test"}},
		{name: "no proxy CIDR", target: url.URL{Scheme: "https", Host: "192.0.2.15"}},
		{name: "loopback bypass", target: url.URL{Scheme: "http", Host: "127.0.0.1:8080"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ProxyFromEnvironment(&tt.target)
			if err != nil {
				t.Fatalf("ProxyFromEnvironment: %v", err)
			}
			if got == nil {
				if tt.want != "" {
					t.Fatalf("proxy = nil, want %q", tt.want)
				}
				return
			}
			if got.String() != tt.want {
				t.Fatalf("proxy = %q, want %q", got, tt.want)
			}
		})
	}
}

func proxyTestEnv(mode string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "REQUEST_METHOD", "GO_IROH_PROXY_TEST_MODE":
			continue
		}
		env = append(env, entry)
	}
	env = append(env,
		"GO_IROH_PROXY_TEST_MODE="+mode,
		"HTTP_PROXY=http://http-proxy.test:8080",
		"HTTPS_PROXY=http://https-proxy.test:8443",
		"http_proxy=http://lower-http-proxy.test:8080",
		"https_proxy=http://lower-https-proxy.test:8443",
		"NO_PROXY=.excluded.test,192.0.2.0/24",
	)
	if mode == "cgi" {
		env = append(env, "REQUEST_METHOD=GET")
	}
	return env
}

func TestProxyURLReturnsCopy(t *testing.T) {
	original, err := url.Parse("http://proxy.example:3128")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProxyURL(original)(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got == original || got.String() != original.String() {
		t.Fatalf("ProxyURL result = %p %q, original = %p %q", got, got, original, original)
	}
	got.Host = "changed.example"
	if original.Host != "proxy.example:3128" {
		t.Fatalf("mutating result changed original host to %q", original.Host)
	}
}

func ExampleWithProxy() {
	proxyURL, _ := url.Parse("http://proxy.example:3128")
	option := WithProxy(ProxyURL(proxyURL))
	_ = option
	fmt.Println("proxy option configured")
	// Output: proxy option configured
}

func ExampleProxyFromEnvironment() {
	option := WithProxy(ProxyFromEnvironment)
	_ = option
	fmt.Println("uses HTTP_PROXY, HTTPS_PROXY, and NO_PROXY")
	// Output: uses HTTP_PROXY, HTTPS_PROXY, and NO_PROXY
}

func ExampleProxyURL() {
	proxyURL, _ := url.Parse("http://proxy.example:3128")
	proxy := ProxyURL(proxyURL)
	target, _ := url.Parse("https://relay.example")
	selected, _ := proxy(target)
	fmt.Println(selected.Scheme, selected.Host)
	// Output: http proxy.example:3128
}
