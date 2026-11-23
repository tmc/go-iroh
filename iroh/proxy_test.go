package iroh

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
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

func ExampleProxyURL() {
	proxyURL, err := url.Parse("http://proxy.example:3128")
	if err != nil {
		panic(err)
	}
	proxy := ProxyURL(proxyURL)
	target, err := url.Parse("https://relay.example")
	if err != nil {
		panic(err)
	}
	selected, err := proxy(target)
	if err != nil {
		panic(err)
	}
	fmt.Println(selected.Scheme, selected.Host)
	// Output: http proxy.example:3128
}

// TestPkarrUsesEndpointProxy mirrors upstream n0-computer/iroh#4595: when an
// endpoint is configured with WithProxy, pkarr resolver and publisher requests
// registered via WithAddressLookup route through the endpoint's proxy.
func TestPkarrUsesEndpointProxy(t *testing.T) {
	capturingProxy := func(t *testing.T) (*url.URL, <-chan string) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		reqCh := make(chan string, 2)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					line, err := bufio.NewReader(c).ReadString('\n')
					if err == nil {
						reqCh <- strings.TrimSpace(line)
					}
				}(conn)
			}
		}()
		u, err := url.Parse("http://" + ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return u, reqCh
	}

	t.Run("resolver", func(t *testing.T) {
		proxyURL, reqCh := capturingProxy(t)
		res, err := NewPkarrResolver("https://pkarr.test/pkarr", nil)
		if err != nil {
			t.Fatal(err)
		}
		var svcs AddressLookupServices
		svcs.AddResolver(res)

		ep, err := Bind(t.Context(), WithProxy(ProxyURL(proxyURL)), WithAddressLookup(&svcs))
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Shutdown(context.Background())

		sk, _ := key.GenerateSecretKey()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for range svcs.Resolve(ctx, sk.Public().EndpointID()) {
			break
		}

		select {
		case line := <-reqCh:
			if !strings.HasPrefix(line, "CONNECT pkarr.test:443 ") {
				t.Fatalf("proxy received %q, want CONNECT pkarr.test:443", line)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("proxy did not receive pkarr resolver request")
		}
	})

	t.Run("publisher", func(t *testing.T) {
		proxyURL, reqCh := capturingProxy(t)
		sk, _ := key.GenerateSecretKey()
		pub, err := NewPkarrPublisher(sk, "https://pkarr.test/pkarr", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer pub.Close()
		var svcs AddressLookupServices
		svcs.AddPublisher(pub)

		ep, err := Bind(t.Context(), WithProxy(ProxyURL(proxyURL)), WithAddressLookup(&svcs))
		if err != nil {
			t.Fatal(err)
		}
		defer ep.Shutdown(context.Background())

		relayU, _ := netaddr.ParseRelayURL("https://relay.example")
		pub.Publish(dns.NewEndpointData(netaddr.RelayAddr{URL: relayU}))

		select {
		case line := <-reqCh:
			if !strings.HasPrefix(line, "CONNECT pkarr.test:443 ") {
				t.Fatalf("proxy received %q, want CONNECT pkarr.test:443", line)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("proxy did not receive pkarr publisher request")
		}
	})
}

func TestWithProxyRedactsCredentialsInError(t *testing.T) {
	badProxy, err := url.Parse("socks5://proxy-user:s3cret@proxy.example:1080")
	if err != nil {
		t.Fatal(err)
	}
	var c config
	if err := WithProxy(ProxyURL(badProxy))(&c); err != nil {
		t.Fatal(err)
	}
	_, err = c.proxy(&url.URL{Scheme: "https", Host: "relay.example"})
	if err == nil {
		t.Fatal("expected invalid proxy URL error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error leaked password: %v", err)
	}
	if !strings.Contains(err.Error(), "proxy-user:") {
		t.Fatalf("error = %q, want redacted URL preserving username", err)
	}
}
