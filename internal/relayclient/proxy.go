package relayclient

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tmc/go-iroh/internal/proxyurl"
)

// dialProxy opens a CONNECT tunnel to target. TLS to the relay is performed by
// the caller so relay authentication is derived from the tunneled TLS session.
func dialProxy(ctx context.Context, proxy *url.URL, target string, relayTLS *tls.Config) (net.Conn, error) {
	if err := proxyurl.Validate(proxy); err != nil {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	scheme := strings.ToLower(proxy.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxy.Scheme)
	}
	port := proxy.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("invalid proxy port %q", port)
	}
	proxyAddr := net.JoinHostPort(proxy.Hostname(), port)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()

	if scheme == "https" {
		// Rust uses the relay TLS connector for the proxy TLS layer too.
		proxyTLS := &tls.Config{}
		if relayTLS != nil {
			proxyTLS = relayTLS.Clone()
		}
		proxyTLS.ServerName = proxy.Hostname()
		tlsConn := tls.Client(conn, proxyTLS)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("proxy TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			stopCancel()
			return nil, fmt.Errorf("set proxy deadline: %w", err)
		}
	}
	authority := target
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", authority, authority); err != nil {
		stopCancel()
		return nil, fmt.Errorf("write CONNECT request: %w", err)
	}
	if proxy.User != nil {
		password, _ := proxy.User.Password()
		credentials := proxy.User.Username() + ":" + password
		if _, err := fmt.Fprintf(conn, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(credentials))); err != nil {
			stopCancel()
			return nil, fmt.Errorf("write proxy authorization: %w", err)
		}
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		stopCancel()
		return nil, fmt.Errorf("finish CONNECT request: %w", err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		stopCancel()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		stopCancel()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	if !stopCancel() {
		return nil, ctx.Err()
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear proxy deadline: %w", err)
	}
	if reader.Buffered() > 0 {
		conn = &bufferedConn{Conn: conn, reader: reader}
	}
	ok = true
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
