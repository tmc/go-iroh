// Package relayclient implements the client side of an iroh relay connection.
//
// A client dials a relay server over a secure WebSocket (standard WebPKI TLS,
// wire-compatible with iroh), negotiates the relay protocol version, completes
// the authentication handshake, and then exchanges relay frames
// ([relayproto.ClientToRelayMsg] / [relayproto.RelayToClientMsg]).
//
// It is a port of the client side of iroh-relay/src/client.
package relayclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// relayPath is the HTTP path of the relay WebSocket endpoint.
const relayPath = "/relay"

// maxFrameSize is the maximum relay frame size (1 MiB), matching MAX_FRAME_SIZE.
const maxFrameSize = 1024 * 1024

// Errors returned when connecting to a relay.
var (
	ErrBadVersionHeader = errors.New("relayclient: relay returned an unsupported protocol version")
	ErrHandshake        = errors.New("relayclient: handshake failed")
)

// Options configures a relay client dial.
type Options struct {
	// SecretKey is the client's secret key, used for the authentication
	// handshake. Required.
	SecretKey key.SecretKey
	// TLSConfig overrides the TLS configuration used for the WSS connection.
	// If nil, the default WebPKI verification is used.
	TLSConfig *tls.Config
	// HTTPClient overrides the HTTP client used for the WebSocket dial.
	HTTPClient *http.Client
	// Proxy selects an HTTP proxy for the relay connection. Nil disables
	// proxying.
	Proxy func(*url.URL) (*url.URL, error)
	// AuthToken, if set, is sent as a Bearer token in the Authorization header.
	AuthToken string
}

// Client is a connected relay client. It is not safe for concurrent use by
// multiple senders or multiple receivers; use one goroutine for Send and one
// for Recv.
type Client struct {
	conn    *websocket.Conn
	version relayproto.ProtocolVersion
	url     netaddr.RelayURL
	rd      relayproto.FrameReader
	wmu     sync.Mutex
	wbuf    []byte
}

// Connect dials the relay at u and completes the protocol handshake.
func Connect(ctx context.Context, u netaddr.RelayURL, opts Options) (*Client, error) {
	dialURL, err := websocketURL(u)
	if err != nil {
		return nil, err
	}

	header := http.Header{}
	if opts.AuthToken != "" {
		header.Set("Authorization", "Bearer "+opts.AuthToken)
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = keyMaterialHTTPClient(opts.SecretKey, opts.TLSConfig, opts.Proxy)
	}

	conn, resp, err := websocket.Dial(ctx, dialURL, dialOptions(httpClient, header))
	if err != nil {
		return nil, fmt.Errorf("relayclient: dial %s: %w", dialURL, err)
	}
	conn.SetReadLimit(maxFrameSize)

	version, ok := relayproto.ParseProtocolVersion(resp.Header.Get("Sec-WebSocket-Protocol"))
	if !ok {
		// coder/websocket also exposes the negotiated subprotocol on the conn.
		version, ok = relayproto.ParseProtocolVersion(conn.Subprotocol())
	}
	if !ok {
		conn.Close(websocket.StatusProtocolError, "bad version")
		return nil, fmt.Errorf("%w: %q", ErrBadVersionHeader, resp.Header.Get("Sec-WebSocket-Protocol"))
	}

	c := &Client{conn: conn, version: version, url: u}
	if err := c.handshake(ctx, opts.SecretKey); err != nil {
		conn.Close(websocket.StatusInternalError, "handshake failed")
		return nil, err
	}
	return c, nil
}

func keyMaterialHTTPClient(sk key.SecretKey, config *tls.Config, proxy func(*url.URL) (*url.URL, error)) *http.Client {
	return &http.Client{Transport: keyMaterialTransport{secretKey: sk, tlsConfig: config, proxy: proxy}}
}

type keyMaterialTransport struct {
	secretKey key.SecretKey
	tlsConfig *tls.Config
	proxy     func(*url.URL) (*url.URL, error)
}

func (t keyMaterialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	tr := &http.Transport{TLSClientConfig: t.tlsConfig}
	if t.proxy != nil {
		// Plain HTTP relay URLs do not use the key-material TLS dialer, so let
		// net/http send those requests through its ordinary HTTP proxy path.
		// HTTPS relays use the custom CONNECT tunnel below.
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			if req.URL.Scheme != "http" {
				return nil, nil
			}
			return t.proxy(req.URL)
		}
	}
	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		tlsConfig := t.tlsConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		if tlsConfig.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			tlsConfig.ServerName = host
		}
		var conn net.Conn
		var err error
		if t.proxy != nil {
			target := &url.URL{Scheme: "https", Host: addr}
			proxy, proxyErr := t.proxy(target)
			if proxyErr != nil {
				return nil, fmt.Errorf("relayclient: select proxy for %s: %w", target, proxyErr)
			}
			if proxy != nil {
				conn, err = dialProxy(ctx, proxy, addr, tlsConfig)
				if err == nil {
					tlsConn := tls.Client(conn, tlsConfig)
					if err = tlsConn.HandshakeContext(ctx); err != nil {
						conn.Close()
					} else {
						conn = tlsConn
					}
				}
			} else {
				dialer := tls.Dialer{Config: tlsConfig}
				conn, err = dialer.DialContext(ctx, network, addr)
			}
		} else {
			dialer := tls.Dialer{Config: tlsConfig}
			conn, err = dialer.DialContext(ctx, network, addr)
		}
		if err != nil {
			return nil, fmt.Errorf("relayclient: dial %s: %w", addr, err)
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			return conn, nil
		}
		state := tlsConn.ConnectionState()
		if auth, err := relayproto.NewKeyMaterialClientAuth(t.secretKey, &state); err == nil {
			if value, err := auth.HeaderValue(); err == nil {
				req.Header.Set(relayproto.ClientAuthHeader, value)
			}
		}
		return tlsConn, nil
	}
	return tr.RoundTrip(req)
}

// Version returns the negotiated relay protocol version.
func (c *Client) Version() relayproto.ProtocolVersion { return c.version }

// Send sends a client-to-relay message.
func (c *Client) Send(ctx context.Context, msg relayproto.ClientToRelayMsg) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.wbuf = msg.AppendTo(c.wbuf[:0])
	return c.conn.Write(ctx, websocket.MessageBinary, c.wbuf)
}

// Recv receives the next relay-to-client message.
func (c *Client) Recv(ctx context.Context) (relayproto.RelayToClientMsg, error) {
	data, err := c.rd.Read(ctx, c.conn)
	if err != nil {
		return relayproto.RelayToClientMsg{}, err
	}
	msg, err := relayproto.ParseRelayToClientMsgNoCopy(data, c.version)
	if err != nil {
		return msg, err
	}
	// rd reuses its buffer and datagrams outlive this call.
	if msg.Type == relayproto.FrameRelayToClientDatagram || msg.Type == relayproto.FrameRelayToClientDatagramBat {
		msg.Datagrams = msg.Datagrams.Pooled()
	}
	return msg, nil
}

// Close closes the relay connection.
func (c *Client) Close() error {
	return c.conn.Close(websocket.StatusNormalClosure, "")
}

// handshake runs the challenge-based authentication handshake. The relay sends a
// ServerChallenge, the client replies with a signed ClientAuth, and the relay
// responds with ServerConfirmsAuth or ServerDeniesAuth.
func (c *Client) handshake(ctx context.Context, sk key.SecretKey) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	frame, err := c.readFrame(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading challenge: %v", ErrHandshake, err)
	}

	switch f := frame.(type) {
	case *relayproto.ServerChallenge:
		auth := relayproto.NewClientAuth(sk, *f)
		if err := c.writeFrame(ctx, auth.AppendTo(nil)); err != nil {
			return fmt.Errorf("%w: sending client auth: %v", ErrHandshake, err)
		}
		return c.expectConfirmation(ctx)
	case *relayproto.ServerConfirmsAuth:
		return nil
	case *relayproto.ServerDeniesAuth:
		return fmt.Errorf("%w: %s", relayproto.ErrServerDeniedAuth, f.Reason)
	default:
		return fmt.Errorf("%w: unexpected first frame %T", ErrHandshake, frame)
	}
}

func (c *Client) expectConfirmation(ctx context.Context) error {
	frame, err := c.readFrame(ctx)
	if err != nil {
		return fmt.Errorf("%w: reading confirmation: %v", ErrHandshake, err)
	}
	switch f := frame.(type) {
	case *relayproto.ServerConfirmsAuth:
		return nil
	case *relayproto.ServerDeniesAuth:
		return fmt.Errorf("%w: %s", relayproto.ErrServerDeniedAuth, f.Reason)
	default:
		return fmt.Errorf("%w: unexpected frame %T", ErrHandshake, frame)
	}
}

func (c *Client) readFrame(ctx context.Context) (any, error) {
	_, data, err := c.conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	return relayproto.ParseHandshakeFrame(data)
}

func (c *Client) writeFrame(ctx context.Context, data []byte) error {
	return c.conn.Write(ctx, websocket.MessageBinary, data)
}

// websocketURL converts a relay URL (http/https) into the ws/wss dial URL with
// the relay path, matching the Rust client.
func websocketURL(u netaddr.RelayURL) (string, error) {
	parsed := u.URL()
	if parsed == nil {
		return "", errors.New("relayclient: empty relay url")
	}
	dial := *parsed
	dial.Path = relayPath
	switch strings.ToLower(dial.Scheme) {
	case "http", "ws":
		dial.Scheme = "ws"
	default:
		dial.Scheme = "wss"
	}
	return dial.String(), nil
}

var _ = url.URL{}
