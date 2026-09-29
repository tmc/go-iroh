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
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// fakeRelay is a minimal in-process relay server speaking enough of the protocol
// to test the client: it accepts the WS upgrade, sends a challenge, verifies the
// client's auth, confirms, then echoes one datagram back as a relay-to-client
// datagram.
func fakeRelay(t *testing.T, deny bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(fakeRelayHandler(t, deny, nil))
}

func fakeRelayTLS(t *testing.T, keyMaterialSeen *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(fakeRelayHandler(t, false, keyMaterialSeen))
}

func fakeRelayHandler(t *testing.T, deny bool, keyMaterialSeen *atomic.Bool) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		if keyMaterialSeen != nil {
			if r.Header.Get(relayproto.ClientAuthHeader) == "" {
				t.Error("relay request missing key-material auth header")
			} else {
				keyMaterialSeen.Store(true)
			}
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: relayproto.SupportedProtocolVersions(),
		})
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		defer conn.Close(websocket.StatusNormalClosure, "")

		// Send challenge.
		var challenge relayproto.ServerChallenge
		for i := range challenge.Challenge {
			challenge.Challenge[i] = byte(i + 1)
		}
		if err := conn.Write(ctx, websocket.MessageBinary, challenge.AppendTo(nil)); err != nil {
			return
		}

		// Read client auth.
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		frame, err := relayproto.ParseHandshakeFrame(data)
		if err != nil {
			t.Errorf("parse client auth: %v", err)
			return
		}
		auth, ok := frame.(*relayproto.ClientAuth)
		if !ok {
			t.Errorf("expected ClientAuth, got %T", frame)
			return
		}
		if err := auth.Verify(challenge); err != nil {
			t.Errorf("client auth verify: %v", err)
			return
		}

		if deny {
			conn.Write(ctx, websocket.MessageBinary, relayproto.ServerDeniesAuth{Reason: "nope"}.AppendTo(nil))
			return
		}
		// Confirm.
		if err := conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil)); err != nil {
			return
		}

		// Echo loop: turn a client datagram into a relay-to-client datagram.
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			msg, err := relayproto.ParseClientToRelayMsg(data)
			if err != nil {
				return
			}
			if msg.Type == relayproto.FrameClientToRelayDatagram || msg.Type == relayproto.FrameClientToRelayDatagramBat {
				reply := relayproto.RelayToClientMsg{
					Type:             relayproto.FrameRelayToClientDatagram,
					RemoteEndpointID: msg.DstEndpointID,
					Datagrams:        msg.Datagrams,
				}
				conn.Write(ctx, websocket.MessageBinary, reply.AppendTo(nil))
			}
		}
	})
	return mux
}

func TestClientConnectThroughProxy(t *testing.T) {
	var keyMaterialSeen atomic.Bool
	relayServer := fakeRelayTLS(t, &keyMaterialSeen)
	defer relayServer.Close()

	var proxyMu sync.Mutex
	var connectTarget, proxyAuth string
	proxy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyMu.Lock()
		connectTarget = r.Host
		proxyAuth = r.Header.Get("Proxy-Authorization")
		proxyMu.Unlock()
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, "dial target", http.StatusBadGateway)
			return
		}
		client, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			upstream.Close()
			t.Errorf("hijack proxy connection: %v", err)
			return
		}
		fmt.Fprint(rw, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if err := rw.Flush(); err != nil {
			upstream.Close()
			client.Close()
			return
		}
		go func() {
			defer upstream.Close()
			defer client.Close()
			io.Copy(upstream, rw.Reader)
		}()
		io.Copy(client, upstream)
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("proxy-user", "proxy-secret")
	sk, _ := key.GenerateSecretKey()
	client, err := Connect(context.Background(), relayURL(t, relayServer), Options{
		SecretKey: sk,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:     func(*url.URL) (*url.URL, error) { return proxyURL, nil },
	})
	if err != nil {
		t.Fatalf("Connect through proxy: %v", err)
	}
	client.Close()

	proxyMu.Lock()
	defer proxyMu.Unlock()
	if connectTarget != strings.TrimPrefix(relayServer.URL, "https://") {
		t.Errorf("CONNECT target = %q, want %q", connectTarget, strings.TrimPrefix(relayServer.URL, "https://"))
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-secret"))
	if proxyAuth != wantAuth {
		t.Errorf("Proxy-Authorization = %q, want %q", proxyAuth, wantAuth)
	}
	if !keyMaterialSeen.Load() {
		t.Error("relay did not receive key-material auth from tunneled TLS session")
	}
}

func TestClientProxyFailureDoesNotLeakCredentials(t *testing.T) {
	relayServer := fakeRelayTLS(t, nil)
	defer relayServer.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "credentials rejected", http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("proxy-user", "proxy-secret")
	sk, _ := key.GenerateSecretKey()
	_, err = Connect(context.Background(), relayURL(t, relayServer), Options{
		SecretKey: sk,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:     func(*url.URL) (*url.URL, error) { return proxyURL, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("Connect error = %v, want proxy status 407", err)
	}
	if strings.Contains(err.Error(), "proxy-secret") {
		t.Fatalf("Connect error leaked proxy password: %v", err)
	}
}

func TestDialProxyPreservesBufferedTunnelBytes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				done <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\nhello")
		done <- err
	}()

	proxyURL, err := url.Parse("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialProxy(context.Background(), proxyURL, "relay.example:443", nil)
	if err != nil {
		t.Fatalf("dialProxy: %v", err)
	}
	defer conn.Close()
	if _, ok := conn.(*bufferedConn); !ok {
		t.Fatalf("connection = %T, want bufferedConn", conn)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read tunnel bytes: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("tunnel bytes = %q, want hello", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("proxy: %v", err)
	}
}

func relayURL(t *testing.T, ts *httptest.Server) netaddr.RelayURL {
	t.Helper()
	u, err := netaddr.ParseRelayURL(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestClientConnectAndEcho(t *testing.T) {
	ts := fakeRelay(t, false)
	defer ts.Close()

	sk, _ := key.GenerateSecretKey()
	ctx := context.Background()
	c, err := Connect(ctx, relayURL(t, ts), Options{SecretKey: sk})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	// Send a datagram destined for some peer.
	dst, _ := key.GenerateSecretKey()
	payload := []byte("hello relay")
	err = c.Send(ctx, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: dst.Public().EndpointID(),
		Datagrams:     relayproto.DatagramsFromBytes(payload),
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}

	msg, err := c.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if msg.Type != relayproto.FrameRelayToClientDatagram {
		t.Fatalf("got frame %s, want RelayToClientDatagram", msg.Type)
	}
	if string(msg.Datagrams.Contents) != string(payload) {
		t.Errorf("echo = %q, want %q", msg.Datagrams.Contents, payload)
	}
	if !msg.RemoteEndpointID.Equal(dst.Public().EndpointID()) {
		t.Error("remote endpoint id mismatch")
	}
}

func TestClientHandshakeDenied(t *testing.T) {
	ts := fakeRelay(t, true)
	defer ts.Close()

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if err == nil {
		t.Fatal("expected handshake denial error")
	}
	if !strings.Contains(err.Error(), "denied") && !strings.Contains(err.Error(), "nope") {
		t.Errorf("error = %v, want denial", err)
	}
}

func TestWebsocketURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://relay.example.com", "wss://relay.example.com/relay"},
		{"http://localhost:8080", "ws://localhost:8080/relay"},
	}
	for _, c := range cases {
		u, err := netaddr.ParseRelayURL(c.in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := websocketURL(u)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("websocketURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
