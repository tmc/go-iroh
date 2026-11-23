package relayclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/internal/relayproto"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// scriptRelay is a configurable in-process relay server. The handler runs after
// a successful WebSocket upgrade and drives whatever server-side behavior a test
// needs; the bool returned by the optional authHook gates the upgrade. It lets
// the error-path tests exercise the handshake state machine without mocking the
// websocket transport.
type scriptRelay struct {
	// subprotocols offered by the server for negotiation. Defaults to the
	// supported set; set to a non-matching list to force a version mismatch.
	subprotocols []string
	// onUpgrade inspects the upgrade request before Accept; returning false
	// makes the server reject with 401 (used for auth-header assertions).
	onUpgrade func(r *http.Request) bool
	// run drives the post-upgrade conversation.
	run func(t *testing.T, ctx context.Context, conn *websocket.Conn)
}

func (s scriptRelay) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		if s.onUpgrade != nil && !s.onUpgrade(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		subs := s.subprotocols
		if subs == nil {
			subs = relayproto.SupportedProtocolVersions()
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: subs})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		defer conn.Close(websocket.StatusNormalClosure, "")
		if s.run != nil {
			s.run(t, ctx, conn)
		}
	})
	return httptest.NewServer(mux)
}

func newScriptServer(t *testing.T, s scriptRelay) *httptest.Server {
	t.Helper()
	ts := s.server(t)
	t.Cleanup(ts.Close)
	return ts
}

// sendChallenge writes the canonical fixed challenge used by the fake relay.
func sendChallenge(ctx context.Context, conn *websocket.Conn) error {
	var challenge relayproto.ServerChallenge
	for i := range challenge.Challenge {
		challenge.Challenge[i] = byte(i + 1)
	}
	return conn.Write(ctx, websocket.MessageBinary, challenge.AppendTo(nil))
}

func TestClientVersion(t *testing.T) {
	ts := fakeRelay(t, false)
	defer ts.Close()

	sk, _ := key.GenerateSecretKey()
	c, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	// The client offers V2 first and the fake relay supports it, so V2 is
	// negotiated. iroh-relay/src/protos: protocol versions are V1/V2.
	if got := c.Version(); got != relayproto.ProtocolV2 {
		t.Errorf("Version() = %v, want %v", got, relayproto.ProtocolV2)
	}
}

func TestConnectInvalidURL(t *testing.T) {
	// The zero RelayURL has a nil underlying URL, so websocketURL fails before
	// any dial is attempted.
	_, err := Connect(context.Background(), netaddr.RelayURL{}, Options{})
	if err == nil {
		t.Fatal("expected error for empty relay url")
	}
	if !strings.Contains(err.Error(), "empty relay url") {
		t.Errorf("error = %v, want 'empty relay url'", err)
	}
}

func TestConnectAuthTokenHeader(t *testing.T) {
	var gotAuth string
	ts := newScriptServer(t, scriptRelay{
		onUpgrade: func(r *http.Request) bool {
			gotAuth = r.Header.Get("Authorization")
			return true
		},
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			if err := sendChallenge(ctx, conn); err != nil {
				return
			}
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
			conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil))
		},
	})

	sk, _ := key.GenerateSecretKey()
	c, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk, AuthToken: "token123"})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	if want := "Bearer token123"; gotAuth != want {
		t.Errorf("Authorization header = %q, want %q", gotAuth, want)
	}
}

func TestConnectTLSConfig(t *testing.T) {
	// Build the same conversation as fakeRelay but over an httptest TLS server,
	// then route the client dial through opts.TLSConfig trusting that server's
	// cert. This exercises the httpClient-from-TLSConfig branch in Connect.
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: relayproto.SupportedProtocolVersions(),
		})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		defer conn.Close(websocket.StatusNormalClosure, "")
		if err := sendChallenge(ctx, conn); err != nil {
			return
		}
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// Trust the httptest server's self-signed certificate.
	certPool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tlsConfig := &tls.Config{RootCAs: certPool}

	u := relayURL(t, ts) // https:// URL -> wss:// dial
	sk, _ := key.GenerateSecretKey()
	c, err := Connect(context.Background(), u, Options{SecretKey: sk, TLSConfig: tlsConfig})
	if err != nil {
		t.Fatalf("Connect over TLS: %v", err)
	}
	defer c.Close()
	if got := c.Version(); got != relayproto.ProtocolV2 {
		t.Errorf("Version() = %v, want V2", got)
	}
}

func TestConnectTLSKeyMaterialAuthHeader(t *testing.T) {
	var gotHeader string
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(relayproto.ClientAuthHeader)
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: relayproto.SupportedProtocolVersions(),
		})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		defer conn.Close(websocket.StatusNormalClosure, "")
		conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	certPool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tlsConfig := &tls.Config{RootCAs: certPool}
	sk, _ := key.GenerateSecretKey()
	c, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk, TLSConfig: tlsConfig})
	if err != nil {
		t.Fatalf("Connect over TLS: %v", err)
	}
	defer c.Close()
	if gotHeader == "" {
		t.Fatal("missing key-material auth header")
	}
	auth, err := relayproto.KeyMaterialClientAuthFromHeader(gotHeader)
	if err != nil {
		t.Fatalf("decode key-material auth header: %v", err)
	}
	if !auth.PublicKey.Equal(sk.Public()) {
		t.Fatalf("auth public key = %s, want %s", auth.PublicKey, sk.Public())
	}
}

func TestConnectDialFails(t *testing.T) {
	// Start then immediately close a server so its address refuses connections.
	ts := fakeRelay(t, false)
	u := relayURL(t, ts)
	ts.Close()

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), u, Options{SecretKey: sk})
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !strings.Contains(err.Error(), "dial") {
		t.Errorf("error = %v, want dial error", err)
	}
}

func TestConnectBadVersionHeader(t *testing.T) {
	// The server offers a subprotocol the client never requested, so negotiation
	// settles on the empty subprotocol; neither the response header nor
	// conn.Subprotocol() parse, and Connect must close and report
	// ErrBadVersionHeader.
	ts := newScriptServer(t, scriptRelay{
		subprotocols: []string{"some-other-proto"},
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			// Block until the client closes after the version error.
			conn.Read(ctx)
		},
	})

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, ErrBadVersionHeader) {
		t.Fatalf("error = %v, want ErrBadVersionHeader", err)
	}
}

func TestRecvReadError(t *testing.T) {
	// Complete the handshake, then have the server abruptly close so the next
	// Recv hits a read error.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			if err := sendChallenge(ctx, conn); err != nil {
				return
			}
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
			conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil))
			conn.Close(websocket.StatusGoingAway, "bye")
		},
	})

	sk, _ := key.GenerateSecretKey()
	c, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()

	if _, err := c.Recv(context.Background()); err == nil {
		t.Fatal("expected Recv error after server close")
	}
}

func TestHandshakeChallengeReadError(t *testing.T) {
	// Server closes before sending the challenge: handshake's first readFrame
	// fails and is wrapped as ErrHandshake.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			conn.Close(websocket.StatusGoingAway, "no challenge")
		},
	})

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("error = %v, want ErrHandshake", err)
	}
	if !strings.Contains(err.Error(), "reading challenge") {
		t.Errorf("error = %v, want 'reading challenge'", err)
	}
}

func TestHandshakeSignsChallenge(t *testing.T) {
	// Verify the ClientAuth the client sends actually verifies against the
	// challenge (blake3-derived message-to-sign). This asserts the signing
	// branch of handshake end-to-end.
	var (
		challenge   relayproto.ServerChallenge
		verifyErr   error
		gotPubKey   key.PublicKey
		expectedKey key.PublicKey
	)
	for i := range challenge.Challenge {
		challenge.Challenge[i] = byte(0xA0 + i)
	}
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			if err := conn.Write(ctx, websocket.MessageBinary, challenge.AppendTo(nil)); err != nil {
				return
			}
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			frame, err := relayproto.ParseHandshakeFrame(data)
			if err != nil {
				verifyErr = err
				return
			}
			auth, ok := frame.(*relayproto.ClientAuth)
			if !ok {
				verifyErr = fmt.Errorf("got %T, want *ClientAuth", frame)
				return
			}
			gotPubKey = auth.PublicKey
			verifyErr = auth.Verify(challenge)
			conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil))
		},
	})

	sk, _ := key.GenerateSecretKey()
	expectedKey = sk.Public()
	c, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()
	if verifyErr != nil {
		t.Fatalf("server-side ClientAuth verify: %v", verifyErr)
	}
	if !gotPubKey.Equal(expectedKey) {
		t.Error("ClientAuth public key did not match client secret key")
	}
}

func TestHandshakeWriteError(t *testing.T) {
	// Server sends the challenge then immediately closes, so the client's
	// writeFrame of ClientAuth fails and is wrapped as ErrHandshake.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			sendChallenge(ctx, conn)
			conn.Close(websocket.StatusGoingAway, "gone")
		},
	})

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("error = %v, want ErrHandshake", err)
	}
}

func TestHandshakeConfirmsWithoutChallenge(t *testing.T) {
	// Relay confirms immediately (no challenge); handshake returns nil and the
	// connection is usable.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil))
			conn.Read(ctx)
		},
	})

	sk, _ := key.GenerateSecretKey()
	c, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer c.Close()
}

func TestHandshakeDeniesWithoutChallenge(t *testing.T) {
	// Relay denies immediately (no challenge); Connect returns ErrServerDeniedAuth.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			conn.Write(ctx, websocket.MessageBinary, relayproto.ServerDeniesAuth{Reason: "go away"}.AppendTo(nil))
		},
	})

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, relayproto.ErrServerDeniedAuth) {
		t.Fatalf("error = %v, want ErrServerDeniedAuth", err)
	}
	if !strings.Contains(err.Error(), "go away") {
		t.Errorf("error = %v, want reason 'go away'", err)
	}
}

func TestHandshakeUnexpectedFirstFrame(t *testing.T) {
	// Relay's first frame is a ClientAuth (which the client should never receive
	// in the challenge slot); handshake reports ErrHandshake.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			sk, _ := key.GenerateSecretKey()
			var ch relayproto.ServerChallenge
			bogus := relayproto.NewClientAuth(sk, ch)
			conn.Write(ctx, websocket.MessageBinary, bogus.AppendTo(nil))
		},
	})

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("error = %v, want ErrHandshake", err)
	}
	if !strings.Contains(err.Error(), "unexpected first frame") {
		t.Errorf("error = %v, want 'unexpected first frame'", err)
	}
}

func TestExpectConfirmationReadError(t *testing.T) {
	// Relay sends a challenge, reads the client's auth, then closes before
	// confirming; expectConfirmation's readFrame fails as ErrHandshake.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			if err := sendChallenge(ctx, conn); err != nil {
				return
			}
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
			conn.Close(websocket.StatusGoingAway, "no confirmation")
		},
	})

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("error = %v, want ErrHandshake", err)
	}
	if !strings.Contains(err.Error(), "reading confirmation") {
		t.Errorf("error = %v, want 'reading confirmation'", err)
	}
}

func TestExpectConfirmationDenied(t *testing.T) {
	// fakeRelay(deny=true) sends a challenge, reads the auth, then denies in the
	// confirmation phase; Connect returns ErrServerDeniedAuth.
	ts := fakeRelay(t, true)
	defer ts.Close()

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, relayproto.ErrServerDeniedAuth) {
		t.Fatalf("error = %v, want ErrServerDeniedAuth", err)
	}
}

func TestExpectConfirmationUnexpectedFrame(t *testing.T) {
	// Relay sends a challenge, reads the auth, then sends another challenge in
	// the confirmation slot; expectConfirmation reports ErrHandshake.
	ts := newScriptServer(t, scriptRelay{
		run: func(t *testing.T, ctx context.Context, conn *websocket.Conn) {
			if err := sendChallenge(ctx, conn); err != nil {
				return
			}
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
			sendChallenge(ctx, conn) // a ServerChallenge is not a valid confirmation
		},
	})

	sk, _ := key.GenerateSecretKey()
	_, err := Connect(context.Background(), relayURL(t, ts), Options{SecretKey: sk})
	if !errors.Is(err, ErrHandshake) {
		t.Fatalf("error = %v, want ErrHandshake", err)
	}
	if !strings.Contains(err.Error(), "unexpected frame") {
		t.Errorf("error = %v, want 'unexpected frame'", err)
	}
}

func TestWebsocketURLPath(t *testing.T) {
	// The dial URL joins "relay" onto the relay URL's path prefix, and the
	// scheme maps http->ws, https->wss. Matches iroh-relay PR #4617.
	cases := []struct{ in, want string }{
		{"https://relay.example.com", "wss://relay.example.com/relay"},
		{"https://relay.example.com/", "wss://relay.example.com/relay"},
		{"https://relay.example.com/prefix", "wss://relay.example.com/prefix/relay"},
		{"https://relay.example.com/prefix/", "wss://relay.example.com/prefix/relay"},
		{"http://localhost:8080/foo/bar", "ws://localhost:8080/foo/bar/relay"},
		{"http://localhost:8080/foo/bar/", "ws://localhost:8080/foo/bar/relay"},
		{"ws://relay.example.com", "ws://relay.example.com/relay"},
		{"wss://relay.example.com", "wss://relay.example.com/relay"},
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

func TestWebsocketURLEmpty(t *testing.T) {
	_, err := websocketURL(netaddr.RelayURL{})
	if err == nil {
		t.Fatal("expected error for empty relay url")
	}
	if !strings.Contains(err.Error(), "empty relay url") {
		t.Errorf("error = %v, want 'empty relay url'", err)
	}
}

// Example shows the typical client lifecycle: connect to a relay, exchange a
// datagram with a peer, then close the connection.
func ExampleClient() {
	ts := exampleRelay()
	defer ts.Close()

	u, _ := netaddr.ParseRelayURL(ts.URL)
	sk, _ := key.GenerateSecretKey()

	ctx := context.Background()
	c, err := Connect(ctx, u, Options{SecretKey: sk})
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer c.Close()

	peer, _ := key.GenerateSecretKey()
	if err := c.Send(ctx, relayproto.ClientToRelayMsg{
		Type:          relayproto.FrameClientToRelayDatagram,
		DstEndpointID: peer.Public().EndpointID(),
		Datagrams:     relayproto.DatagramsFromBytes([]byte("ping")),
	}); err != nil {
		fmt.Println("send:", err)
		return
	}

	msg, err := c.Recv(ctx)
	if err != nil {
		fmt.Println("recv:", err)
		return
	}
	fmt.Printf("version=%d echoed=%q\n", c.Version(), msg.Datagrams.Contents)
	// Output: version=2 echoed="ping"
}

// exampleRelay is a minimal echoing relay used by the runnable example. It
// mirrors fakeRelay but does not depend on *testing.T.
func exampleRelay() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: relayproto.SupportedProtocolVersions(),
		})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		defer conn.Close(websocket.StatusNormalClosure, "")

		var ch relayproto.ServerChallenge
		for i := range ch.Challenge {
			ch.Challenge[i] = byte(i + 1)
		}
		if err := conn.Write(ctx, websocket.MessageBinary, ch.AppendTo(nil)); err != nil {
			return
		}
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		if err := conn.Write(ctx, websocket.MessageBinary, relayproto.ServerConfirmsAuth{}.AppendTo(nil)); err != nil {
			return
		}
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			msg, err := relayproto.ParseClientToRelayMsg(data)
			if err != nil {
				return
			}
			reply := relayproto.RelayToClientMsg{
				Type:             relayproto.FrameRelayToClientDatagram,
				RemoteEndpointID: msg.DstEndpointID,
				Datagrams:        msg.Datagrams,
			}
			conn.Write(ctx, websocket.MessageBinary, reply.AppendTo(nil))
		}
	})
	return httptest.NewServer(mux)
}
