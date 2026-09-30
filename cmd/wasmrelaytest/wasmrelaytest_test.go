//go:build !js

package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
	"github.com/tmc/go-iroh/relayserver"
)

func TestBrowserRelayOnlyEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ts := newWASMRelayServer(t, ctx)
	defer ts.Close()

	page := ts.URL + "/?relay=" + url.QueryEscape(ts.URL+"/")
	status, detail, err := runHeadless(ctx, t, page)
	if err != nil {
		t.Fatalf("headless browser: %v", err)
	}
	if status != "pass" {
		t.Fatalf("browser relay echo status=%q detail=%q", status, detail)
	}
}

func TestBrowserNativeRelayOnlyEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ts := newWASMRelayServer(t, ctx)
	defer ts.Close()
	relayURL, err := netaddr.ParseRelayURL(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	const alpn = "iroh-wasm-native/2"
	server, err := iroh.Bind(ctx,
		iroh.WithALPNs(alpn),
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAliveNative()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(ctx)
	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}

	errc := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err != nil {
			errc <- err
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			errc <- err
			return
		}
		errc <- serveFramesNative(ctx, stream)
	}()

	q := url.Values{
		"relay": {ts.URL + "/"},
		"mode":  {"browser-native"},
		"peer":  {server.ID().String()},
	}
	status, detail, err := runHeadless(ctx, t, ts.URL+"/?"+q.Encode())
	if err != nil {
		t.Fatalf("headless browser: %v", err)
	}
	if status != "pass" {
		t.Fatalf("browser native relay echo status=%q detail=%q", status, detail)
	}
	if err := <-errc; err != nil {
		t.Fatalf("native server: %v", err)
	}
}

func TestBrowserBlobRelayOnlyFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ts := newWASMRelayServer(t, ctx)
	defer ts.Close()
	relayURL, err := netaddr.ParseRelayURL(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	const size = 70 * 1024
	data := blobPayloadNative(size)

	server, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAliveNative()),
	)
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		blobs.ALPN: iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return err
			}
			return blobs.ServeBlob(ctx, stream, mustBlobStore(t, data))
		}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)
	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}

	q := url.Values{
		"relay": {ts.URL + "/"},
		"mode":  {"blob-native"},
		"peer":  {server.ID().String()},
		"size":  {fmt.Sprint(size)},
	}
	status, detail, err := runHeadless(ctx, t, ts.URL+"/?"+q.Encode())
	if err != nil {
		t.Fatalf("headless browser: %v", err)
	}
	if status != "pass" {
		t.Fatalf("browser blob fetch status=%q detail=%q", status, detail)
	}
}

func TestBrowserDocsRelayOnlySync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ts := newWASMRelayServer(t, ctx)
	defer ts.Close()
	relayURL, err := netaddr.ParseRelayURL(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	mode := relay.ModeCustom(relay.MapFromURLs(relayURL))
	namespace := docs.NewNamespaceSecret(repeat32Native(0xb2))
	author := docs.NewAuthor(repeat32Native(0xa1))
	serverEntry := docSignedEntryNative(namespace, author, "server", "server-data", 1)

	serverStore := docs.NewMemoryStore()
	serverStore.Put(serverEntry)
	server, err := iroh.Bind(ctx,
		iroh.WithRelayMode(mode),
		iroh.WithoutIPTransports(),
		iroh.WithTransportConfig(shortKeepAliveNative()),
	)
	if err != nil {
		t.Fatal(err)
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		docs.ALPN: &docs.Handler{Store: serverStore, Allow: func(ns docs.NamespaceID, _ key.EndpointID) bool { return ns == namespace.ID() }},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)
	if err := server.Online(ctx); err != nil {
		t.Fatalf("server online: %v", err)
	}

	q := url.Values{
		"relay": {ts.URL + "/"},
		"mode":  {"docs-native"},
		"peer":  {server.ID().String()},
	}
	status, detail, err := runHeadless(ctx, t, ts.URL+"/?"+q.Encode())
	if err != nil {
		t.Fatalf("headless browser: %v", err)
	}
	if status != "pass" {
		t.Fatalf("browser docs sync status=%q detail=%q", status, detail)
	}
	if _, ok := serverStore.GetExact(namespace.ID(), author.ID(), []byte("client"), false); !ok {
		t.Fatal("server missing browser client entry")
	}
}

func TestBrowserGossipRelayOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ts := newWASMRelayServer(t, ctx)
	defer ts.Close()
	q := url.Values{
		"relay": {ts.URL + "/"},
		"mode":  {"gossip-browser"},
	}
	status, detail, err := runHeadless(ctx, t, ts.URL+"/?"+q.Encode())
	if err != nil {
		t.Fatalf("headless browser: %v", err)
	}
	if status != "pass" {
		t.Fatalf("browser gossip status=%q detail=%q", status, detail)
	}
}

func newWASMRelayServer(t *testing.T, ctx context.Context) *httptest.Server {
	t.Helper()
	tmp := t.TempDir()
	wasm := filepath.Join(tmp, "wasmrelaytest.wasm")
	build := exec.CommandContext(ctx, "go", "build", "-o", wasm, "./cmd/wasmrelaytest")
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build wasm: %v\n%s", err, out)
	}

	wasmExec := filepath.Join(runtimeRoot(t), "lib", "wasm", "wasm_exec.js")
	mux := http.NewServeMux()
	mux.Handle("/relay", relayserver.New())
	mux.HandleFunc("/wasm_exec.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, wasmExec)
	})
	mux.HandleFunc("/wasmrelaytest.wasm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		http.ServeFile(w, r, wasm)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		relay := "http://" + r.Host + "/"
		fmt.Fprintf(w, `<!doctype html>
<html><head><meta charset="utf-8"><script src="/wasm_exec.js"></script></head>
<body data-status="running">
<script>
const go = new Go();
WebAssembly.instantiateStreaming(fetch("/wasmrelaytest.wasm"), go.importObject)
  .then((result) => go.run(result.instance))
  .catch((err) => {
    document.body.textContent = String(err);
    document.body.setAttribute("data-status", "fail");
    document.body.setAttribute("data-detail", String(err));
  });
</script>
<a id="relay" href="?relay=%s"></a>
</body></html>`, html.EscapeString(url.QueryEscape(relay)))
	})
	return httptest.NewServer(mux)
}

func runHeadless(ctx context.Context, t *testing.T, page string) (string, string, error) {
	t.Helper()
	browser := browserPath(t)
	// Use a dedicated profile dir removed only after the browser has fully
	// exited, not t.TempDir(): the harness cleans t.TempDir() as soon as the
	// test returns, which races the browser still flushing its Cache_Data and
	// fails with "directory not empty".
	profile, err := os.MkdirTemp("", "wasmrelaytest-profile-")
	if err != nil {
		return "", "", err
	}
	args := []string{
		"--headless=new",
		"--disable-gpu",
		"--no-first-run",
		"--no-default-browser-check",
		"--user-data-dir=" + profile,
		"--remote-debugging-port=0",
		page,
	}
	cmd := exec.CommandContext(ctx, browser, args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		os.RemoveAll(profile)
		return "", "", err
	}
	if err := cmd.Start(); err != nil {
		os.RemoveAll(profile)
		return "", "", err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		// The browser has exited; remove its profile, retrying briefly in case
		// the OS is still releasing cache files.
		for range 10 {
			if os.RemoveAll(profile) == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	devtools, err := readDevToolsURL(ctx, stderr)
	if err != nil {
		return "", "", err
	}
	target, err := pageWebSocketURL(ctx, devtools)
	if err != nil {
		return "", "", err
	}
	return waitBrowserStatus(ctx, target)
}

func shortKeepAliveNative() *iroh.QUICTransportConfig {
	return &iroh.QUICTransportConfig{
		KeepAlivePeriod: 200 * time.Millisecond,
		MaxIdleTimeout:  5 * time.Second,
	}
}

func serveFramesNative(ctx context.Context, stream io.ReadWriteCloser) error {
	for i := 0; i < 4; i++ {
		got, err := readFrameNative(stream)
		if err != nil {
			return fmt.Errorf("server read frame %d: %w", i, err)
		}
		if want := payloadNative(i); string(got) != string(want) {
			return fmt.Errorf("server frame %d mismatch", i)
		}
		if err := writeFrameNative(stream, payloadNative(100+i)); err != nil {
			return fmt.Errorf("server write frame %d: %w", i, err)
		}
		if i == 1 {
			timer := time.NewTimer(600 * time.Millisecond)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
	}
	return stream.Close()
}

func payloadNative(seed int) []byte {
	p := make([]byte, 64*1024+seed%17)
	for i := range p {
		p[i] = byte(seed + i*31)
	}
	return p
}

func blobPayloadNative(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(11 + i*17)
	}
	return p
}

func docSignedEntryNative(namespace docs.NamespaceSecret, author docs.Author, keyName, data string, timestamp uint64) docs.SignedEntry {
	hash := blobs.NewHash([]byte(data))
	id := docs.NewRecordIdentifier(namespace.ID(), author.ID(), []byte(keyName))
	return docs.NewSignedEntry(docs.NewEntry(id, docs.NewRecord(hash, uint64(len(data)), timestamp)), namespace, author)
}

func repeat32Native(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func writeFrameNative(w io.Writer, p []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func readFrameNative(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	p := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	_, err := io.ReadFull(r, p)
	return p, err
}

func browserPath(t *testing.T) string {
	t.Helper()
	candidates := []string{
		os.Getenv("IROH_WASM_BROWSER"),
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"brave-browser",
		"google-chrome",
		"chromium",
		"chromium-browser",
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if strings.ContainsRune(c, filepath.Separator) {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				return c
			}
			continue
		}
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	t.Skip("no headless Chrome/Brave browser found")
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func runtimeRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func readDevToolsURL(ctx context.Context, r io.Reader) (string, error) {
	type result struct {
		url string
		err error
	}
	done := make(chan result, 1)
	go func() {
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			line := scan.Text()
			const prefix = "DevTools listening on "
			if i := strings.Index(line, prefix); i >= 0 {
				done <- result{url: strings.TrimSpace(line[i+len(prefix):])}
				return
			}
		}
		done <- result{err: scan.Err()}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return "", res.err
		}
		if res.url == "" {
			return "", fmt.Errorf("missing devtools url")
		}
		return res.url, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func pageWebSocketURL(ctx context.Context, devtools string) (string, error) {
	u, err := url.Parse(devtools)
	if err != nil {
		return "", err
	}
	list := url.URL{Scheme: "http", Host: u.Host, Path: "/json"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, list.String(), nil)
	if err != nil {
		return "", err
	}
	for {
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var targets []struct {
				Type                 string `json:"type"`
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			decErr := json.NewDecoder(resp.Body).Decode(&targets)
			resp.Body.Close()
			if decErr == nil {
				for _, target := range targets {
					if target.Type == "page" && target.WebSocketDebuggerURL != "" {
						return target.WebSocketDebuggerURL, nil
					}
				}
			}
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return "", ctx.Err()
		}
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, list.String(), nil)
	}
}

func waitBrowserStatus(ctx context.Context, target string) (string, string, error) {
	conn, _, err := websocket.Dial(ctx, target, nil)
	if err != nil {
		return "", "", err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	for {
		status, detail, err := browserStatus(ctx, conn)
		if err != nil {
			return "", "", err
		}
		switch status {
		case "pass", "fail":
			return status, detail, nil
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-ctx.Done():
			return "", "", ctx.Err()
		}
	}
}

func browserStatus(ctx context.Context, conn *websocket.Conn) (string, string, error) {
	expr := `JSON.stringify({
status: document.body && document.body.getAttribute("data-status"),
detail: document.body && document.body.getAttribute("data-detail")
})`
	var req = struct {
		ID     int    `json:"id"`
		Method string `json:"method"`
		Params any    `json:"params"`
	}{
		ID:     1,
		Method: "Runtime.evaluate",
		Params: map[string]any{
			"expression":    expr,
			"returnByValue": true,
		},
	}
	data, _ := json.Marshal(req)
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return "", "", err
	}
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			return "", "", err
		}
		var resp struct {
			ID     int `json:"id"`
			Result struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			} `json:"result"`
			Error any `json:"error"`
		}
		if err := json.Unmarshal(msg, &resp); err != nil {
			return "", "", err
		}
		if resp.ID != req.ID {
			continue
		}
		if resp.Error != nil {
			return "", "", fmt.Errorf("runtime evaluate: %v", resp.Error)
		}
		var status struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal([]byte(resp.Result.Result.Value), &status); err != nil {
			return "", "", err
		}
		return status.Status, status.Detail, nil
	}
}

// mustBlobStore returns an in-memory blob store holding data.
func mustBlobStore(t *testing.T, data ...[]byte) *blobs.MemStore {
	t.Helper()
	m, err := blobs.NewMemStore(data...)
	if err != nil {
		t.Fatalf("NewMemStore: %v", err)
	}
	return m
}
