package irpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

const testALPN = "go-iroh/irpc/test/0"

type testRequest struct {
	ID   uint64
	Op   string
	Body string
}

type testResponse struct {
	ID     uint64
	Result string
}

func TestCallLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, router := newTestServer(t, ctx)
	defer router.Shutdown(ctx)
	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), testALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	jobs := []testRequest{
		{ID: 1, Op: "upper", Body: "first"},
		{ID: 2, Op: "count", Body: "second"},
	}
	got := make(chan testResponse, len(jobs))
	for _, job := range jobs {
		go func() {
			responses, err := Call[testRequest, testResponse](ctx, conn, job, 0)
			if err != nil {
				t.Errorf("Call: %v", err)
				return
			}
			for resp, err := range responses {
				if err != nil {
					t.Errorf("response: %v", err)
					return
				}
				got <- resp
			}
		}()
	}
	seen := make(map[uint64]string)
	for range jobs {
		select {
		case resp := <-got:
			seen[resp.ID] = resp.Result
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if seen[1] != "FIRST" || seen[2] != "6 bytes" {
		t.Fatalf("responses = %#v", seen)
	}
}

func TestCallStreamsResponses(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, router := newTestServer(t, ctx)
	defer router.Shutdown(ctx)
	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), testALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	responses, err := Call[testRequest, testResponse](ctx, conn, testRequest{ID: 3, Op: "split", Body: "a b c"}, 0)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	var got []string
	for resp, err := range responses {
		if err != nil {
			t.Fatalf("response: %v", err)
		}
		got = append(got, resp.Result)
	}
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("stream = %q", got)
	}
}

func TestCallReceivesHandlerError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, router := newTestServer(t, ctx)
	defer router.Shutdown(ctx)
	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)
	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), testALPN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	responses, err := Call[testRequest, testResponse](ctx, conn, testRequest{ID: 4, Op: "fail"}, 0)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	for _, err := range responses {
		if err == nil {
			t.Fatal("error response = nil")
		}
		if err.Error() != "forced failure" {
			t.Fatalf("error = %v, want forced failure", err)
		}
		return
	}
	t.Fatal("response stream ended without error")
}

func newTestServer(t *testing.T, ctx context.Context) (*iroh.Endpoint, *iroh.Router) {
	t.Helper()
	server, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	handler := Handler[testRequest, testResponse]{
		Handle: func(ctx context.Context, req testRequest, r *Responder[testResponse]) error {
			switch req.Op {
			case "upper":
				return r.Send(testResponse{ID: req.ID, Result: strings.ToUpper(req.Body)})
			case "count":
				return r.Send(testResponse{ID: req.ID, Result: fmt.Sprintf("%d bytes", len(req.Body))})
			case "split":
				for _, word := range strings.Fields(req.Body) {
					if err := r.Send(testResponse{ID: req.ID, Result: word}); err != nil {
						return err
					}
				}
				return nil
			case "fail":
				return errors.New("forced failure")
			default:
				return r.Send(testResponse{ID: req.ID, Result: "unknown"})
			}
		},
	}
	router, err := iroh.NewRouter(server, map[string]iroh.ProtocolHandler{
		testALPN: handler,
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	return server, router
}

func TestReadValueRejectsOversizedLength(t *testing.T) {
	tests := []struct {
		name string
		hdr  uint32
	}{
		{"just over", 4097},
		{"high bit set", 1 << 31},
		{"max uint32", ^uint32(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], tt.hdr)
			buf.Write(hdr[:])
			err := readValue(context.Background(), &buf, 4096, &testRequest{})
			if err == nil || !strings.Contains(err.Error(), "message too large") {
				t.Fatalf("readValue err = %v, want message too large", err)
			}
		})
	}
}
