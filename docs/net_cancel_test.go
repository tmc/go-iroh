package docs

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
)

func TestHandlerCancellation(t *testing.T) {
	for _, stage := range []string{"opening", "reconciliation", "reply-write"} {
		t.Run(stage, func(t *testing.T) {
			ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			handlerCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			secret := NewNamespaceSecret(repeat32(0xb2))
			store := NewMemoryStore()
			name := "k"
			if stage == "reply-write" {
				name = strings.Repeat("k", 1024*1024)
			}
			store.Put(testSignedEntry(secret, NewAuthor(repeat32(0xa1)), name, testRecord("data", 4, 1)))
			h := Handler{Store: store, Allow: allowAllSync}
			done := make(chan error, 1)
			server := newSyncNode(t, ctx, iroh.ProtocolHandlerFunc(func(_ context.Context, conn *iroh.Conn) error {
				err := h.Accept(handlerCtx, conn)
				done <- err
				return err
			}))
			client := newSyncClient(t, ctx)
			conn, err := client.Connect(ctx, syncAddr(server), ALPN)
			if err != nil {
				t.Fatal(err)
			}
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if stage == "opening" {
				if _, err := stream.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := writeSyncFrame(stream, syncWireMessage{Kind: syncMessageInit, Namespace: secret.ID(), Message: NewMemoryStore().InitialMessageInNamespace(secret.ID())}); err != nil {
					t.Fatal(err)
				}
				if stage == "reply-write" {
					var header [4]byte
					if _, err := io.ReadFull(stream, header[:]); err != nil {
						t.Fatal(err)
					}
				} else if _, err := readSyncFrame(stream); err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("Accept error = %v, want context canceled", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Accept did not stop after cancellation")
			}
		})
	}
}

func TestSyncCancellation(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	ready := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	server := newSyncNode(t, ctx, iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		defer stream.Close()
		if _, err := readSyncFrame(stream); err != nil {
			return err
		}
		close(ready)
		<-release
		return nil
	}))
	client := newSyncClient(t, ctx)
	syncCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Sync(syncCtx, client, syncAddr(server), NewNamespaceSecret(repeat32(0xb2)).ID(), NewMemoryStore(), nil, SyncConfig{})
		done <- err
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Sync error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sync did not stop after cancellation")
	}
}

func TestSyncOpeningWriteCancellation(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	ready := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	server := newSyncNode(t, ctx, iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return err
		}
		defer stream.Close()
		var first [1]byte
		if _, err := io.ReadFull(stream, first[:]); err != nil {
			return err
		}
		close(ready)
		<-release
		return nil
	}))
	secret := NewNamespaceSecret(repeat32(0xb2))
	store := NewMemoryStore()
	store.Put(testSignedEntry(secret, NewAuthor(repeat32(0xa1)), strings.Repeat("k", 1024*1024), testRecord("data", 4, 1)))
	client := newSyncClient(t, ctx)
	syncCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Sync(syncCtx, client, syncAddr(server), secret.ID(), store, nil, SyncConfig{})
		done <- err
	}()
	select {
	case <-ready:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Sync error = %v, want context canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sync write did not stop after cancellation")
	}
}
