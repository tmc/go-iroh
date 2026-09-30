package docs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
)

func TestSyncPersistenceFailure(t *testing.T) {
	for _, side := range []string{"accept", "dial"} {
		t.Run(side, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			secret := NewNamespaceSecret(repeat32(0xb2))
			author := NewAuthor(repeat32(0xa1))
			entry := testSignedEntry(secret, author, "k", testRecord("data", 4, 1))
			source := NewMemoryStore()
			source.Put(entry)
			// Replace the snapshot directory with a regular file so the next save
			// fails independently of filesystem permissions or the test user's UID.
			dir := filepath.Join(t.TempDir(), "snapshots")
			snapshot := filepath.Join(dir, "entries")
			target, err := NewFileStore(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.RemoveAll(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dir, []byte("blocked"), 0600); err != nil {
				t.Fatal(err)
			}
			serverStore, clientStore := target, source
			if side == "dial" {
				serverStore, clientStore = source, target
			}
			h := Handler{Store: serverStore, Allow: allowAllSync}
			acceptDone := make(chan error, 3)
			server := newSyncNode(t, ctx, iroh.ProtocolHandlerFunc(func(ctx context.Context, conn *iroh.Conn) error {
				err := h.Accept(ctx, conn)
				acceptDone <- err
				return err
			}))
			client := newSyncClient(t, ctx)
			_, err = Sync(ctx, client, syncAddr(server), secret.ID(), clientStore, nil, SyncConfig{})
			if err == nil {
				t.Fatal("Sync succeeded after persistence failure")
			}
			if target.PersistError() == nil {
				t.Fatal("missing local persistence error")
			}
			if side == "accept" {
				if !strings.Contains(err.Error(), "sync aborted: 2") {
					t.Fatalf("Sync error = %v, want internal-server abort", err)
				}
				select {
				case err := <-acceptDone:
					if !errors.Is(err, target.PersistError()) {
						t.Fatalf("Accept error = %v, want persistence error %v", err, target.PersistError())
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			} else if !errors.Is(err, target.PersistError()) {
				t.Fatalf("Sync error = %v, want persistence error %v", err, target.PersistError())
			}
			// Both stores now hold the entry. Matching fingerprints must not
			// conceal the outstanding save failure on a subsequent sync.
			if _, err := Sync(ctx, client, syncAddr(server), secret.ID(), clientStore, nil, SyncConfig{}); err == nil {
				t.Fatal("repeated Sync succeeded with unresolved persistence failure")
			}
			if err := os.Remove(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := target.SaveFile(snapshot); err != nil {
				t.Fatal(err)
			}
			if _, err := Sync(ctx, client, syncAddr(server), secret.ID(), clientStore, nil, SyncConfig{}); err != nil {
				t.Fatalf("Sync after successful save: %v", err)
			}
		})
	}
}
