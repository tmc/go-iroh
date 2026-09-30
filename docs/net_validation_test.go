package docs

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

func TestSyncMandatoryValidation(t *testing.T) {
	for _, side := range []string{"accept", "dial"} {
		for _, kind := range []string{"signature", "empty-hash", "empty-length", "valid"} {
			t.Run(side+"/"+kind, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				secret := NewNamespaceSecret(repeat32(0xb2))
				author := NewAuthor(repeat32(0xa1))
				entry := testSignedEntry(secret, author, "k", testRecord("data", 4, 1))
				switch kind {
				case "signature":
					entry.Signature = EntrySignature{}
				case "empty-hash":
					entry = testSignedEntry(secret, author, "k", NewRecord(blobs.EmptyHash, 4, 1))
				case "empty-length":
					entry = testSignedEntry(secret, author, "k", NewRecord(blobs.NewHash([]byte("data")), 0, 1))
				}
				source, target := NewMemoryStore(), NewMemoryStore()
				source.Put(entry)
				handler := &Handler{Allow: allowAllSync, Validate: func(SignedEntry, ContentStatus) bool { return true }}
				serverStore, clientStore := target, source
				if side == "dial" {
					serverStore, clientStore = source, target
				}
				handler.Store = serverStore
				server := newSyncNode(t, ctx, handler)
				client := newSyncClient(t, ctx)
				if _, err := Sync(ctx, client, syncAddr(server), secret.ID(), clientStore, nil, SyncConfig{}); err != nil {
					t.Fatal(err)
				}
				_, got := target.GetExact(secret.ID(), author.ID(), []byte("k"), false)
				if got != (kind == "valid") {
					t.Fatalf("inserted = %v, want %v", got, kind == "valid")
				}
			})
		}
	}
}

func TestHandlerValidationPolicy(t *testing.T) {
	secret := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(secret, author, "k", testRecord("data", 4, 1))
	called := false
	store := NewMemoryStore()
	handler := Handler{Store: store, Validate: func(SignedEntry, ContentStatus) bool { called = true; return false }}
	message := Message{Parts: []MessagePart{{Kind: MessagePartRangeItem, RangeItem: RangeItem{Values: []RangeValue{{Entry: entry}}, HaveLocal: true}}}}
	if _, err := handler.run(context.Background(), nil, key.EndpointID{}, secret.ID(), message, true); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("valid entry did not reach application policy")
	}
	if _, ok := store.GetExact(secret.ID(), author.ID(), []byte("k"), false); ok {
		t.Fatal("application policy rejection was ignored")
	}
}
