package docs

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
)

func allowAllSync(NamespaceID, key.EndpointID) bool { return true }

func TestHandlerAuthorization(t *testing.T) {
	for _, kind := range []syncMessageKind{syncMessageInit, syncMessageReport} {
		for _, policy := range []string{"nil", "deny", "allow"} {
			t.Run(kindName(kind)+"/"+policy, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				secret := NewNamespaceSecret(repeat32(0xb2))
				namespace := secret.ID()
				store := NewMemoryStore()
				store.Put(testSignedEntry(secret, NewAuthor(repeat32(0xa1)), "k", testRecord("data", 4, 1)))
				client := newSyncClient(t, ctx)
				clientID := client.ID()
				handler := &Handler{Store: store}
				if policy != "nil" {
					handler.Allow = func(ns NamespaceID, peer key.EndpointID) bool {
						if ns != namespace || peer != clientID {
							t.Errorf("Allow received namespace %v, peer %v", ns, peer)
						}
						return policy == "allow"
					}
				}
				server := newSyncNode(t, ctx, handler)
				conn, err := client.Connect(ctx, syncAddr(server), ALPN)
				if err != nil {
					t.Fatal(err)
				}
				stream, err := conn.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.Close()
				msg := syncWireMessage{Kind: kind, Namespace: namespace, Message: NewMemoryStore().InitialMessageInNamespace(namespace), Report: liveSyncReport{Namespace: namespace, Heads: store.encodeSyncHeads(namespace)}}
				if err := writeSyncFrame(stream, msg); err != nil {
					t.Fatal(err)
				}
				reply, err := readSyncFrame(stream)
				if err != nil {
					t.Fatal(err)
				}
				if policy != "allow" {
					if reply.Kind != syncMessageAbort || reply.Reason != AbortNotFound {
						t.Fatalf("reply kind = %v, reason = %v, want AbortNotFound", reply.Kind, reply.Reason)
					}
				} else if reply.Kind == syncMessageAbort {
					t.Fatal("authorized sync aborted")
				}
			})
		}
	}
}

func kindName(kind syncMessageKind) string {
	if kind == syncMessageReport {
		return "report"
	}
	return "init"
}
