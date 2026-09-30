//go:build gaptests

package docs

import (
	"context"
	"testing"

	"github.com/tmc/go-iroh/blobs"
)

// A document reference alone is not a blob GC root. This is a characterization
// of the current application-owned retention contract, not a GC defect.
func TestGapDocumentReferenceDoesNotProtectContent(t *testing.T) {
	for _, tagged := range []bool{false, true} {
		name := "reference only"
		if tagged {
			name = "application tag"
		}
		t.Run(name, func(t *testing.T) {
			content, err := blobs.NewFSStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("document content")
			hash, err := content.Add(data)
			if err != nil {
				t.Fatal(err)
			}
			store := NewMemoryStore()
			entry := testSignedEntry(NewNamespaceSecret(repeat32(2)), NewAuthor(repeat32(3)), "k", NewRecord(hash, uint64(len(data)), 1))
			if outcome := store.Put(entry); !outcome.Inserted() || outcome.Err() != nil {
				t.Fatalf("insert: %+v, %v", outcome, outcome.Err())
			}
			if tagged {
				if err := content.SetTag("document", blobs.HashAndFormat{Hash: hash}); err != nil {
					t.Fatal(err)
				}
			}
			result, err := content.GC(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			complete := contentComplete(context.Background(), content, hash)
			t.Logf("tagged=%v deleted=%d document entries=%d content available=%v", tagged, result.Deleted, len(store.Entries()), complete)
			if complete != tagged || len(store.Entries()) != 1 {
				t.Fatalf("content available=%v, document entries=%d", complete, len(store.Entries()))
			}
		})
	}
}
