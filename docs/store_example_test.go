package docs_test

import (
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/docs"
)

func ExampleInsertOutcome_Err() {
	namespace := docs.NewNamespaceSecret([32]byte{1})
	author := docs.NewAuthor([32]byte{2})
	id := docs.NewRecordIdentifier(namespace.ID(), author.ID(), []byte("greeting"))
	data := []byte("hello")
	entry := docs.NewSignedEntry(docs.NewEntry(id, docs.NewRecord(blobs.NewHash(data), uint64(len(data)), 1)), namespace, author)
	outcome := docs.NewMemoryStore().Put(entry)
	fmt.Println(outcome.Inserted(), outcome.Err())
	// Output: true <nil>
}
