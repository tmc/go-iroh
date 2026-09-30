//go:build gaptests

package docs

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/key"
)

// These characterization tests measure retained work without a consumer. They
// demonstrate that the ready-channel capacity is not a total scheduling bound;
// they do not prescribe a future limit or discard policy.
func TestGapLiveSyncRetainedDownloads(t *testing.T) {
	for _, count := range []int{16, 64, 256, 1024} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			l := &LiveSync{downloads: make(chan liveDownload, liveDownloadQueueSize)}
			peer := key.NewSecretKey(repeat32(1)).Public().EndpointID()
			for i := 0; i < count; i++ {
				hash := blobs.NewHash([]byte(fmt.Sprintf("content %d", i)))
				l.queueDownload(context.Background(), liveSyncOptions{}, hash, []byte("k"), true, peer)
			}
			queued, overflow, retained := len(l.downloads), len(l.backlog), len(l.pending)
			t.Logf("requests=%d ready=%d backlog=%d pending=%d", count, queued, overflow, retained)
			if retained != count || queued+overflow != count {
				t.Fatalf("retained %d pending and %d descriptors for %d requests", retained, queued+overflow, count)
			}
		})
	}
}

func TestGapLiveSyncRetainedProviders(t *testing.T) {
	l := &LiveSync{downloads: make(chan liveDownload, liveDownloadQueueSize)}
	hash := blobs.NewHash([]byte("shared content"))
	const count = 1024
	for i := 0; i < count; i++ {
		var seed [32]byte
		binary.LittleEndian.PutUint64(seed[:], uint64(i+1))
		peer := key.NewSecretKey(seed).Public().EndpointID()
		l.queueDownload(context.Background(), liveSyncOptions{}, hash, []byte("k"), true, peer)
		// Duplicate announcements are coalesced, but distinct providers accumulate.
		l.queueDownload(context.Background(), liveSyncOptions{}, hash, []byte("k"), true, peer)
	}
	providers := l.pending[hash].snapshot()
	t.Logf("hashes=%d ready=%d providers=%d", len(l.pending), len(l.downloads), len(providers))
	if len(l.pending) != 1 || len(l.downloads) != 1 || len(providers) != count {
		t.Fatalf("got %d hashes, %d ready, %d providers", len(l.pending), len(l.downloads), len(providers))
	}
}
