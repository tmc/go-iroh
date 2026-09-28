package docs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/irohtest"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// A provider that fails a download must not stop the content from being
// fetched from a good provider that announces it afterwards, whether the
// announcement arrives after the failure or while the download is in flight.
func TestLiveSyncRetriesAfterFailedProvider(t *testing.T) {
	for _, inFlight := range []bool{false, true} {
		t.Run(fmt.Sprintf("inFlight=%v", inFlight), func(t *testing.T) {
			testLiveSyncRetriesAfterFailedProvider(t, inFlight)
		})
	}
}

func testLiveSyncRetriesAfterFailedProvider(t *testing.T, inFlight bool) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		namespace := NewNamespaceSecret(repeat32(0xb2))
		author := NewAuthor(repeat32(0xa1))
		content := []byte("content held by the good provider")
		hash := blobs.NewHash(content)
		entry := testSignedEntry(namespace, author, "k", NewRecord(hash, uint64(len(content)), 1))
		store := NewMemoryStore()
		store.PutWithOrigin(entry, InsertOrigin{Kind: InsertOriginRemote, ContentStatus: ContentMissing})
		events, cancelEvents := store.Subscribe()
		defer cancelEvents()
		blobStore, err := blobs.NewMemStore()
		if err != nil {
			t.Fatalf("NewMemStore: %v", err)
		}

		bad := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(0x01)).Public().EndpointID())
		good := netaddr.NewEndpointAddr(key.NewSecretKey(repeat32(0x02)).Public().EndpointID())
		release := make(chan struct{})
		if !inFlight {
			close(release)
		}
		opts := liveSyncOptions{
			LiveSyncOptions: LiveSyncOptions{
				BlobStore: blobStore,
				Resolver:  iroh.StaticLookupFromAddrs(bad, good),
			},
			downloadBlob: func(ctx context.Context, providers []netaddr.EndpointAddr, h blobs.Hash) error {
				for _, p := range providers {
					if p.ID.Equal(good.ID) {
						_, err := blobStore.Add(content)
						return err
					}
				}
				<-release
				return errors.New("provider does not have the blob")
			},
		}
		n := irohtest.NewNet(t)
		topic, err := gossip.NewGossip(n.Peer().Endpoint).Subscribe(ctx, gossip.TopicID(namespace.ID().Bytes()), nil)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		defer topic.Close()
		l := &LiveSync{
			topic:     topic,
			downloads: make(chan liveDownload, liveDownloadQueueSize),
			pending:   make(map[blobs.Hash]*pendingDownload),
		}
		go l.runDownloader(ctx, store, opts)

		announce := func(from netaddr.EndpointAddr) {
			msg, err := postcard.Marshal(liveOp{Kind: liveOpContentReady, Hash: hash})
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			l.handleReceived(ctx, namespace.ID(), store, opts, gossip.Event{
				Kind:          gossip.Received,
				Content:       msg,
				DeliveredFrom: from.ID,
			})
		}
		announce(bad)
		synctest.Wait()
		announce(good)
		if inFlight {
			close(release)
		}

		irohtest.Within(t, time.Second, func(ctx context.Context) error {
			for {
				select {
				case ev := <-events:
					if ev.Kind == StoreEventContentReady && ev.Hash == hash {
						return nil
					}
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		})
	})
}
