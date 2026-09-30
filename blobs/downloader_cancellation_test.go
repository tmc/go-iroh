package blobs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/tmc/go-iroh/netaddr"
)

// This specifies cancellation isolation for concurrent calls sharing a
// Downloader. A canceled stream opening must not close another call's stream.
func TestDownloaderCanceledOpenPreservesSharedConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		data := []byte("unrelated active download")
		providerStore := mustStore(t, data)
		release := make(chan struct{})
		conn := &sharedBlobConn{release: release, store: providerStore}
		d := NewDownloader(&downloadStore{}, BlobConnectorFunc(func(context.Context, netaddr.EndpointAddr, string) (BlobConn, error) {
			return conn, nil
		}), DownloaderOptions{StallTimeout: -1})
		addr := testEndpointAddr(91)
		active := make(chan error, 1)
		go func() {
			tag, err := d.Download(context.Background(), NewHash(data), []netaddr.EndpointAddr{addr})
			_ = tag.Close()
			active <- err
		}()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		canceled := make(chan error, 1)
		go func() {
			tag, err := d.Download(ctx, NewHash([]byte("other blob")), []netaddr.EndpointAddr{addr})
			_ = tag.Close()
			canceled <- err
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		canceledErr := <-canceled
		prematureCloses := conn.closes.Load()
		close(release)
		synctest.Wait()
		activeErr := <-active
		_ = d.Close()
		if !errors.Is(canceledErr, context.Canceled) {
			t.Errorf("canceled download error = %v, want context.Canceled", canceledErr)
		}
		if prematureCloses != 0 {
			t.Errorf("canceling stream opening closed shared connection %d times", prematureCloses)
		}
		if activeErr != nil {
			t.Errorf("unrelated active download failed: %v", activeErr)
		}
	})
}

type sharedBlobConn struct {
	mu      sync.Mutex
	streams []*testBidiStream
	opens   atomic.Int32
	closes  atomic.Int32
	release <-chan struct{}
	store   *MemStore
}

func (c *sharedBlobConn) OpenStreamSync(ctx context.Context) (BidiStream, error) {
	if c.opens.Add(1) != 1 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client, server := newTestBidiStreamPair()
	c.mu.Lock()
	c.streams = append(c.streams, client, server)
	c.mu.Unlock()
	go func() {
		<-c.release
		_ = ServeBlob(ctx, server, c.store)
	}()
	return client, nil
}

func (c *sharedBlobConn) CloseWithError(uint64, string) error {
	c.closes.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, stream := range c.streams {
		_ = stream.r.CloseWithError(errors.New("connection closed"))
		_ = stream.w.CloseWithError(errors.New("connection closed"))
	}
	return nil
}
