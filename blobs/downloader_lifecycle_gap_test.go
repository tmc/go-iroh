//go:build gaptests

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
		conn := &gapSharedBlobConn{release: release, store: providerStore}
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

type gapSharedBlobConn struct {
	mu      sync.Mutex
	streams []*testBidiStream
	opens   atomic.Int32
	closes  atomic.Int32
	release <-chan struct{}
	store   *MemStore
}

func (c *gapSharedBlobConn) OpenStreamSync(ctx context.Context) (BidiStream, error) {
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

func (c *gapSharedBlobConn) CloseWithError(uint64, string) error {
	c.closes.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, stream := range c.streams {
		_ = stream.r.CloseWithError(errors.New("connection closed"))
		_ = stream.w.CloseWithError(errors.New("connection closed"))
	}
	return nil
}

// Terminal Close with cancellation and worker joining is a proposed stricter
// contract. The current public comment promises only closing cached connections.
func TestDownloaderCloseWaitsForActiveWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		release := make(chan struct{})
		var calls atomic.Int32
		d := NewDownloader(&downloadStore{}, BlobConnectorFunc(func(ctx context.Context, _ netaddr.EndpointAddr, _ string) (BlobConn, error) {
			calls.Add(1)
			<-ctx.Done()
			<-release
			return nil, ctx.Err()
		}), DownloaderOptions{StallTimeout: -1})
		download := make(chan error, 1)
		go func() {
			tag, err := d.Download(ctx, NewHash([]byte("blob")), []netaddr.EndpointAddr{testEndpointAddr(92)})
			_ = tag.Close()
			download <- err
		}()
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("download did not enter connector")
		}
		closed := make(chan error, 1)
		go func() { closed <- d.Close() }()
		synctest.Wait()
		returnedEarly := false
		select {
		case err := <-closed:
			if err != nil {
				t.Error(err)
			}
			returnedEarly = true
		default:
		}
		// Clean up the current implementation, which does not cancel the caller.
		cancel()
		close(release)
		synctest.Wait()
		if !returnedEarly {
			if err := <-closed; err != nil {
				t.Error(err)
			}
		}
		if err := <-download; !errors.Is(err, context.Canceled) {
			t.Errorf("download error = %v, want context.Canceled", err)
		}
		if returnedEarly {
			t.Error("Close returned before active connector work finished")
		}
	})
}

// Rejecting new work after Close is also part of the proposed terminal contract.
func TestDownloaderCloseRejectsNewWork(t *testing.T) {
	data := []byte("post-close download")
	hash := NewHash(data)
	addr := testEndpointAddr(93)
	connector := &fakeBlobConnector{blobs: map[string]map[Hash][]byte{addr.String(): {hash: data}}}
	d := NewDownloader(&downloadStore{}, connector, DownloaderOptions{})
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	tag, err := d.Download(context.Background(), hash, []netaddr.EndpointAddr{addr})
	_ = tag.Close()
	_ = d.Close()
	if err == nil {
		t.Error("Download admitted new work after Close")
	}
	connector.mu.Lock()
	calls := connector.connects[addr.String()]
	connector.mu.Unlock()
	if calls != 0 {
		t.Errorf("new work opened %d provider connections after Close", calls)
	}
}
