//go:build gaptests

package blobs

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/tmc/go-iroh/netaddr"
)

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
