package blobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/tmc/go-iroh/netaddr"
)

func TestDownloaderCloseAndWaitForActiveWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		canceled := make(chan struct{})
		d := NewDownloader(&downloadStore{}, BlobConnectorFunc(func(ctx context.Context, _ netaddr.EndpointAddr, _ string) (BlobConn, error) {
			<-ctx.Done()
			close(canceled)
			<-release
			return nil, ctx.Err()
		}), DownloaderOptions{StallTimeout: -1})
		download := make(chan error, 1)
		go func() {
			tag, err := d.Download(context.Background(), NewHash([]byte("blob")), []netaddr.EndpointAddr{testEndpointAddr(92)})
			_ = tag.Close()
			download <- err
		}()
		synctest.Wait()
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case <-canceled:
		default:
			t.Fatal("Close did not cancel connector")
		}
		waited := make(chan error, 1)
		go func() { waited <- d.Wait(context.Background()) }()
		synctest.Wait()
		select {
		case err := <-waited:
			t.Fatalf("Wait returned before connector finished: %v", err)
		default:
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := d.Wait(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Wait = %v", err)
		}
		close(release)
		synctest.Wait()
		if err := <-waited; err != nil {
			t.Fatal(err)
		}
		if err := <-download; !errors.Is(err, context.Canceled) {
			t.Fatalf("download = %v", err)
		}
	})
}

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
	if !errors.Is(err, ErrDownloaderClosed) {
		t.Errorf("Download after Close = %v, want ErrDownloaderClosed", err)
	}
	connector.mu.Lock()
	calls := connector.connects[addr.String()]
	connector.mu.Unlock()
	if calls != 0 {
		t.Errorf("new work opened %d provider connections after Close", calls)
	}
}

func TestDownloaderCloseRejectsEmptyWithoutStore(t *testing.T) {
	sink := &closedDownloadSink{}
	d := NewDownloader(sink, BlobConnectorFunc(func(context.Context, netaddr.EndpointAddr, string) (BlobConn, error) {
		t.Fatal("closed downloader used connector")
		return nil, ErrDownloaderClosed
	}), DownloaderOptions{})
	_ = d.Close()
	for _, hash := range []Hash{EmptyHash, NewHash([]byte("blob"))} {
		tag, err := d.Download(nil, hash, nil)
		_ = tag.Close()
		if !errors.Is(err, ErrDownloaderClosed) {
			t.Fatalf("Download = %v", err)
		}
	}
	if sink.calls != 0 {
		t.Fatalf("closed downloader touched sink %d times", sink.calls)
	}
}

type closedDownloadSink struct{ calls int }

func (s *closedDownloadSink) NewBlob(context.Context) (BlobWriter, error) {
	s.calls++
	return nil, errors.New("unexpected sink access")
}

func TestDownloaderCloseFromEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var d *Downloader
		var events atomic.Int32
		d = NewDownloader(&downloadStore{}, BlobConnectorFunc(func(ctx context.Context, _ netaddr.EndpointAddr, _ string) (BlobConn, error) {
			return nil, ctx.Err()
		}), DownloaderOptions{OnEvent: func(DownloadEvent) { events.Add(1); _ = d.Close() }})
		tag, err := d.Download(nil, NewHash([]byte("blob")), []netaddr.EndpointAddr{testEndpointAddr(94)})
		_ = tag.Close()
		if err == nil {
			t.Fatal("download succeeded after callback closed downloader")
		}
		if err := d.Wait(nil); err != nil {
			t.Fatal(err)
		}
		if events.Load() == 0 {
			t.Fatal("no event")
		}
	})
}

func TestDownloaderCloseDiscardsLateConnection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		conn := &sharedBlobConn{}
		d := NewDownloader(&downloadStore{}, BlobConnectorFunc(func(ctx context.Context, _ netaddr.EndpointAddr, _ string) (BlobConn, error) {
			<-ctx.Done()
			<-release
			return conn, nil
		}), DownloaderOptions{StallTimeout: -1})
		download := make(chan error, 1)
		go func() {
			tag, err := d.Download(nil, NewHash([]byte("blob")), []netaddr.EndpointAddr{testEndpointAddr(95)})
			_ = tag.Close()
			download <- err
		}()
		synctest.Wait()
		_ = d.Close()
		close(release)
		synctest.Wait()
		if err := <-download; !errors.Is(err, ErrDownloaderClosed) {
			t.Fatalf("download = %v", err)
		}
		if err := d.Wait(nil); err != nil {
			t.Fatal(err)
		}
		if n := conn.closes.Load(); n != 1 {
			t.Fatalf("late connection closes = %d", n)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		if len(d.conns) != 0 {
			t.Fatal("late connection cached")
		}
	})
}

func TestDownloaderConcurrentCloseDownloadWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := NewDownloader(&downloadStore{}, BlobConnectorFunc(func(ctx context.Context, _ netaddr.EndpointAddr, _ string) (BlobConn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}), DownloaderOptions{StallTimeout: -1})
		var wg sync.WaitGroup
		for i := range 32 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tag, _ := d.Download(nil, NewHash([]byte{byte(i)}), []netaddr.EndpointAddr{testEndpointAddr(96)})
				_ = tag.Close()
			}()
		}
		synctest.Wait()
		for range 16 {
			wg.Add(1)
			go func() { defer wg.Done(); _ = d.Close(); _ = d.Wait(nil) }()
		}
		wg.Wait()
		if err := d.Wait(nil); err != nil {
			t.Fatal(err)
		}
	})
}

func ExampleDownloader_Wait() {
	d := NewDownloader(nil, nil, DownloaderOptions{})
	_ = d.Close()
	fmt.Println(d.Wait(context.Background()))
	// Output: <nil>
}

func TestDownloaderWaitJoinsEventCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var d *Downloader
		d = NewDownloader(&downloadStore{}, BlobConnectorFunc(func(context.Context, netaddr.EndpointAddr, string) (BlobConn, error) {
			return nil, errors.New("failed")
		}), DownloaderOptions{OnEvent: func(ev DownloadEvent) {
			if ev.Kind == DownloadTryProvider {
				_ = d.Close()
				<-release
			}
		}})
		downloaded := make(chan struct{})
		go func() {
			tag, _ := d.Download(nil, NewHash([]byte("blob")), []netaddr.EndpointAddr{testEndpointAddr(97)})
			_ = tag.Close()
			close(downloaded)
		}()
		synctest.Wait()
		waited := make(chan error, 1)
		go func() { waited <- d.Wait(nil) }()
		synctest.Wait()
		select {
		case err := <-waited:
			t.Fatalf("Wait returned during callback: %v", err)
		default:
		}
		close(release)
		synctest.Wait()
		if err := <-waited; err != nil {
			t.Fatal(err)
		}
		<-downloaded
	})
}
