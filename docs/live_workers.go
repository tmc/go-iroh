package docs

import (
	"context"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

type livePeerSync struct {
	again bool
}

// startWorker prevents new work from racing with shutdown's wait.
func (l *LiveSync) startWorker(f func()) {
	l.mu.Lock()
	if l.stopping {
		l.mu.Unlock()
		return
	}
	l.workers.Add(1)
	l.mu.Unlock()
	go func() {
		defer l.workers.Done()
		f()
	}()
}

// scheduleDownloads fills the bounded ready queue without discarding its backlog.
func (l *LiveSync) scheduleDownloads() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for len(l.backlog) != 0 {
		select {
		case l.downloads <- l.backlog[0]:
			l.backlog[0] = liveDownload{}
			l.backlog = l.backlog[1:]
		default:
			return
		}
	}
}

// recoverStore rebuilds work from a snapshot when store notifications were lost.
// Retained origins identify providers whose notifications were lost; entries
// loaded from disk fall back to known peers as candidates to try.
func (l *LiveSync) recoverStore(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions) {
	// A failed save leaves entries in memory. Do not publish that snapshot
	// until a successful save has made it durable.
	if store.PersistError() != nil {
		return
	}
	l.mu.Lock()
	peers := make(map[key.EndpointID]netaddr.EndpointAddr, len(l.peers)+len(opts.Bootstrap))
	for id, addr := range l.peers {
		peers[id] = addr
	}
	l.mu.Unlock()
	for _, addr := range opts.Bootstrap {
		peers[addr.ID] = addr
	}
	l.broadcastSyncReport(ctx, namespace, store, opts)
	for _, event := range store.snapshotEvents(namespace) {
		entry := event.Entry
		if ctx.Err() != nil {
			return
		}
		if entry.Entry.Namespace() != namespace {
			continue
		}
		if event.Kind == StoreEventInsertLocal {
			l.handleStoreEvent(ctx, namespace, opts, event)
		}
		if contentComplete(ctx, opts.BlobStore, entry.Entry.ContentHash()) {
			continue
		} else if event.Kind == StoreEventInsertRemote && event.ContentStatus == ContentComplete && !event.From.IsZero() {
			l.queueDownload(ctx, opts, entry.Entry.ContentHash(), entry.Entry.Key(), true, event.From)
		} else {
			for _, addr := range peers {
				l.queueDownload(ctx, opts, entry.Entry.ContentHash(), entry.Entry.Key(), true, addr.ID)
			}
		}
	}
}

// Retain providers discovered by sync for future lag recovery and downloads.
func (l *LiveSync) knownPeer(id key.EndpointID) (netaddr.EndpointAddr, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	addr, ok := l.peers[id]
	return addr, ok
}
