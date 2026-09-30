//go:build gaptests

package blobs

import "testing"

// This proposes cancellation isolation across calls sharing a Downloader.
// The fixed regressions retain the separate proposed terminal-Close contract.
func TestScheduledDownloaderSharedCancellationGap(t *testing.T) {
	m := downloaderMachineSpec(true)
	m.Replay(t, []byte{0, 1, 0, 2, 0, 2, 0, 0, 3, 1})
}
