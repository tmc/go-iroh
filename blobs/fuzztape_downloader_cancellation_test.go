package blobs

import "testing"

// Check cancellation isolation across calls sharing a Downloader.
func TestScheduledDownloaderSharedCancellation(t *testing.T) {
	m := downloaderMachineSpec(true)
	m.Replay(t, []byte{0, 1, 0, 2, 0, 2, 0, 0, 3, 1})
}
