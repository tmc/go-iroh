package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

func TestFramerHasMaxData(t *testing.T) {
	f := newFramer(nil)
	if f.HasData() {
		t.Fatal("new framer has data")
	}
	f.QueueMaxDataFrame(protocol.ByteCount(1))
	if !f.HasData() {
		t.Fatal("framer with MAX_DATA has no data")
	}
}

// TestMaxDataFrameNotAliased guards against sharing one wire.MaxDataFrame
// across emissions: the retransmission queue retains the frame pointer on
// loss, so a later window update must not mutate an in-flight frame.
func TestMaxDataFrameNotAliased(t *testing.T) {
	f := newFramer(nil)
	f.QueueMaxDataFrame(1 << 20)
	frames, _ := f.AppendControlFrames(nil, 1000, monotime.Now(), protocol.Version1)
	if len(frames) != 1 {
		t.Fatalf("appended %d frames, want 1", len(frames))
	}
	inFlight := frames[0].Frame.(*wire.MaxDataFrame)
	if got := inFlight.MaximumData; got != 1<<20 {
		t.Fatalf("MaximumData = %d, want %d", got, 1<<20)
	}

	f.QueueMaxDataFrame(2 << 20)
	if got := inFlight.MaximumData; got != 1<<20 {
		t.Fatalf("in-flight frame mutated to %d after a later window update", got)
	}
	frames2, _ := f.AppendControlFrames(nil, 1000, monotime.Now(), protocol.Version1)
	if len(frames2) != 1 {
		t.Fatalf("appended %d frames, want 1", len(frames2))
	}
	if frames2[0].Frame.(*wire.MaxDataFrame) == inFlight {
		t.Fatal("second emission reused the in-flight frame pointer")
	}
}

// TestAppendControlFramesCarriesMaxData covers the ack-only packet path: a
// congestion-limited receiver grants window updates through
// AppendControlFrames, so a queued MAX_DATA must be emitted by it.
func TestAppendControlFramesCarriesMaxData(t *testing.T) {
	f := newFramer(nil)
	f.QueueMaxDataFrame(1 << 20)
	frames, length := f.AppendControlFrames(nil, 1000, monotime.Now(), protocol.Version1)
	if len(frames) != 1 {
		t.Fatalf("appended %d frames, want 1", len(frames))
	}
	md, ok := frames[0].Frame.(*wire.MaxDataFrame)
	if !ok || md.MaximumData != 1<<20 {
		t.Fatalf("frame = %#v, want MAX_DATA %d", frames[0].Frame, 1<<20)
	}
	if length == 0 {
		t.Fatal("length not accounted")
	}
	if frames, _ := f.AppendControlFrames(nil, 1000, monotime.Now(), protocol.Version1); len(frames) != 0 {
		t.Fatalf("second call re-emitted %d frames, want 0", len(frames))
	}
}
