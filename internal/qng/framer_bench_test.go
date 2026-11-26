package quic

import (
	"testing"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// benchStream is always ready to send. It hands back the same frame forever,
// so Append stays in the steady state a sending connection spends almost all
// of its time in and the benchmark measures scheduling rather than frame
// construction. DataLenPresent is set on every pop because Append clears it on
// the last frame of a packet, and a real popStreamFrame sets it each time.
type benchStream struct {
	id      protocol.StreamID
	urgency int8
	frame   wire.StreamFrame
}

func (s *benchStream) priority() (int8, bool, uint32) { return s.urgency, true, 0 }

func (s *benchStream) popStreamFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, sendState) {
	s.frame.DataLenPresent = true
	return ackhandler.StreamFrame{Frame: &s.frame}, nil, sendStateReady
}

func (s *benchStream) popRetransmissionFrame(protocol.ByteCount, protocol.Version) (ackhandler.StreamFrame, bool) {
	return ackhandler.StreamFrame{}, false
}

func newBenchFramer(urgencies []int8) *framer {
	const window = protocol.ByteCount(1) << 40
	cfc := newConnectionFlowController(window, window, nil, utils.NewRTTStats(), utils.DefaultLogger)
	cfc.UpdateSendWindow(window)
	f := newFramer(cfc)
	for i, u := range urgencies {
		s := &benchStream{id: protocol.StreamID(i * 4), urgency: u}
		s.frame.StreamID = s.id
		s.frame.Data = make([]byte, 8)
		f.AddActiveStream(s.id, s)
	}
	return f
}

// BenchmarkFramerAppend measures the per-packet cost of stream scheduling.
//
// Two quantities move independently, and the cases separate them so neither is
// read off a number that confounds both: how many streams are queued, which
// sets how many turns the scheduling loop takes, and how many urgency levels
// it walks. The floor case pins the second on its own — with nothing queued at
// all, any difference between revisions is the walk and nothing else. A
// connection that never sets a priority leaves seven of the eight levels empty
// for its whole life, so on the common path that walk finds nothing every time.
//
// Read the absolute nanoseconds between revisions, not the percentage. A fixed
// per-call cost sits underneath every case, so the same regression reports a
// different percentage depending on how much of that floor is in the
// denominator, and the single-stream cases are mostly floor.
//
// There is a resolution floor under that. At the 130-150ns/op the eight-stream
// cases sit at, this benchmark cannot resolve a sub-1% difference to a cause in
// the code, in either direction and whatever the p-value says: differences that
// small move under harness changes that do not touch the code being measured.
// Hoisting one clock read out of the loop moved a -0.4% reading at p=0.01 to
// -0.1% at p=0.88. Treat anything under about a percent as unresolved.
func BenchmarkFramerAppend(b *testing.B) {
	for _, bb := range []struct {
		name      string
		urgencies []int8
	}{
		{"0streams/floor", nil},
		{"1stream/1level", []int8{0}},
		{"1stream/level7", []int8{7}},
		{"8streams/1level", []int8{0, 0, 0, 0, 0, 0, 0, 0}},
		{"8streams/8levels", []int8{0, 1, 2, 3, 4, 5, 6, 7}},
	} {
		b.Run(bb.name, func(b *testing.B) {
			f := newBenchFramer(bb.urgencies)
			buf := make([]ackhandler.StreamFrame, 0, 16)
			// Append takes now only for control frames, of which there are
			// Fail loudly rather than benchmark a framer that schedules nothing.
			if len(bb.urgencies) > 0 {
				if _, _, has, sf, _ := f.AppendStreamFrames(nil, buf[:0], protocol.MaxPacketBufferSize, protocol.Version1); !has && len(sf) == 0 {
					b.Fatal("AppendStreamFrames produced no STREAM frame; the benchmark is measuring an empty framer")
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			frames := 0
			for range b.N {
				_, _, has, sf, _ := f.AppendStreamFrames(nil, buf[:0], protocol.MaxPacketBufferSize, protocol.Version1)
				frames += len(sf)
				if has {
					frames++
				}
				buf = sf[:0]
			}
			b.StopTimer()
			// A liveness check, not a proof of equal work: it counts STREAM
			// frames, so it cannot see frame size, control frames, or how many
			// urgency levels were walked to produce them. It catches a revision
			// that stops scheduling, which is the failure that would otherwise
			// look like a speedup.
			b.ReportMetric(float64(frames)/float64(b.N), "frames/op")
		})
	}
}
