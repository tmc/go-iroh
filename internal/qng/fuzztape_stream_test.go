package quic

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/fuzztape"
	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/flowcontrol"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/qerr"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// The stream machine drives the receiving half of a connection — the real
// ReceiveStream, flow controllers, framer and packet packer — against a
// model of the peer that sends data and consumes the credit-announcing
// frames the packer emits. Everything the code under test reads from the
// clock is passed in explicitly, so a sequence replays identically.
//
// Only the receiving half is real. A SendStream cannot be driven from an
// operation sequence without goroutines, because Write blocks until the
// data has been popped into frames; modelling the peer sender as a credit
// counter keeps the machine deterministic and still exercises the whole
// credit-granting path.

const (
	streamMachineConnWindow      = 1024
	streamMachineConnMaxWindow   = 8192
	streamMachineStreamWindow    = 512
	streamMachineStreamMaxWindow = 4096
	streamMachineMaxStreams      = 4
	streamMachineMaxWrite        = 96
)

// streamMachineData is the byte the peer sends at off on stream id. Using a
// function of the position rather than a recorded buffer keeps the model
// small and still detects data that was never written.
func streamMachineData(id protocol.StreamID, off protocol.ByteCount) byte {
	return byte(uint64(off)*7 + uint64(id)*13 + 1)
}

// streamMachineStream is one stream: the real receiving end, plus the model
// of the peer's send side.
type streamMachineStream struct {
	id protocol.StreamID
	rs *ReceiveStream
	fc flowcontrol.StreamFlowController

	sendWindow protocol.ByteCount // credit granted to the peer, stream level
	sent       protocol.ByteCount // highest offset the peer has sent
	readPos    protocol.ByteCount // bytes the application has read

	last *wire.StreamFrame // last frame sent, for retransmission

	fin       bool
	finOffset protocol.ByteCount
	reset     bool
	cancelled bool // CancelRead was called locally
	eof       bool // Read has returned its terminal error
}

// readable reports whether Read returns without blocking. Every terminal
// condition — EOF, local cancellation, remote reset — returns immediately,
// so only a stream with no buffered data and no known end can block.
func (s *streamMachineStream) readable() bool {
	return s.eof || s.cancelled || s.reset || s.readPos < s.sent ||
		(s.fin && s.readPos >= s.finOffset)
}

// sendable reports whether the peer may send more data on the stream.
func (s *streamMachineStream) sendable() bool {
	return !s.fin && !s.reset && s.sent < s.sendWindow
}

type streamMachine struct {
	t   *testing.T
	now monotime.Time

	connFC flowcontrol.ConnectionFlowController
	framer *framer
	packer *packetPacker

	streams  []*streamMachineStream
	nextID   protocol.StreamID
	connData bool // the receiver signalled a connection-level window update

	// model of the peer's send side, connection level
	connSendWindow protocol.ByteCount
	connSent       protocol.ByteCount

	// maxData is queued in the framer but not yet packed into a packet.
	maxDataQueued bool
	maxDataOffset protocol.ByteCount
}

// streamMachineSender routes the receive stream's notifications the way
// Conn does: stream data and control frames go to the framer, connection
// window updates schedule a send.
type streamMachineSender struct{ m *streamMachine }

func (s streamMachineSender) onHasConnectionData() { s.m.connData = true }

func (s streamMachineSender) onHasStreamData(id protocol.StreamID, str *SendStream) {
	s.m.framer.AddActiveStream(id, str)
}

func (s streamMachineSender) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	s.m.framer.AddStreamWithControlFrames(id, str)
}

func (s streamMachineSender) onStreamCompleted(protocol.StreamID) {}

func newStreamMachine(t *testing.T) *streamMachine {
	rttStats := utils.NewRTTStats()
	connFC := flowcontrol.NewConnectionFlowController(
		streamMachineConnWindow,
		streamMachineConnMaxWindow,
		func(protocol.ByteCount) bool { return true },
		rttStats,
		utils.DefaultLogger,
	)
	m := &streamMachine{
		t:   t,
		now: monotime.Now(),
		// The framer only consults its flow controller for DATA_BLOCKED
		// frames on the sending path, which this machine doesn't drive.
		framer:         newFramer(noopConnectionFlowController{}),
		connFC:         connFC,
		connSendWindow: streamMachineConnWindow,
	}
	m.packer = &packetPacker{
		framer:              m.framer,
		acks:                noAckFrameSource{},
		retransmissionQueue: newRetransmissionQueue(),
	}
	return m
}

func (m *streamMachine) connCredit() protocol.ByteCount {
	return m.connSendWindow - m.connSent
}

// deliver hands frame to the receive stream, failing the test if the stream
// rejects it: every frame the machine sends is valid by construction.
func (m *streamMachine) deliver(s *streamMachineStream, frame *wire.StreamFrame) {
	if err := s.rs.handleStreamFrame(frame, m.now); err != nil {
		m.t.Fatalf("stream %d: handleStreamFrame(off %d, len %d, fin %v): %v",
			s.id, frame.Offset, len(frame.Data), frame.Fin, err)
	}
}

// FuzzStreamMachine explores operation sequences over the receiving half of
// a connection under go test -fuzz.
func FuzzStreamMachine(f *testing.F) {
	streamMachineSpec().Fuzz(f)
}

func TestStreamMachine(t *testing.T) {
	streamMachineSpec().Run(t, 200)
}

func streamMachineSpec() fuzztape.Machine[*streamMachine] {
	return fuzztape.Machine[*streamMachine]{
		Name:   "FuzzStreamMachine",
		MaxOps: 48,
		Init:   newStreamMachine,
		Ops: []fuzztape.Op[*streamMachine]{
			{
				Name:   "openStream",
				Weight: 2,
				When:   func(m *streamMachine) bool { return len(m.streams) < streamMachineMaxStreams },
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					id := m.nextID
					m.nextID += 4
					fc := flowcontrol.NewStreamFlowController(
						id,
						m.connFC,
						streamMachineStreamWindow,
						streamMachineStreamMaxWindow,
						0, // send window; the machine never sends on this stream
						utils.NewRTTStats(),
						utils.DefaultLogger,
					)
					m.streams = append(m.streams, &streamMachineStream{
						id:         id,
						rs:         newReceiveStream(id, streamMachineSender{m}, fc),
						fc:         fc,
						sendWindow: streamMachineStreamWindow,
					})
					return nil
				},
			},
			{
				Name:   "sendData",
				Weight: 6,
				When: func(m *streamMachine) bool {
					if m.connCredit() == 0 {
						return false
					}
					for _, s := range m.streams {
						if s.sendable() {
							return true
						}
					}
					return false
				},
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					open := make([]*streamMachineStream, 0, len(m.streams))
					for _, s := range m.streams {
						if s.sendable() {
							open = append(open, s)
						}
					}
					s := open[t.IntN(len(open))]
					limit := min(s.sendWindow-s.sent, m.connCredit(), streamMachineMaxWrite)
					n := protocol.ByteCount(t.IntN(int(limit) + 1))
					data := make([]byte, n)
					for i := range data {
						data[i] = streamMachineData(s.id, s.sent+protocol.ByteCount(i))
					}
					frame := &wire.StreamFrame{
						StreamID: s.id,
						Offset:   s.sent,
						Data:     data,
						Fin:      t.Bool(),
					}
					m.deliver(s, frame)
					s.last = frame
					s.sent += n
					m.connSent += n
					if frame.Fin {
						s.fin = true
						s.finOffset = s.sent
					}
					return nil
				},
			},
			{
				Name: "resendData",
				When: func(m *streamMachine) bool {
					for _, s := range m.streams {
						if s.last != nil && !s.reset {
							return true
						}
					}
					return false
				},
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					open := make([]*streamMachineStream, 0, len(m.streams))
					for _, s := range m.streams {
						if s.last != nil && !s.reset {
							open = append(open, s)
						}
					}
					s := open[t.IntN(len(open))]
					// A retransmission consumes no additional credit: the
					// receiver must recognize the duplicate offsets.
					m.deliver(s, &wire.StreamFrame{
						StreamID: s.last.StreamID,
						Offset:   s.last.Offset,
						Data:     append([]byte(nil), s.last.Data...),
						Fin:      s.last.Fin,
					})
					return nil
				},
			},
			{
				Name:   "read",
				Weight: 5,
				When: func(m *streamMachine) bool {
					for _, s := range m.streams {
						if s.readable() {
							return true
						}
					}
					return false
				},
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					open := make([]*streamMachineStream, 0, len(m.streams))
					for _, s := range m.streams {
						if s.readable() {
							open = append(open, s)
						}
					}
					s := open[t.IntN(len(open))]
					buf := make([]byte, 1+t.IntN(streamMachineMaxWrite))
					// A Read that blocks means the precondition above is
					// wrong, or the receiver lost track of buffered data.
					// The deadline turns that hang into a failure.
					s.rs.SetReadDeadline(time.Now().Add(5 * time.Second))
					n, err := s.rs.Read(buf)
					s.rs.SetReadDeadline(time.Time{})
					if errors.Is(err, errDeadline) {
						m.t.Fatalf("stream %d: Read blocked with %d bytes buffered (read %d, sent %d)",
							s.id, s.sent-s.readPos, s.readPos, s.sent)
					}
					for i := range n {
						want := streamMachineData(s.id, s.readPos+protocol.ByteCount(i))
						if buf[i] != want {
							m.t.Fatalf("stream %d: Read at offset %d = %#x, want %#x",
								s.id, s.readPos+protocol.ByteCount(i), buf[i], want)
						}
					}
					s.readPos += protocol.ByteCount(n)
					if s.readPos > s.sent {
						m.t.Fatalf("stream %d: read %d bytes, but only %d were sent", s.id, s.readPos, s.sent)
					}
					var streamErr *StreamError
					switch {
					case err == nil:
					case errors.Is(err, io.EOF), errors.As(err, &streamErr):
						s.eof = true
					default:
						m.t.Fatalf("stream %d: Read: %v", s.id, err)
					}
					return nil
				},
			},
			{
				Name:   "connWindowUpdate",
				Weight: 3,
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					// This mirrors Conn.sendPackets: whenever the send loop
					// runs, a pending connection-level window update is
					// queued as a MAX_DATA frame.
					m.connData = false
					offset := m.connFC.GetWindowUpdate(m.now)
					if offset == 0 {
						return nil
					}
					m.framer.QueueMaxDataFrame(offset)
					m.maxDataQueued = true
					if offset > m.maxDataOffset {
						m.maxDataOffset = offset
					}
					return nil
				},
			},
			{
				Name:   "packPacket",
				Weight: 5,
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					size := fuzztape.Pick(t, []protocol.ByteCount{1200, 128, 64, 32, 26, 1452})
					pl := m.packer.composeNextPacket(size, false, true, m.now, protocol.Version1)
					if pl.hasStreamFrame || len(pl.streamFrames) > 0 {
						m.t.Fatalf("packed %d STREAM frames, but no stream is sending", pl.numStreamFrames())
					}
					for _, f := range pl.frames {
						switch frame := f.Frame.(type) {
						case *wire.MaxDataFrame:
							if frame.MaximumData < m.connSendWindow {
								m.t.Fatalf("MAX_DATA = %d, below the already granted %d",
									frame.MaximumData, m.connSendWindow)
							}
							m.connSendWindow = frame.MaximumData
							m.maxDataQueued = false
						case *wire.MaxStreamDataFrame:
							s := m.stream(frame.StreamID)
							if s == nil {
								m.t.Fatalf("MAX_STREAM_DATA for unknown stream %d", frame.StreamID)
							}
							// A queued MAX_STREAM_DATA can be packed after the
							// update became unnecessary — an abandoned stream
							// reports no window update — in which case the
							// frame announces 0 and the peer ignores it.
							if frame.MaximumStreamData > s.sendWindow {
								s.sendWindow = frame.MaximumStreamData
							}
						case *wire.StopSendingFrame:
							if s := m.stream(frame.StreamID); s == nil {
								m.t.Fatalf("STOP_SENDING for unknown stream %d", frame.StreamID)
							}
						}
					}
					return nil
				},
			},
			{
				Name: "resetStream",
				When: func(m *streamMachine) bool {
					for _, s := range m.streams {
						if !s.reset && !s.fin {
							return true
						}
					}
					return false
				},
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					open := make([]*streamMachineStream, 0, len(m.streams))
					for _, s := range m.streams {
						if !s.reset && !s.fin {
							open = append(open, s)
						}
					}
					s := open[t.IntN(len(open))]
					// The final size must be the highest offset sent, or the
					// receiver rejects the frame as a protocol violation.
					if err := s.rs.handleResetStreamFrame(&wire.ResetStreamFrame{
						StreamID:  s.id,
						ErrorCode: qerr.StreamErrorCode(t.IntN(8)),
						FinalSize: s.sent,
					}, m.now); err != nil {
						m.t.Fatalf("stream %d: handleResetStreamFrame(final %d): %v", s.id, s.sent, err)
					}
					s.reset = true
					s.fin = true
					s.finOffset = s.sent
					return nil
				},
			},
			{
				Name: "cancelRead",
				When: func(m *streamMachine) bool {
					for _, s := range m.streams {
						if !s.cancelled && !s.eof {
							return true
						}
					}
					return false
				},
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					open := make([]*streamMachineStream, 0, len(m.streams))
					for _, s := range m.streams {
						if !s.cancelled && !s.eof {
							open = append(open, s)
						}
					}
					s := open[t.IntN(len(open))]
					s.rs.CancelRead(StreamErrorCode(t.IntN(8)))
					s.cancelled = true
					return nil
				},
			},
			{
				Name: "advanceTime",
				Apply: func(m *streamMachine, t *fuzztape.Tape) error {
					m.now = m.now.Add(time.Duration(t.IntN(100)) * time.Millisecond)
					return nil
				},
			},
		},
		Check: func(t *testing.T, m *streamMachine) {
			for _, s := range m.streams {
				if s.sent > s.sendWindow {
					t.Fatalf("stream %d: sent %d bytes, granted %d", s.id, s.sent, s.sendWindow)
				}
				if s.readPos > s.sent {
					t.Fatalf("stream %d: read %d bytes, sent %d", s.id, s.readPos, s.sent)
				}
			}
			if m.connSent > m.connSendWindow {
				t.Fatalf("connection: sent %d bytes, granted %d", m.connSent, m.connSendWindow)
			}
			// A queued MAX_DATA frame that the framer doesn't report as
			// data is never packed: the packer asks HasData before it
			// composes a packet, so the peer stays blocked forever once its
			// credit runs out. See "qng: send queued MAX_DATA frames
			// promptly".
			if m.maxDataQueued && !m.framer.HasData() {
				t.Fatalf("framer has a MAX_DATA frame for offset %d queued, but HasData reports no data",
					m.maxDataOffset)
			}
		},
	}
}

func (m *streamMachine) stream(id protocol.StreamID) *streamMachineStream {
	for _, s := range m.streams {
		if s.id == id {
			return s
		}
	}
	return nil
}

// ackFrequencyMachine models the received packet handler and ACK frequency processing under fuzztape.
type ackFrequencyMachine struct {
	t                     *testing.T
	c                     *Conn
	unpatchedHandler      *ackhandler.ReceivedPacketHandler
	receivedAckFreq       bool
	lastSeq               uint64
	lastSeqSet            bool
	lastRequestedMaxAck   time.Duration
	currentAckElicitingPN protocol.PacketNumber
	nextRcvTime           monotime.Time
	immediateAckOccurred  bool
	immediateAckAckQueued bool
}

func newAckFrequencyMachine(t *testing.T) *ackFrequencyMachine {
	cfg := &Config{}
	peer := &wire.TransportParameters{}
	c := &Conn{
		config:      cfg,
		perspective: protocol.PerspectiveClient,
	}
	c.peerParams.Store(peer)
	c.receivedPacketHandler = *ackhandler.NewReceivedPacketHandler(utils.DefaultLogger)
	c.rttStats = utils.NewRTTStats()

	unpatched := ackhandler.NewReceivedPacketHandler(utils.DefaultLogger)

	return &ackFrequencyMachine{
		t:                     t,
		c:                     c,
		unpatchedHandler:      unpatched,
		lastRequestedMaxAck:   protocol.MaxAckDelay,
		nextRcvTime:           monotime.Now(),
		currentAckElicitingPN: 0,
	}
}

func ackFrequencyMachineSpec() fuzztape.Machine[*ackFrequencyMachine] {
	return fuzztape.Machine[*ackFrequencyMachine]{
		Name:   "FuzzAckFrequencyMachine",
		MaxOps: 48,
		Init:   newAckFrequencyMachine,
		Ops: []fuzztape.Op[*ackFrequencyMachine]{
			{
				Name:   "recvDataPacket",
				Weight: 5,
				Apply: func(m *ackFrequencyMachine, t *fuzztape.Tape) error {
					pn := m.currentAckElicitingPN
					m.currentAckElicitingPN++
					now := m.nextRcvTime
					m.nextRcvTime = m.nextRcvTime.Add(time.Duration(1+t.IntN(5)) * time.Millisecond)
					ackEliciting := t.Bool()

					if err := m.c.receivedPacketHandler.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, ackEliciting); err != nil {
						m.t.Fatalf("ReceivedPacket: %v", err)
					}
					if !m.receivedAckFreq {
						if err := m.unpatchedHandler.ReceivedPacket(pn, protocol.ECNNon, protocol.Encryption1RTT, now, ackEliciting); err != nil {
							m.t.Fatalf("unpatched ReceivedPacket: %v", err)
						}
					}
					return nil
				},
			},
			{
				Name:   "recvAckFrequency",
				Weight: 3,
				Apply: func(m *ackFrequencyMachine, t *fuzztape.Tape) error {
					// Choose sequence number: either in-order, out-of-order/stale, or jump ahead
					var seq uint64
					if !m.lastSeqSet {
						seq = uint64(t.IntN(10))
					} else {
						mode := t.IntN(3)
						switch mode {
						case 0: // stale
							if m.lastSeq > 0 {
								seq = uint64(t.IntN(int(m.lastSeq + 1)))
							} else {
								seq = 0
							}
						case 1: // next in-order
							seq = m.lastSeq + 1
						case 2: // jump ahead
							seq = m.lastSeq + uint64(2+t.IntN(5))
						}
					}

					threshold := uint64(1 + t.IntN(32))
					// Delay between 1ms and 100ms
					reqDelay := time.Duration(1+t.IntN(100)) * time.Millisecond
					reordering := protocol.PacketNumber(t.IntN(5))

					prevLastSeq := m.lastSeq
					prevLastSeqSet := m.lastSeqSet
					prevMaxAckDelay := m.lastRequestedMaxAck

					frame := &wire.AckFrequencyFrame{
						SequenceNumber:        seq,
						AckElicitingThreshold: threshold,
						RequestMaxAckDelay:    reqDelay,
						ReorderingThreshold:   reordering,
					}
					err := m.c.handleAckFrequencyFrame(frame, protocol.Encryption1RTT, m.nextRcvTime)
					if err != nil {
						m.t.Fatalf("handleAckFrequencyFrame: %v", err)
					}

					isStale := prevLastSeqSet && seq <= prevLastSeq
					if !isStale {
						m.receivedAckFreq = true
						m.lastSeq = seq
						m.lastSeqSet = true
						m.lastRequestedMaxAck = reqDelay
					} else {
						// Stale frames must not regress sequence or delay
						if m.lastSeq != prevLastSeq || m.lastRequestedMaxAck != prevMaxAckDelay {
							m.t.Fatalf("stale ACK_FREQUENCY regressed state")
						}
					}
					return nil
				},
			},
			{
				Name:   "recvImmediateAck",
				Weight: 2,
				Apply: func(m *ackFrequencyMachine, t *fuzztape.Tape) error {
					err := m.c.handleImmediateAckFrame(&wire.ImmediateAckFrame{}, protocol.Encryption1RTT)
					if err != nil {
						m.t.Fatalf("handleImmediateAckFrame: %v", err)
					}
					m.receivedAckFreq = true
					return nil
				},
			},
			{
				Name:   "timerFire",
				Weight: 2,
				Apply: func(m *ackFrequencyMachine, t *fuzztape.Tape) error {
					// Advance time past alarm
					timeout := m.c.receivedPacketHandler.GetAlarmTimeout()
					if !timeout.IsZero() {
						m.nextRcvTime = timeout.Add(time.Millisecond)
						_ = m.c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, m.nextRcvTime, true)
					}
					if !m.receivedAckFreq {
						timeoutUnpatched := m.unpatchedHandler.GetAlarmTimeout()
						if !timeoutUnpatched.IsZero() {
							_ = m.unpatchedHandler.GetAckFrame(protocol.Encryption1RTT, m.nextRcvTime, true)
						}
					}
					return nil
				},
			},
		},
		Check: func(t *testing.T, m *ackFrequencyMachine) {
			// Invariant 1: Effective max ack delay must be within [min_ack_delay, requestedMaxAckDelay]
			minDelay := protocol.TimerGranularity
			if m.lastRequestedMaxAck < minDelay {
				t.Fatalf("invariant violation: requested max ack delay %v below min_ack_delay %v", m.lastRequestedMaxAck, minDelay)
			}

			// Invariant 2 (GG guard): If no ACK_FREQUENCY/IMMEDIATE_ACK was ever processed, tracker decisions must be bit-identical to unpatched tracker.
			if !m.receivedAckFreq {
				cAlarm := m.c.receivedPacketHandler.GetAlarmTimeout()
				uAlarm := m.unpatchedHandler.GetAlarmTimeout()
				if cAlarm != uAlarm {
					t.Fatalf("GG invariant violation: alarm timeout mismatch: %v vs %v", cAlarm, uAlarm)
				}
				cAck := m.c.receivedPacketHandler.GetAckFrame(protocol.Encryption1RTT, m.nextRcvTime, true)
				uAck := m.unpatchedHandler.GetAckFrame(protocol.Encryption1RTT, m.nextRcvTime, true)
				if (cAck == nil) != (uAck == nil) {
					t.Fatalf("GG invariant violation: queued ack mismatch: %v vs %v", cAck != nil, uAck != nil)
				}
			}
		},
	}
}

func TestAckFrequencyMachine(t *testing.T) {
	ackFrequencyMachineSpec().Run(t, 200)
}

func FuzzAckFrequencyMachine(f *testing.F) {
	ackFrequencyMachineSpec().Fuzz(f)
}
