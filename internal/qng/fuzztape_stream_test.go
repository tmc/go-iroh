package quic

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/fuzztape"
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
	fc *streamFlowController

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
	t   *fuzztape.T
	now monotime.Time

	connFC *connectionFlowController
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
func (s streamMachineSender) onHasStreamRetransmission(protocol.StreamID, *SendStream)  {}
func (s streamMachineSender) updateStreamPriority(protocol.StreamID)                    {}
func (s streamMachineSender) recordStreamPriorityUpdated(protocol.StreamID, int8, bool) {}

func (s streamMachineSender) onHasStreamControlFrame(id protocol.StreamID, str streamControlFrameGetter) {
	s.m.framer.AddStreamWithControlFrames(id, str)
}

func (s streamMachineSender) onStreamCompleted(protocol.StreamID) {}

func newStreamMachine(t *fuzztape.T) *streamMachine {
	rttStats := utils.NewRTTStats()
	connFC := newConnectionFlowController(
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
		framer:         newFramer(noopConnFC()),
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
				Apply: func(t *fuzztape.T, m *streamMachine) {
					id := m.nextID
					m.nextID += 4
					fc := newStreamFlowController(
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
				Apply: func(t *fuzztape.T, m *streamMachine) {
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
				Apply: func(t *fuzztape.T, m *streamMachine) {
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
				Apply: func(t *fuzztape.T, m *streamMachine) {
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
						t.Fatalf("stream %d: Read blocked with %d bytes buffered (read %d, sent %d)",
							s.id, s.sent-s.readPos, s.readPos, s.sent)
					}
					for i := range n {
						want := streamMachineData(s.id, s.readPos+protocol.ByteCount(i))
						if buf[i] != want {
							t.Fatalf("stream %d: Read at offset %d = %#x, want %#x",
								s.id, s.readPos+protocol.ByteCount(i), buf[i], want)
						}
					}
					s.readPos += protocol.ByteCount(n)
					if s.readPos > s.sent {
						t.Fatalf("stream %d: read %d bytes, but only %d were sent", s.id, s.readPos, s.sent)
					}
					var streamErr *StreamError
					switch {
					case err == nil:
					case errors.Is(err, io.EOF), errors.As(err, &streamErr):
						s.eof = true
					default:
						t.Fatalf("stream %d: Read: %v", s.id, err)
					}
				},
			},
			{
				Name:   "connWindowUpdate",
				Weight: 3,
				Apply: func(t *fuzztape.T, m *streamMachine) {
					// This mirrors Conn.sendPackets: whenever the send loop
					// runs, a pending connection-level window update is
					// queued as a MAX_DATA frame.
					m.connData = false
					offset := m.connFC.GetWindowUpdate(m.now)
					if offset == 0 {
						return
					}
					m.framer.QueueMaxDataFrame(offset)
					m.maxDataQueued = true
					if offset > m.maxDataOffset {
						m.maxDataOffset = offset
					}
				},
			},
			{
				Name:   "packPacket",
				Weight: 5,
				Apply: func(t *fuzztape.T, m *streamMachine) {
					size := fuzztape.Pick(t.Tape, []protocol.ByteCount{1200, 128, 64, 32, 26, 1452})
					pl := m.packer.composeNextPacket(size, false, true, m.now, protocol.Version1)
					if pl.hasStreamFrame || len(pl.streamFrames) > 0 {
						t.Fatalf("packed %d STREAM frames, but no stream is sending", pl.numStreamFrames())
					}
					for _, f := range pl.frames {
						switch frame := f.Frame.(type) {
						case *wire.MaxDataFrame:
							if frame.MaximumData < m.connSendWindow {
								t.Fatalf("MAX_DATA = %d, below the already granted %d",
									frame.MaximumData, m.connSendWindow)
							}
							m.connSendWindow = frame.MaximumData
							m.maxDataQueued = false
						case *wire.MaxStreamDataFrame:
							s := m.stream(frame.StreamID)
							if s == nil {
								t.Fatalf("MAX_STREAM_DATA for unknown stream %d", frame.StreamID)
								return
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
								t.Fatalf("STOP_SENDING for unknown stream %d", frame.StreamID)
							}
						}
					}
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
				Apply: func(t *fuzztape.T, m *streamMachine) {
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
						t.Fatalf("stream %d: handleResetStreamFrame(final %d): %v", s.id, s.sent, err)
					}
					s.reset = true
					s.fin = true
					s.finOffset = s.sent
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
				Apply: func(t *fuzztape.T, m *streamMachine) {
					open := make([]*streamMachineStream, 0, len(m.streams))
					for _, s := range m.streams {
						if !s.cancelled && !s.eof {
							open = append(open, s)
						}
					}
					s := open[t.IntN(len(open))]
					s.rs.CancelRead(StreamErrorCode(t.IntN(8)))
					s.cancelled = true
				},
			},
			{
				Name: "advanceTime",
				Apply: func(t *fuzztape.T, m *streamMachine) {
					m.now = m.now.Add(time.Duration(t.IntN(100)) * time.Millisecond)
				},
			},
		},
		Check: func(t *fuzztape.T, m *streamMachine) {
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

// pathCIDMachine models the per-path CID generator and state machine under fuzztape.
type pathCIDMachine struct {
	t             *fuzztape.T
	g             *connIDGenerator
	frames        []wire.Frame
	addedCIDs     []protocol.ConnectionID
	retiredCIDs   map[protocol.PathID]map[protocol.ConnectionID]bool
	cidSeenAcross map[protocol.ConnectionID]protocol.PathID

	multipathNegotiated bool
	handshakeConfirmed  bool
	peerLimit           uint64
	localMaxPathID      protocol.PathID
	peerMaxPathID       protocol.PathID
	parser              wire.FrameParser

	receivedPathCIDsBlocked bool
}

func newPathCIDMachine(t *fuzztape.T) *pathCIDMachine {
	m := &pathCIDMachine{
		t:                   t,
		retiredCIDs:         make(map[protocol.PathID]map[protocol.ConnectionID]bool),
		cidSeenAcross:       make(map[protocol.ConnectionID]protocol.PathID),
		multipathNegotiated: true,
		peerLimit:           protocol.DefaultActiveConnectionIDLimit,
		localMaxPathID:      4,
		peerMaxPathID:       0,
		parser:              *wire.NewFrameParser(true, true, true, true),
	}

	initial := protocol.ParseConnectionID([]byte{0x00, 0x11, 0x22, 0x33})
	m.g = newConnIDGenerator(
		stubConnRunner{},
		initial,
		nil,
		newStatelessResetter(nil),
		connRunnerCallbacks{
			AddConnectionID: func(id protocol.ConnectionID) {
				m.addedCIDs = append(m.addedCIDs, id)
			},
			RemoveConnectionID: func(protocol.ConnectionID) {},
			ReplaceWithClosed:  func([]protocol.ConnectionID, []byte, time.Duration) {},
		},
		func(f wire.Frame) {
			m.frames = append(m.frames, f)
		},
		&protocol.DefaultConnectionIDGenerator{ConnLen: 4},
	)
	m.cidSeenAcross[initial] = protocol.PathIDZero
	return m
}

func (m *pathCIDMachine) budget() uint64 {
	return min(m.peerLimit, protocol.MaxIssuedConnectionIDs)
}

func (m *pathCIDMachine) effectiveMaxPathID() protocol.PathID {
	if m.localMaxPathID < m.peerMaxPathID {
		return m.localMaxPathID
	}
	return m.peerMaxPathID
}

func pathCIDMachineSpec() fuzztape.Machine[*pathCIDMachine] {
	return fuzztape.Machine[*pathCIDMachine]{
		Name:   "FuzzPathCIDMachine",
		MaxOps: 48,
		Init:   newPathCIDMachine,
		Ops: []fuzztape.Op[*pathCIDMachine]{
			{
				Name:   "drawInitialTransportParams",
				Weight: 3,
				When:   func(m *pathCIDMachine) bool { return !m.handshakeConfirmed },
				Apply: func(t *fuzztape.T, m *pathCIDMachine) {
					// Draw active_connection_id_limit in [2, 8]
					m.peerLimit = uint64(2 + t.IntN(7))
					if err := m.g.SetMaxActiveConnIDs(m.peerLimit); err != nil {
						t.Fatalf("SetMaxActiveConnIDs: %v", err)
					}
					// Draw local and peer initial_max_path_id in [1, 8]
					m.localMaxPathID = protocol.PathID(1 + t.IntN(8))
					m.peerMaxPathID = protocol.PathID(1 + t.IntN(8))
				},
			},
			{
				Name:   "handshakeComplete",
				Weight: 2,
				When:   func(m *pathCIDMachine) bool { return !m.handshakeConfirmed },
				Apply: func(t *fuzztape.T, m *pathCIDMachine) {
					m.handshakeConfirmed = true
					effectiveMax := m.effectiveMaxPathID()
					if m.multipathNegotiated && effectiveMax > 0 {
						if err := m.g.IssueFirstPathCIDs(effectiveMax); err != nil {
							t.Fatalf("IssueFirstPathCIDs on handshakeComplete: %v", err)
						}
					}
				},
			},
			{
				Name:   "raiseMaxPathID",
				Weight: 4,
				When:   func(m *pathCIDMachine) bool { return m.peerMaxPathID < 8 },
				Apply: func(t *fuzztape.T, m *pathCIDMachine) {
					delta := protocol.PathID(1 + t.IntN(3))
					newMax := m.peerMaxPathID + delta
					if newMax > 8 {
						newMax = 8
					}
					m.peerMaxPathID = newMax
					effectiveMax := m.effectiveMaxPathID()
					if m.handshakeConfirmed && m.multipathNegotiated && effectiveMax > 0 {
						if err := m.g.IssueFirstPathCIDs(effectiveMax); err != nil {
							t.Fatalf("IssueFirstPathCIDs on raiseMaxPathID: %v", err)
						}
					}
				},
			},
			{
				Name:   "peerLimitRenegotiation",
				Weight: 2,
				Apply: func(t *fuzztape.T, m *pathCIDMachine) {
					// In QUIC, active_connection_id_limit can increase
					limit := m.peerLimit + uint64(1+t.IntN(4))
					if limit > protocol.MaxIssuedConnectionIDs {
						limit = protocol.MaxIssuedConnectionIDs
					}
					m.peerLimit = limit
					if err := m.g.SetMaxActiveConnIDs(limit); err != nil {
						t.Fatalf("SetMaxActiveConnIDs: %v", err)
					}
				},
			},
			{
				Name:   "retireCID",
				Weight: 5,
				When: func(m *pathCIDMachine) bool {
					effectiveMax := m.effectiveMaxPathID()
					for pid := protocol.PathID(1); pid <= effectiveMax; pid++ {
						if len(m.g.pathSrcConnIDs[pid]) > 0 {
							return true
						}
					}
					return false
				},
				Apply: func(t *fuzztape.T, m *pathCIDMachine) {
					type activeCID struct {
						pid protocol.PathID
						seq uint64
						cid protocol.ConnectionID
					}
					var candidates []activeCID
					effectiveMax := m.effectiveMaxPathID()
					for pid := protocol.PathID(1); pid <= effectiveMax; pid++ {
						for seq, cid := range m.g.pathSrcConnIDs[pid] {
							candidates = append(candidates, activeCID{pid: pid, seq: seq, cid: cid})
						}
					}
					if len(candidates) == 0 {
						return
					}
					c := candidates[t.IntN(len(candidates))]
					if m.retiredCIDs[c.pid] == nil {
						m.retiredCIDs[c.pid] = make(map[protocol.ConnectionID]bool)
					}
					m.retiredCIDs[c.pid][c.cid] = true

					// Retire using a dummy destination connection ID
					if err := m.g.RetirePath(c.pid, c.seq, protocol.ParseConnectionID([]byte{0xfe, 0xdc, 0xba, 0x98}), monotime.Now()); err != nil {
						t.Fatalf("RetirePath(path %d, seq %d): %v", c.pid, c.seq, err)
					}
				},
			},
			{
				Name: "receivePathCIDsBlocked",
				When: func(m *pathCIDMachine) bool {
					effectiveMax := m.effectiveMaxPathID()
					if !m.handshakeConfirmed || effectiveMax == 0 {
						return false
					}
					for pid := protocol.PathID(1); pid <= effectiveMax; pid++ {
						if len(m.g.pathSrcConnIDs[pid]) == 0 {
							return true
						}
					}
					return false
				},
				Apply: func(t *fuzztape.T, m *pathCIDMachine) {
					m.receivedPathCIDsBlocked = true
				},
			},
		},
		Check: func(t *fuzztape.T, m *pathCIDMachine) {
			// Invariant: receiving PATH_CIDS_BLOCKED at all is a failure (a correct issuer never lets the peer starve)
			if m.receivedPathCIDsBlocked {
				t.Fatalf("invariant violation: received PATH_CIDS_BLOCKED (a correct issuer never lets the peer starve)")
			}

			effectiveMax := m.effectiveMaxPathID()
			perPathSeenSeqs := make(map[protocol.PathID]map[uint64]bool)
			for _, f := range m.frames {
				nc, ok := f.(*wire.NewConnectionIDFrame)
				if !ok {
					t.Fatalf("unexpected frame type: %T", f)
				}
				if nc.PathID == nil {
					// Path 0 CID
					continue
				}
				pid := *nc.PathID
				// Invariant 1: PathIDZero never in a PATH_NEW_CONNECTION_ID frame
				if pid == protocol.PathIDZero {
					t.Fatalf("invariant violation: PathIDZero in PATH_NEW_CONNECTION_ID frame")
				}
				// Invariant 2: No PATH_NEW_CONNECTION_ID with path_id > min(local, peer max)
				if pid > effectiveMax {
					t.Fatalf("invariant violation: emitted PATH_NEW_CONNECTION_ID for path %d > effectiveMax %d", pid, effectiveMax)
				}

				if perPathSeenSeqs[pid] == nil {
					perPathSeenSeqs[pid] = make(map[uint64]bool)
				}
				perPathSeenSeqs[pid][nc.SequenceNumber] = true

				// Invariant: No CID reuse across paths
				if prevPid, ok := m.cidSeenAcross[nc.ConnectionID]; ok && prevPid != pid {
					t.Fatalf("invariant violation: CID %s reused across path %d and path %d", nc.ConnectionID, prevPid, pid)
				}
				m.cidSeenAcross[nc.ConnectionID] = pid

				// Invariant 3: Every emitted advertised-implied frame type must parse in 1-RTT
				data, err := nc.Append(nil, protocol.Version1)
				if err != nil {
					t.Fatalf("invariant violation: failed to append frame: %v", err)
				}
				ft, l, err := m.parser.ParseType(data, protocol.Encryption1RTT)
				if err != nil {
					t.Fatalf("invariant violation: emitted frame failed ParseType: %v", err)
				}
				parsedFrame, _, err := m.parser.ParseLessCommonFrame(ft, data[l:], protocol.Version1)
				if err != nil {
					t.Fatalf("invariant violation: emitted frame failed ParseLessCommonFrame: %v", err)
				}
				if parsedFrame == nil {
					t.Fatalf("invariant violation: parsed frame is nil")
				}
			}

			// Invariant: per-path sequence numbers strictly monotonic starting at 0 (no gaps)
			for pid, seqs := range perPathSeenSeqs {
				for i := uint64(0); i < uint64(len(seqs)); i++ {
					if !seqs[i] {
						t.Fatalf("path %d sequence numbers not strictly monotonic: missing seq %d out of %d issued", pid, i, len(seqs))
					}
				}
			}

			// Invariant 4: Per-path active CID count (issued minus retired) never exceeds peer's advertised limit
			b := m.budget()
			for pid := protocol.PathID(1); pid <= 8; pid++ {
				activeCount := uint64(len(m.g.pathSrcConnIDs[pid]))
				if activeCount > m.peerLimit {
					t.Fatalf("invariant violation: path %d active pool size = %d exceeds peer limit %d", pid, activeCount, m.peerLimit)
				}
				if m.handshakeConfirmed && pid <= effectiveMax {
					if activeCount != b {
						t.Fatalf("invariant violation: path %d active pool size = %d, want budget %d", pid, activeCount, b)
					}
				}
			}
		},
	}
}

func TestPathCIDMachine(t *testing.T) {
	pathCIDMachineSpec().Run(t, 200)
}

func FuzzPathCIDMachine(f *testing.F) {
	pathCIDMachineSpec().Fuzz(f)
}
