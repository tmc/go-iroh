package quic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/ackhandler"
	"github.com/tmc/go-iroh/internal/qng/internal/monotime"
	"github.com/tmc/go-iroh/internal/qng/internal/protocol"
	"github.com/tmc/go-iroh/internal/qng/internal/utils"
	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

type stubFrameSource struct {
	blockedFrames  []wire.Frame
	singleFrame    ackhandler.StreamFrame
	hasSingleFrame bool
	streamFrames   []ackhandler.StreamFrame
}

func (f *stubFrameSource) HasData() bool {
	return len(f.blockedFrames) > 0 || f.hasSingleFrame || len(f.streamFrames) > 0
}

func (f *stubFrameSource) AppendControlFrames(frames []ackhandler.Frame, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	return frames, 0
}

func (f *stubFrameSource) AppendStreamFrames(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	_ protocol.ByteCount,
	v protocol.Version,
) ([]ackhandler.Frame, ackhandler.StreamFrame, bool, []ackhandler.StreamFrame, protocol.ByteCount) {
	var lengthAdded protocol.ByteCount
	for _, bf := range f.blockedFrames {
		frames = append(frames, ackhandler.Frame{Frame: bf})
		lengthAdded += bf.Length(v)
	}
	if f.hasSingleFrame {
		lengthAdded += f.singleFrame.Frame.Length(v)
	}
	for _, sf := range f.streamFrames {
		streamFrames = append(streamFrames, sf)
		lengthAdded += sf.Frame.Length(v)
	}
	return frames, f.singleFrame, f.hasSingleFrame, streamFrames, lengthAdded
}

type stubAckSource struct {
	ack *wire.AckFrame
}

func (a *stubAckSource) GetAckFrame(_ protocol.EncryptionLevel, _ monotime.Time, _ bool) *wire.AckFrame {
	return a.ack
}

func (a *stubAckSource) GetAckFrameForPath(_ protocol.PathID, _ monotime.Time, _ bool) *wire.AckFrame {
	return a.ack
}

func TestComposeNextPacketDatagramLengthWithStreamFrames(t *testing.T) {
	tests := []struct {
		name               string
		ack                *wire.AckFrame
		datagrams          [][]byte
		blockedFrames      []wire.Frame
		singleStream       []byte
		sliceStreams       [][]byte
		wantDataLenPresent []bool
		wantOrder          []string // expected parsed frame kinds in wire order
	}{
		{
			name:               "one_datagram_before_single_stream_frame",
			datagrams:          [][]byte{bytes.Repeat([]byte("d"), 20)},
			singleStream:       []byte("hello-stream"),
			wantDataLenPresent: []bool{true},
			wantOrder:          []string{"DATAGRAM", "STREAM"},
		},
		{
			name:               "two_datagrams_before_single_stream_frame",
			datagrams:          [][]byte{[]byte("first-dg"), []byte("second-dg")},
			singleStream:       []byte("hello-stream"),
			wantDataLenPresent: []bool{true, true},
			wantOrder:          []string{"DATAGRAM", "DATAGRAM", "STREAM"},
		},
		{
			name:               "one_datagram_before_multiple_stream_frames",
			datagrams:          [][]byte{[]byte("dg-payload")},
			sliceStreams:       [][]byte{[]byte("stream-0"), []byte("stream-1")},
			wantDataLenPresent: []bool{true},
			wantOrder:          []string{"DATAGRAM", "STREAM", "STREAM"},
		},
		{
			name:               "one_datagram_without_stream_frames_elides_length",
			datagrams:          [][]byte{bytes.Repeat([]byte("d"), 20)},
			wantDataLenPresent: []bool{false},
			wantOrder:          []string{"DATAGRAM"},
		},
		{
			name:               "two_datagrams_without_stream_frames_elides_last_length",
			datagrams:          [][]byte{[]byte("first-dg"), []byte("second-dg")},
			wantDataLenPresent: []bool{true, false},
			wantOrder:          []string{"DATAGRAM", "DATAGRAM"},
		},
		{
			name:      "datagram_reordered_after_blocked_frames_without_stream",
			datagrams: [][]byte{[]byte("dg-last")},
			blockedFrames: []wire.Frame{
				&wire.StreamDataBlockedFrame{StreamID: 4, MaximumStreamData: 1024},
				&wire.DataBlockedFrame{MaximumData: 2048},
			},
			wantDataLenPresent: []bool{false},
			wantOrder:          []string{"STREAM_DATA_BLOCKED", "DATA_BLOCKED", "DATAGRAM"},
		},
		{
			name:      "datagram_reordered_after_blocked_frames_before_single_stream",
			datagrams: [][]byte{[]byte("dg-mid-1"), []byte("dg-mid-2")},
			blockedFrames: []wire.Frame{
				&wire.StreamDataBlockedFrame{StreamID: 4, MaximumStreamData: 1024},
				&wire.DataBlockedFrame{MaximumData: 2048},
			},
			singleStream:       []byte("after-blocked-and-dg"),
			wantDataLenPresent: []bool{true, true},
			wantOrder:          []string{"STREAM_DATA_BLOCKED", "DATA_BLOCKED", "DATAGRAM", "DATAGRAM", "STREAM"},
		},
		{
			name: "ack_and_datagram_before_single_stream_frame",
			ack: &wire.AckFrame{
				AckRanges: []wire.AckRange{{Smallest: 1, Largest: 3}},
			},
			datagrams:          [][]byte{[]byte("dg-after-ack")},
			singleStream:       []byte("stream-after-dg"),
			wantDataLenPresent: []bool{true},
			wantOrder:          []string{"ACK", "DATAGRAM", "STREAM"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dq := newDatagramQueue(func() {}, utils.DefaultLogger, nil)
			for _, d := range tc.datagrams {
				if err := dq.Add(&wire.DatagramFrame{Data: d, DataLenPresent: true}); err != nil {
					t.Fatalf("Add datagram: %v", err)
				}
			}

			fs := &stubFrameSource{blockedFrames: tc.blockedFrames}
			var wantStreams [][]byte
			if tc.singleStream != nil {
				fs.hasSingleFrame = true
				fs.singleFrame = ackhandler.StreamFrame{
					Frame: &wire.StreamFrame{
						StreamID:       0,
						Data:           tc.singleStream,
						DataLenPresent: false,
					},
				}
				wantStreams = append(wantStreams, tc.singleStream)
			}
			for i, s := range tc.sliceStreams {
				fs.streamFrames = append(fs.streamFrames, ackhandler.StreamFrame{
					Frame: &wire.StreamFrame{
						StreamID:       protocol.StreamID(i * 4),
						Data:           s,
						DataLenPresent: i < len(tc.sliceStreams)-1,
					},
				})
				wantStreams = append(wantStreams, s)
			}

			packer := &packetPacker{
				framer:               fs,
				acks:                 &stubAckSource{ack: tc.ack},
				datagramQueue:        dq,
				maxDatagramFrameSize: protocol.MaxPacketBufferSize,
				retransmissionQueue:  newRetransmissionQueue(),
				rand:                 *rand.New(rand.NewPCG(1, 2)),
			}

			pl := packer.composeNextPacket(protocol.MaxPacketBufferSize, false, tc.ack != nil, monotime.Now(), protocol.Version1)
			wantNonAckFrames := len(tc.blockedFrames) + len(tc.wantDataLenPresent)
			if len(pl.frames) != wantNonAckFrames {
				t.Fatalf("len(pl.frames) = %d, want %d", len(pl.frames), wantNonAckFrames)
			}
			// Blocked frames must have been reordered before DATAGRAM frames.
			dgStart := len(tc.blockedFrames)
			for i, wantPresent := range tc.wantDataLenPresent {
				df, ok := pl.frames[dgStart+i].Frame.(*wire.DatagramFrame)
				if !ok {
					t.Fatalf("pl.frames[%d].Frame = %T, want *wire.DatagramFrame", dgStart+i, pl.frames[dgStart+i].Frame)
				}
				if df.DataLenPresent != wantPresent {
					t.Fatalf("datagram[%d].DataLenPresent = %v, want %v", i, df.DataLenPresent, wantPresent)
				}
			}

			raw, err := packer.appendPacketPayload(nil, pl, 0, protocol.Version1)
			if err != nil {
				t.Fatalf("appendPacketPayload: %v", err)
			}
			if protocol.ByteCount(len(raw)) != pl.length {
				t.Fatalf("serialized payload len = %d, pl.length = %d", len(raw), pl.length)
			}

			parser := wire.NewFrameParser(true, false, false, false)
			var gotOrder []string
			var gotDatagrams [][]byte
			var gotStreams [][]byte
			for len(raw) > 0 {
				ft, l, err := parser.ParseType(raw, protocol.Encryption1RTT)
				if err != nil {
					t.Fatalf("ParseType: %v", err)
				}
				raw = raw[l:]
				switch {
				case ft.IsAckFrameType():
					_, n, err := parser.ParseAckFrame(ft, raw, protocol.Encryption1RTT, protocol.Version1)
					if err != nil {
						t.Fatalf("ParseAckFrame: %v", err)
					}
					raw = raw[n:]
					gotOrder = append(gotOrder, "ACK")
				case ft.IsDatagramFrameType():
					f, n, err := parser.ParseDatagramFrame(ft, raw, protocol.Version1)
					if err != nil {
						t.Fatalf("ParseDatagramFrame: %v", err)
					}
					raw = raw[n:]
					gotOrder = append(gotOrder, "DATAGRAM")
					gotDatagrams = append(gotDatagrams, append([]byte(nil), f.Data...))
				case ft.IsStreamFrameType():
					f, n, err := parser.ParseStreamFrame(ft, raw, protocol.Version1)
					if err != nil {
						t.Fatalf("ParseStreamFrame: %v", err)
					}
					raw = raw[n:]
					gotOrder = append(gotOrder, "STREAM")
					gotStreams = append(gotStreams, append([]byte(nil), f.Data...))
				default:
					f, n, err := parser.ParseLessCommonFrame(ft, raw, protocol.Version1)
					if err != nil {
						t.Fatalf("ParseLessCommonFrame(%v): %v", ft, err)
					}
					raw = raw[n:]
					switch f.(type) {
					case *wire.StreamDataBlockedFrame:
						gotOrder = append(gotOrder, "STREAM_DATA_BLOCKED")
					case *wire.DataBlockedFrame:
						gotOrder = append(gotOrder, "DATA_BLOCKED")
					default:
						t.Fatalf("unexpected frame %T", f)
					}
				}
			}

			if len(gotOrder) != len(tc.wantOrder) {
				t.Fatalf("parsed frame order = %v, want %v", gotOrder, tc.wantOrder)
			}
			// appendPacketPayload shuffles non-datagram control frames before
			// DATAGRAMs, so compare the blocked-frame prefix as a set and the
			// remaining ACK / DATAGRAM / STREAM positions strictly.
			ackOffset := 0
			if tc.ack != nil {
				if gotOrder[0] != "ACK" {
					t.Fatalf("parsed frame order = %v, want ACK first", gotOrder)
				}
				ackOffset = 1
			}
			blockedEnd := ackOffset + len(tc.blockedFrames)
			gotBlocked := slices.Clone(gotOrder[ackOffset:blockedEnd])
			wantBlocked := slices.Clone(tc.wantOrder[ackOffset:blockedEnd])
			slices.Sort(gotBlocked)
			slices.Sort(wantBlocked)
			if !slices.Equal(gotBlocked, wantBlocked) {
				t.Fatalf("blocked prefix = %v, want %v (full order %v)", gotOrder[ackOffset:blockedEnd], tc.wantOrder[ackOffset:blockedEnd], gotOrder)
			}
			if !slices.Equal(gotOrder[blockedEnd:], tc.wantOrder[blockedEnd:]) {
				t.Fatalf("post-blocked frame order = %v, want %v (full order %v)", gotOrder[blockedEnd:], tc.wantOrder[blockedEnd:], gotOrder)
			}
			if len(gotDatagrams) != len(tc.datagrams) {
				t.Fatalf("got %d datagrams, want %d", len(gotDatagrams), len(tc.datagrams))
			}
			for i := range tc.datagrams {
				if !bytes.Equal(gotDatagrams[i], tc.datagrams[i]) {
					t.Fatalf("datagram[%d] = %q (%d bytes), want %q (%d bytes)", i, gotDatagrams[i], len(gotDatagrams[i]), tc.datagrams[i], len(tc.datagrams[i]))
				}
			}
			if len(gotStreams) != len(wantStreams) {
				t.Fatalf("got %d stream frames, want %d", len(gotStreams), len(wantStreams))
			}
			for i := range wantStreams {
				if !bytes.Equal(gotStreams[i], wantStreams[i]) {
					t.Fatalf("stream[%d] = %q, want %q", i, gotStreams[i], wantStreams[i])
				}
			}
		})
	}
}

func TestDatagramAndStreamInterleaved(t *testing.T) {
	serverTLS, clientTLS, _, _, _, _ := multipathTLSConfigs(t)

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	tr := &Transport{Conn: serverUDP}
	defer tr.Close()

	ln, err := tr.Listen(serverTLS, &Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const rounds = 20
	var wantStream bytes.Buffer
	for i := range rounds {
		fmt.Fprintf(&wantStream, "stream-chunk-%02d\n", i)
	}

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.CloseWithError(0, "")

		dgDone := make(chan error, 1)
		go func() {
			for {
				dg, err := conn.ReceiveDatagram(ctx)
				if err != nil {
					dgDone <- nil
					return
				}
				if len(dg) != 20 || !bytes.HasPrefix(dg, []byte("dg-")) {
					dgDone <- fmt.Errorf("corrupted datagram %q (%d bytes), want 20-byte dg-*", dg, len(dg))
					return
				}
			}
		}()

		st, err := conn.AcceptStream(ctx)
		if err != nil {
			srvErr <- err
			return
		}
		got, err := io.ReadAll(st)
		if err != nil {
			srvErr <- err
			return
		}
		if !bytes.Equal(got, wantStream.Bytes()) {
			srvErr <- fmt.Errorf("stream payload mismatch: got %d bytes, want %d bytes", len(got), wantStream.Len())
			return
		}
		_ = conn.CloseWithError(0, "done")
		srvErr <- <-dgDone
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	clientConn, err := Dial(ctx, clientUDP, serverUDP.LocalAddr(), clientTLS, &Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.CloseWithError(0, "")

	st, err := clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range rounds {
		dg := fmt.Sprintf("dg-%02d-xxxxxxxxxxxxxx", i)
		if err := clientConn.SendDatagram([]byte(dg)); err != nil {
			t.Fatalf("SendDatagram %d: %v", i, err)
		}
		if _, err := fmt.Fprintf(st, "stream-chunk-%02d\n", i); err != nil {
			t.Fatalf("stream Write %d: %v", i, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	if err := <-srvErr; err != nil {
		t.Fatal(err)
	}
}
