package gossipproto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	topic := TopicID(seq32(1))
	msg := Message{
		Topic: topic,
		Message: TopicMessage{
			Kind: TopicMessageGossip,
			Gossip: PlumtreeMessage{
				Kind:   PlumtreeGossip,
				Gossip: Gossip{ID: MessageIDFromContent([]byte("hello")), Content: []byte("hello")},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, StreamHeader{Topic: topic}, DefaultMaxMessageSize); err != nil {
		t.Fatalf("WriteFrame header: %v", err)
	}
	if err := WriteFrame(&buf, msg.Message, DefaultMaxMessageSize); err != nil {
		t.Fatalf("WriteFrame message: %v", err)
	}

	if got := binary.BigEndian.Uint32(buf.Bytes()[:4]); got != 32 {
		t.Fatalf("header length = %d, want 32", got)
	}
	var gotHeader StreamHeader
	if err := ReadFrame(&buf, &gotHeader, DefaultMaxMessageSize); err != nil {
		t.Fatalf("ReadFrame header: %v", err)
	}
	if gotHeader != (StreamHeader{Topic: topic}) {
		t.Fatalf("header = %#v, want %#v", gotHeader, StreamHeader{Topic: topic})
	}
	var gotMessage TopicMessage
	if err := ReadFrame(&buf, &gotMessage, DefaultMaxMessageSize); err != nil {
		t.Fatalf("ReadFrame message: %v", err)
	}
	if !reflect.DeepEqual(gotMessage, msg.Message) {
		t.Fatalf("message = %#v, want %#v", gotMessage, msg.Message)
	}
}

func TestRustFrameVectors(t *testing.T) {
	topic := TopicID(seq32(0))
	tests := []struct {
		name string
		v    any
		hex  string
	}{
		{
			name: "stream header",
			v:    StreamHeader{Topic: topic},
			hex:  "00000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		},
		{
			name: "topic prune",
			v: TopicMessage{
				Kind:   TopicMessageGossip,
				Gossip: PlumtreeMessage{Kind: PlumtreePrune},
			},
			hex: "000000020101",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, tt.v, DefaultMaxMessageSize); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			if got := hex.EncodeToString(buf.Bytes()); got != tt.hex {
				t.Fatalf("frame = %s, want %s", got, tt.hex)
			}
			dst := reflect.New(reflect.TypeOf(tt.v)).Interface()
			if err := ReadFrame(&buf, dst, DefaultMaxMessageSize); err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(dst).Elem().Interface(), tt.v) {
				t.Fatalf("round trip = %#v, want %#v", reflect.ValueOf(dst).Elem().Interface(), tt.v)
			}
		})
	}
}

func TestFrameTooLarge(t *testing.T) {
	var buf bytes.Buffer
	err := WriteFrame(&buf, make([]byte, MinMaxMessageSize), MinMaxMessageSize)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame err = %v, want ErrFrameTooLarge", err)
	}

	var raw bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], MinMaxMessageSize+1)
	raw.Write(hdr[:])
	raw.Write(make([]byte, MinMaxMessageSize+1))
	err = ReadFrame(&raw, &StreamHeader{}, MinMaxMessageSize)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame err = %v, want ErrFrameTooLarge", err)
	}
}

func TestNormalizeMaxMessageSize(t *testing.T) {
	tests := []struct {
		name string
		in   int
		want int
	}{
		{name: "zero", in: 0, want: DefaultMaxMessageSize},
		{name: "negative", in: -1, want: DefaultMaxMessageSize},
		{name: "below minimum", in: MinMaxMessageSize - 1, want: MinMaxMessageSize},
		{name: "minimum", in: MinMaxMessageSize, want: MinMaxMessageSize},
		{name: "larger", in: 8192, want: 8192},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeMaxMessageSize(tt.in); got != tt.want {
				t.Fatalf("NormalizeMaxMessageSize(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestFrameUsesMinimumMaxMessageSize(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, StreamHeader{}, 1); err != nil {
		t.Fatalf("WriteFrame below minimum: %v", err)
	}
	var got StreamHeader
	if err := ReadFrame(&buf, &got, 1); err != nil {
		t.Fatalf("ReadFrame below minimum: %v", err)
	}
}

func TestFrameShortRead(t *testing.T) {
	err := ReadFrame(bytes.NewReader([]byte{0, 0}), &StreamHeader{}, DefaultMaxMessageSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short length err = %v, want io.ErrUnexpectedEOF", err)
	}

	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 8)
	buf.Write(hdr[:])
	buf.Write([]byte{1, 2})
	err = ReadFrame(&buf, &StreamHeader{}, DefaultMaxMessageSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short body err = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadFrameRejectsOversizedLength(t *testing.T) {
	tests := []struct {
		name string
		hdr  uint32
	}{
		{"just over", DefaultMaxMessageSize + 1},
		{"high bit set", 1 << 31},
		{"max uint32", ^uint32(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], tt.hdr)
			buf.Write(hdr[:])
			err := ReadFrame(&buf, &StreamHeader{}, DefaultMaxMessageSize)
			if !errors.Is(err, ErrFrameTooLarge) {
				t.Fatalf("ReadFrame err = %v, want ErrFrameTooLarge", err)
			}
		})
	}
}
