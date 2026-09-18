package docs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"testing"
)

// headerReader serves a frame header and records whether the body after it was
// read, so a test can tell a length the cap refused outright from one it
// refused only after consuming what followed.
type headerReader struct {
	hdr      []byte
	bodyRead bool
}

func (r *headerReader) Read(p []byte) (int, error) {
	if len(r.hdr) == 0 {
		r.bodyRead = true
		return 0, io.EOF
	}
	n := copy(p, r.hdr)
	r.hdr = r.hdr[n:]
	return n, nil
}

func TestReadSyncFrameRejectsOversizeLength(t *testing.T) {
	tests := []struct {
		name   string
		length uint32
	}{
		{"above cap", maxSyncMessageSize + 1},
		{"former cap", 1024 * 1024 * 1024},
		{"uint32 max", ^uint32(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], tt.length)
			r := &headerReader{hdr: hdr[:]}
			if _, err := readSyncFrame(r); err == nil {
				t.Fatalf("readSyncFrame accepted length %d, want an error", tt.length)
			}
			if r.bodyRead {
				t.Fatalf("readSyncFrame read the body of a %d-byte frame, want the length refused first", tt.length)
			}
		})
	}
}

// TestReadSyncFrameDoesNotPreallocate pins that the read buffer grows with the
// bytes a peer sends and not with the length it claims, so a header alone
// commits nothing.
func TestReadSyncFrameDoesNotPreallocate(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], maxSyncMessageSize)
	frame := append(hdr[:], make([]byte, 8)...)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := readSyncFrame(bytes.NewReader(frame))
	runtime.ReadMemStats(&after)

	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("readSyncFrame err = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > maxSyncMessageSize/16 {
		t.Fatalf("allocated %d bytes for an 8-byte body, want under %d", got, maxSyncMessageSize/16)
	}
}
