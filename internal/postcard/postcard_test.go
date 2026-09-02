package postcard

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

type bag struct {
	N     uint64
	I     int64
	OK    bool
	Name  string
	Bytes []byte
	Fixed [4]byte
}

type blobFormat uint64

const (
	blobRaw blobFormat = iota
	blobHashSeq
)

type hashAndFormat struct {
	Hash   [32]byte
	Format blobFormat
}

type announceKind uint64

const (
	announcePartial announceKind = iota
	announceComplete
)

type absoluteTime uint64

type announce struct {
	Host      [32]byte
	Content   hashAndFormat
	Kind      announceKind
	Timestamp absoluteTime
}

type queryFlags struct {
	Complete bool
	Verified bool
}

type query struct {
	Content hashAndFormat
	Flags   queryFlags
}

type maybeU16 struct {
	Value *uint16
}

type testMessage struct {
	Kind uint64
	One  uint16
	Pair struct {
		A uint8
		B *uint8
	}
	Many []uint16
}

func (m testMessage) EncodePostcard(e *Encoder) error {
	e.Uint(m.Kind)
	switch m.Kind {
	case 0:
		return nil
	case 1:
		return e.Encode(m.One)
	case 2:
		return e.Encode(m.Pair)
	case 3:
		return e.Encode(m.Many)
	default:
		return nil
	}
}

func (m *testMessage) DecodePostcard(d *Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	m.Kind = kind
	switch kind {
	case 0:
		return nil
	case 1:
		return d.Decode(&m.One)
	case 2:
		return d.Decode(&m.Pair)
	case 3:
		return d.Decode(&m.Many)
	default:
		return nil
	}
}

func TestRustVectors(t *testing.T) {
	var fixed [4]byte
	copy(fixed[:], []byte{9, 8, 7, 6})
	var host [32]byte
	for i := range host {
		host[i] = byte(i)
	}
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(0xa0 + i)
	}
	content := hashAndFormat{Hash: hash, Format: blobHashSeq}

	tests := []struct {
		name string
		v    any
		hex  string
	}{
		{name: "u64", v: uint64(624485), hex: "e58e26"},
		{name: "i64", v: int64(-12345), hex: "f1c001"},
		{name: "bool", v: true, hex: "01"},
		{name: "string", v: "hello", hex: "0568656c6c6f"},
		{name: "bytes", v: []byte{1, 2, 3, 4}, hex: "0401020304"},
		{name: "fixed", v: fixed, hex: "09080706"},
		{
			name: "bag",
			v:    bag{N: 624485, I: -12345, OK: true, Name: "hello", Bytes: []byte{1, 2, 3, 4}, Fixed: fixed},
			hex:  "e58e26f1c001010568656c6c6f040102030409080706",
		},
		{
			name: "hash and format",
			v:    content,
			hex:  "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf01",
		},
		{
			name: "announce",
			v: announce{
				Host:      host,
				Content:   content,
				Kind:      announceComplete,
				Timestamp: absoluteTime(1_700_000_000_123_456),
			},
			hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
				"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
				"0101c0c480c1c1c48203",
		},
		{
			name: "query",
			v:    query{Content: content, Flags: queryFlags{Complete: true, Verified: false}},
			hex:  "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf010100",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Marshal(tt.v)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("Marshal = %x, want %s", got, tt.hex)
			}

			dst := reflect.New(reflect.TypeOf(tt.v)).Interface()
			if err := Unmarshal(got, dst); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(dst).Elem().Interface(), tt.v) {
				t.Fatalf("round trip = %#v, want %#v", reflect.ValueOf(dst).Elem().Interface(), tt.v)
			}
		})
	}
}

func TestOptionAndEnumRustVectors(t *testing.T) {
	u300 := uint16(300)
	u9 := uint8(9)
	pair := struct {
		A uint8
		B *uint8
	}{A: 7, B: &u9}

	tests := []struct {
		name string
		v    any
		hex  string
	}{
		{name: "option none", v: maybeU16{}, hex: "00"},
		{name: "option some", v: maybeU16{Value: &u300}, hex: "01ac02"},
		{name: "enum unit", v: testMessage{Kind: 0}, hex: "00"},
		{name: "enum one", v: testMessage{Kind: 1, One: 300}, hex: "01ac02"},
		{name: "enum pair", v: testMessage{Kind: 2, Pair: pair}, hex: "02070109"},
		{name: "enum many", v: testMessage{Kind: 3, Many: []uint16{1, 300, 40000}}, hex: "030301ac02c0b802"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Marshal(tt.v)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("Marshal = %x, want %s", got, tt.hex)
			}
			dst := reflect.New(reflect.TypeOf(tt.v)).Interface()
			if err := Unmarshal(got, dst); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(dst).Elem().Interface(), tt.v) {
				t.Fatalf("round trip = %#v, want %#v", reflect.ValueOf(dst).Elem().Interface(), tt.v)
			}
		})
	}
}

func TestUnmarshalErrors(t *testing.T) {
	var u uint64
	if err := Unmarshal([]byte{0x80}, &u); !errors.Is(err, errShort) {
		t.Fatalf("short varint error = %v", err)
	}
	if err := Unmarshal([]byte{0, 1}, &u); !errors.Is(err, ErrTrailingBytes) {
		t.Fatalf("trailing error = %v", err)
	}
	var b bool
	if err := Unmarshal([]byte{2}, &b); err == nil {
		t.Fatal("Unmarshal accepted invalid bool")
	}
	var s string
	if err := Unmarshal([]byte{1, 0xff}, &s); err == nil {
		t.Fatal("Unmarshal accepted invalid UTF-8")
	}
	var p *uint8
	if err := Unmarshal([]byte{2}, &p); err == nil {
		t.Fatal("Unmarshal accepted invalid option")
	}
}

type eightBit struct {
	U8  uint8
	U16 uint16
	OK  bool
	I8  int8
}

// TestByteSizedRustVectors pins the u8/i8 encoding against Rust postcard, which
// writes both as one raw byte rather than a varint or a zigzag varint. No type
// in this module has an 8-bit field, so nothing else guards it.
func TestByteSizedRustVectors(t *testing.T) {
	tests := []struct {
		name string
		v    any
		hex  string
	}{
		{name: "u8 small", v: uint8(1), hex: "01"},
		{name: "u8 high bit", v: uint8(200), hex: "c8"},
		{name: "u8 max", v: uint8(255), hex: "ff"},
		{name: "i8 zero", v: int8(0), hex: "00"},
		{name: "i8 negative", v: int8(-2), hex: "fe"},
		{name: "i8 min", v: int8(-128), hex: "80"},
		{name: "i8 max", v: int8(127), hex: "7f"},
		{
			name: "mixed struct",
			v:    eightBit{U8: 200, U16: 300, OK: true, I8: -2},
			hex:  "c8ac0201fe",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Marshal(tt.v)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != tt.hex {
				t.Fatalf("Marshal = %s, want %s", hex.EncodeToString(got), tt.hex)
			}
			raw, err := hex.DecodeString(tt.hex)
			if err != nil {
				t.Fatal(err)
			}
			out := reflect.New(reflect.TypeOf(tt.v))
			if err := Unmarshal(raw, out.Interface()); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(out.Elem().Interface(), tt.v) {
				t.Fatalf("Unmarshal = %#v, want %#v", out.Elem().Interface(), tt.v)
			}
		})
	}
}

// TestEncoderByteSizedHelpers checks that the hand-written codec path agrees
// with the reflection path on u8 and i8.
func TestEncoderByteSizedHelpers(t *testing.T) {
	var e Encoder
	e.Uint8(200)
	e.Int8(-2)
	if got := hex.EncodeToString(e.Bytes()); got != "c8fe" {
		t.Fatalf("Encoder = %s, want c8fe", got)
	}
	d := NewDecoder(e.Bytes())
	if u, err := d.Uint8(); err != nil || u != 200 {
		t.Fatalf("Uint8 = %d, %v", u, err)
	}
	if i, err := d.Int8(); err != nil || i != -2 {
		t.Fatalf("Int8 = %d, %v", i, err)
	}
	if !d.Done() {
		t.Fatal("decoder did not consume all input")
	}
}
