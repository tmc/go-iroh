// Package postcard encodes and decodes the Rust postcard wire format.
//
// Integers are varints, little-endian base-128, and signed integers are
// zigzagged first, except for u8 and i8: postcard writes those as one raw byte.
// Go values of kind uint8 and int8 follow that rule, so uint8(200) encodes as
// "c8" and int8(-2) as "fe".
package postcard

import (
	"encoding"
	"errors"
	"fmt"
	"math"
	"reflect"
	"unicode/utf8"
)

// Marshaler is implemented by values with a custom postcard representation.
type Marshaler interface {
	MarshalPostcard() ([]byte, error)
}

// EncoderTo is implemented by values that encode themselves to e.
type EncoderTo interface {
	EncodePostcard(*Encoder) error
}

// DecoderFrom is implemented by values that decode themselves from d.
type DecoderFrom interface {
	DecodePostcard(*Decoder) error
}

var (
	// ErrTrailingBytes is returned when Unmarshal does not consume all input.
	ErrTrailingBytes = errors.New("postcard: trailing bytes")
	errShort         = errors.New("postcard: truncated input")
)

// Marshal encodes v in postcard format.
func Marshal(v any) ([]byte, error) {
	var e Encoder
	if err := e.value(reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return e.b, nil
}

// Unmarshal decodes postcard data into v.
func Unmarshal(data []byte, v any) error {
	if v == nil {
		return errors.New("postcard: nil target")
	}
	d := Decoder{b: data}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("postcard: target must be non-nil pointer")
	}
	if err := d.value(rv.Elem()); err != nil {
		return err
	}
	if d.off != len(d.b) {
		return ErrTrailingBytes
	}
	return nil
}

// Encoder incrementally encodes postcard values.
type Encoder struct {
	b []byte
}

// Encode appends v to e.
func (e *Encoder) Encode(v any) error {
	return e.value(reflect.ValueOf(v))
}

// Bytes returns a copy of the encoded bytes.
func (e *Encoder) Bytes() []byte { return append([]byte(nil), e.b...) }

// Uint appends v as a postcard unsigned integer. Use [Encoder.Uint8] for a
// Rust u8, which is not varint-encoded.
func (e *Encoder) Uint(v uint64) { e.b = appendVarint(e.b, v) }

// Int appends v as a postcard signed integer. Use [Encoder.Int8] for a Rust i8,
// which is not zigzag-encoded.
func (e *Encoder) Int(v int64) { e.b = appendVarint(e.b, zigzag(v)) }

// Uint8 appends v as a postcard u8: one raw byte, not a varint.
func (e *Encoder) Uint8(v uint8) { e.b = append(e.b, v) }

// Int8 appends v as a postcard i8: one raw byte holding the two's complement,
// not a zigzag varint.
func (e *Encoder) Int8(v int8) { e.b = append(e.b, byte(v)) }

// Bool appends v as a postcard bool.
func (e *Encoder) Bool(v bool) {
	if v {
		e.b = append(e.b, 1)
	} else {
		e.b = append(e.b, 0)
	}
}

// BytesValue appends b as a postcard byte sequence.
func (e *Encoder) BytesValue(b []byte) {
	e.b = appendVarint(e.b, uint64(len(b)))
	e.b = append(e.b, b...)
}

// RawBytes appends b without a length prefix.
func (e *Encoder) RawBytes(b []byte) { e.b = append(e.b, b...) }

// String appends s as a postcard string.
func (e *Encoder) String(s string) { e.BytesValue([]byte(s)) }

func (e *Encoder) value(v reflect.Value) error {
	if !v.IsValid() {
		return errors.New("postcard: invalid value")
	}
	if v.Kind() == reflect.Interface && !v.IsNil() {
		v = v.Elem()
	}
	if v.CanInterface() {
		if m, ok := v.Interface().(Marshaler); ok {
			b, err := m.MarshalPostcard()
			if err != nil {
				return err
			}
			e.b = append(e.b, b...)
			return nil
		}
		if m, ok := v.Interface().(EncoderTo); ok {
			return m.EncodePostcard(e)
		}
		if tm, ok := v.Interface().(encoding.TextMarshaler); ok && v.Kind() == reflect.String {
			b, err := tm.MarshalText()
			if err != nil {
				return err
			}
			return e.bytes(b)
		}
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			e.b = append(e.b, 0)
			return nil
		}
		e.b = append(e.b, 1)
		return e.value(v.Elem())
	case reflect.Bool:
		e.Bool(v.Bool())
	case reflect.Uint8:
		e.Uint8(uint8(v.Uint()))
	case reflect.Int8:
		e.Int8(int8(v.Int()))
	case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		e.Uint(v.Uint())
	case reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64:
		e.Int(v.Int())
	case reflect.String:
		return e.bytes([]byte(v.String()))
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			for i := 0; i < v.Len(); i++ {
				e.b = append(e.b, byte(v.Index(i).Uint()))
			}
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			e.b = appendVarint(e.b, 0)
			return nil
		}
		e.b = appendVarint(e.b, uint64(v.Len()))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			e.b = append(e.b, v.Bytes()...)
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := e.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue
			}
			if err := e.value(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("postcard: unsupported type %s", v.Type())
	}
	return nil
}

func (e *Encoder) bytes(b []byte) error {
	e.b = appendVarint(e.b, uint64(len(b)))
	e.b = append(e.b, b...)
	return nil
}

// Decoder incrementally decodes postcard values.
type Decoder struct {
	b   []byte
	off int
}

// NewDecoder returns a decoder reading b.
func NewDecoder(b []byte) *Decoder { return &Decoder{b: b} }

// Decode decodes the next postcard value into v.
func (d *Decoder) Decode(v any) error {
	if v == nil {
		return errors.New("postcard: nil target")
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("postcard: target must be non-nil pointer")
	}
	return d.value(rv.Elem())
}

// Done reports whether d consumed all input.
func (d *Decoder) Done() bool { return d.off == len(d.b) }

// Uint decodes a postcard unsigned integer. Use [Decoder.Uint8] for a Rust u8,
// which is not varint-encoded.
func (d *Decoder) Uint() (uint64, error) { return d.varint() }

// Uint8 decodes a postcard u8: one raw byte.
func (d *Decoder) Uint8() (uint8, error) { return d.byte() }

// Int8 decodes a postcard i8: one raw byte holding the two's complement.
func (d *Decoder) Int8() (int8, error) {
	b, err := d.byte()
	return int8(b), err
}

// Int decodes a postcard signed integer. Use [Decoder.Int8] for a Rust i8,
// which is not zigzag-encoded.
func (d *Decoder) Int() (int64, error) {
	x, err := d.varint()
	if err != nil {
		return 0, err
	}
	return unzigzag(x), nil
}

// Bool decodes a postcard bool.
func (d *Decoder) Bool() (bool, error) {
	x, err := d.byte()
	if err != nil {
		return false, err
	}
	switch x {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("postcard: invalid bool %d", x)
	}
}

// BytesValue decodes a postcard byte sequence.
func (d *Decoder) BytesValue() ([]byte, error) { return d.bytes() }

// RawBytes decodes n bytes without a length prefix.
func (d *Decoder) RawBytes(n int) ([]byte, error) {
	if n < 0 || d.off+n > len(d.b) {
		return nil, errShort
	}
	b := d.b[d.off : d.off+n]
	d.off += n
	return b, nil
}

// String decodes a postcard string.
func (d *Decoder) String() (string, error) {
	b, err := d.bytes()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", fmt.Errorf("postcard: invalid utf-8 string")
	}
	return string(b), nil
}

func (d *Decoder) value(v reflect.Value) error {
	if !v.CanSet() {
		return fmt.Errorf("postcard: cannot set %s", v.Type())
	}
	if v.CanAddr() {
		if u, ok := v.Addr().Interface().(DecoderFrom); ok {
			return u.DecodePostcard(d)
		}
	}
	switch v.Kind() {
	case reflect.Pointer:
		ok, err := d.option()
		if err != nil {
			return err
		}
		if !ok {
			v.SetZero()
			return nil
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return d.value(v.Elem())
	case reflect.Bool:
		x, err := d.Bool()
		if err != nil {
			return err
		}
		v.SetBool(x)
	case reflect.Uint8:
		x, err := d.Uint8()
		if err != nil {
			return err
		}
		v.SetUint(uint64(x))
	case reflect.Int8:
		x, err := d.Int8()
		if err != nil {
			return err
		}
		v.SetInt(int64(x))
	case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		x, err := d.varint()
		if err != nil {
			return err
		}
		if v.OverflowUint(x) {
			return fmt.Errorf("postcard: %d overflows %s", x, v.Type())
		}
		v.SetUint(x)
	case reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := d.Int()
		if err != nil {
			return err
		}
		if v.OverflowInt(i) {
			return fmt.Errorf("postcard: %d overflows %s", i, v.Type())
		}
		v.SetInt(i)
	case reflect.String:
		s, err := d.String()
		if err != nil {
			return err
		}
		v.SetString(s)
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if d.off+v.Len() > len(d.b) {
				return errShort
			}
			reflect.Copy(v, reflect.ValueOf(d.b[d.off:d.off+v.Len()]))
			d.off += v.Len()
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := d.value(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		n, err := d.varint()
		if err != nil {
			return err
		}
		if n > uint64(math.MaxInt) {
			return fmt.Errorf("postcard: sequence too large")
		}
		if n > uint64(len(d.b)-d.off) {
			return errShort
		}
		s := reflect.MakeSlice(v.Type(), int(n), int(n))
		if v.Type().Elem().Kind() == reflect.Uint8 {
			reflect.Copy(s, reflect.ValueOf(d.b[d.off:d.off+int(n)]))
			d.off += int(n)
			v.Set(s)
			return nil
		}
		for i := 0; i < int(n); i++ {
			if err := d.value(s.Index(i)); err != nil {
				return err
			}
		}
		v.Set(s)
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" {
				continue
			}
			if err := d.value(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("postcard: unsupported type %s", v.Type())
	}
	return nil
}

func (d *Decoder) byte() (byte, error) {
	if d.off >= len(d.b) {
		return 0, errShort
	}
	x := d.b[d.off]
	d.off++
	return x, nil
}

func (d *Decoder) bytes() ([]byte, error) {
	n, err := d.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(d.b)-d.off) {
		return nil, errShort
	}
	b := d.b[d.off : d.off+int(n)]
	d.off += int(n)
	return b, nil
}

func (d *Decoder) option() (bool, error) {
	x, err := d.byte()
	if err != nil {
		return false, err
	}
	switch x {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("postcard: invalid option %d", x)
	}
}

func (d *Decoder) varint() (uint64, error) {
	x, n, err := readVarint(d.b[d.off:])
	if err != nil {
		return 0, err
	}
	d.off += n
	return x, nil
}

func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func readVarint(buf []byte) (uint64, int, error) {
	var v uint64
	for i := 0; i < len(buf); i++ {
		if i >= 10 {
			break
		}
		b := buf[i]
		if i == 9 && b > 1 {
			return 0, 0, fmt.Errorf("postcard: varint overflow")
		}
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, i + 1, nil
		}
	}
	return 0, 0, errShort
}

func zigzag(v int64) uint64 {
	return uint64(v<<1) ^ uint64(v>>63)
}

func unzigzag(v uint64) int64 {
	return int64(v>>1) ^ -int64(v&1)
}
