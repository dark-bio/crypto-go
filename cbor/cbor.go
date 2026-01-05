// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cbor implements a tiny CBOR encoder and decoder.
//
// https://datatracker.ietf.org/doc/html/rfc8949
//
// This is an implementation of the CBOR spec with an extremely reduced type
// system, focusing on security rather than flexibility or completeness. The
// following types are supported:
//   - 64bit positive integers: uint64
//   - 64bit signed integers:   int64
//   - UTF-8 text strings:      string
//   - Byte strings:            []byte, [N]byte
//   - Arrays:                  structs (fields in order)
//   - Maps:                    map[int64]V
package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"unicode/utf8"
)

// Supported CBOR major types
const (
	majorUint  = 0
	majorNint  = 1
	majorBytes = 2
	majorText  = 3
	majorArray = 4
	majorMap   = 5
)

// Additional info values
const (
	infoUint8  = 24
	infoUint16 = 25
	infoUint32 = 26
	infoUint64 = 27
)

// maxInt is the maximum value of int, used for overflow checks.
const maxInt = int(^uint(0) >> 1)

// Error types for CBOR encoding/decoding failures
var (
	ErrInvalidMajorType      = errors.New("invalid major type")
	ErrInvalidAdditionalInfo = errors.New("invalid additional info")
	ErrUnexpectedEOF         = errors.New("unexpected end of data")
	ErrNonCanonical          = errors.New("non-canonical encoding")
	ErrInvalidUTF8           = errors.New("invalid UTF-8 in text string")
	ErrTrailingBytes         = errors.New("unexpected trailing bytes")
	ErrUnexpectedItemCount   = errors.New("unexpected item count")
	ErrUnsupportedType       = errors.New("unsupported type")
	ErrIntegerOverflow       = errors.New("integer overflow")
	ErrDuplicateMapKey       = errors.New("duplicate map key")
	ErrInvalidMapKeyOrder    = errors.New("invalid map key order")
)

// Encoder is the low-level implementation of the CBOR encoder with only the
// handful of desired types supported.
type Encoder struct {
	buf []byte
}

// NewEncoder creates a CBOR encoder with an underlying buffer, pre-allocated
// to 1KB (small enough not to be relevant, large enough to avoid tiny appends).
func NewEncoder() *Encoder {
	return &Encoder{buf: make([]byte, 0, 1024)}
}

// Bytes returns the accumulated CBOR data.
func (e *Encoder) Bytes() []byte {
	return e.buf
}

// EncodeUint encodes a positive integer into its canonical shortest-form.
func (e *Encoder) EncodeUint(value uint64) {
	e.encodeLength(majorUint, value)
}

// EncodeInt encodes a signed integer into its canonical shortest-form.
func (e *Encoder) EncodeInt(value int64) {
	if value >= 0 {
		e.encodeLength(majorUint, uint64(value))
	} else {
		e.encodeLength(majorNint, uint64(-1-value))
	}
}

// EncodeBytes encodes an opaque byte string.
func (e *Encoder) EncodeBytes(value []byte) {
	e.encodeLength(majorBytes, uint64(len(value)))
	e.buf = append(e.buf, value...)
}

// EncodeText encodes a UTF-8 text string.
func (e *Encoder) EncodeText(value string) {
	e.encodeLength(majorText, uint64(len(value)))
	e.buf = append(e.buf, value...)
}

// EncodeArrayHeader encodes an array size.
func (e *Encoder) EncodeArrayHeader(length int) {
	e.encodeLength(majorArray, uint64(length))
}

// EncodeMapHeader encodes a map size.
func (e *Encoder) EncodeMapHeader(length int) {
	e.encodeLength(majorMap, uint64(length))
}

// encodeLength encodes a major type with an unsigned integer, which defines
// the length for most types, or the value itself for integers.
func (e *Encoder) encodeLength(majorType uint8, length uint64) {
	switch {
	case length < 24:
		e.buf = append(e.buf, majorType<<5|uint8(length))
	case length <= 0xFF:
		e.buf = append(e.buf, majorType<<5|infoUint8, uint8(length))
	case length <= 0xFFFF:
		e.buf = append(e.buf, majorType<<5|infoUint16)
		e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(length))
	case length <= 0xFFFFFFFF:
		e.buf = append(e.buf, majorType<<5|infoUint32)
		e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(length))
	default:
		e.buf = append(e.buf, majorType<<5|infoUint64)
		e.buf = binary.BigEndian.AppendUint64(e.buf, length)
	}
}

// Decoder is the low-level implementation of the CBOR decoder with only the
// handful of desired types supported.
type Decoder struct {
	data []byte
	pos  int
}

// NewDecoder creates a decoder around a data blob.
func NewDecoder(data []byte) *Decoder {
	return &Decoder{data: data, pos: 0}
}

// Finish terminates decoding and returns an error if trailing bytes remain.
func (d *Decoder) Finish() error {
	if d.pos != len(d.data) {
		return ErrTrailingBytes
	}
	return nil
}

// DecodeUint decodes a positive integer, enforcing minimal canonicalness.
func (d *Decoder) DecodeUint() (uint64, error) {
	major, value, err := d.decodeHeader()
	if err != nil {
		return 0, err
	}
	if major != majorUint {
		return 0, fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, major, majorUint)
	}
	return value, nil
}

// DecodeInt decodes a signed integer (major type 0 or 1).
func (d *Decoder) DecodeInt() (int64, error) {
	major, value, err := d.decodeHeader()
	if err != nil {
		return 0, err
	}
	switch major {
	case majorUint:
		if value > math.MaxInt64 {
			return 0, fmt.Errorf("%w: positive %d exceeds max %d", ErrIntegerOverflow, value, uint64(math.MaxInt64))
		}
		return int64(value), nil
	case majorNint:
		if value > math.MaxInt64 {
			return 0, fmt.Errorf("%w: negative %d exceeds max %d", ErrIntegerOverflow, value, uint64(math.MaxInt64))
		}
		return -1 - int64(value), nil
	default:
		return 0, fmt.Errorf("%w: %d, want %d or %d", ErrInvalidMajorType, major, majorUint, majorNint)
	}
}

// DecodeBytes decodes a byte string.
func (d *Decoder) DecodeBytes() ([]byte, error) {
	// Extract the field type and attached length
	major, length, err := d.decodeHeader()
	if err != nil {
		return nil, err
	}
	if major != majorBytes {
		return nil, fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, major, majorBytes)
	}
	// Retrieve the blob and return as is
	bytes, err := d.readBytes(length)
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(bytes))
	copy(result, bytes)
	return result, nil
}

// DecodeBytesFixed decodes a byte string into a fixed-size array.
func (d *Decoder) DecodeBytesFixed(n int) ([]byte, error) {
	// Extract the field type and attached length
	major, length, err := d.decodeHeader()
	if err != nil {
		return nil, err
	}
	if major != majorBytes {
		return nil, fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, major, majorBytes)
	}
	// Check that the length matches the expected array size
	if int(length) != n {
		return nil, fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, n)
	}
	// Retrieve the bytes and copy into the fixed-size array
	bytes, err := d.readBytes(length)
	if err != nil {
		return nil, err
	}
	result := make([]byte, n)
	copy(result, bytes)
	return result, nil
}

// DecodeText decodes a UTF-8 text string.
func (d *Decoder) DecodeText() (string, error) {
	// Extract the field type and attached length
	major, length, err := d.decodeHeader()
	if err != nil {
		return "", err
	}
	if major != majorText {
		return "", fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, major, majorText)
	}
	// Retrieve the blob and reinterpret as UTF-8
	bytes, err := d.readBytes(length)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(bytes) {
		return "", ErrInvalidUTF8
	}
	return string(bytes), nil
}

// DecodeArrayHeader decodes an array header, returning its length.
func (d *Decoder) DecodeArrayHeader() (uint64, error) {
	// Extract the field type and attached length
	major, length, err := d.decodeHeader()
	if err != nil {
		return 0, err
	}
	if major != majorArray {
		return 0, fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, major, majorArray)
	}
	return length, nil
}

// DecodeMapHeader decodes a map header, returning the number of key-value pairs.
func (d *Decoder) DecodeMapHeader() (uint64, error) {
	// Extract the field type and attached length
	major, length, err := d.decodeHeader()
	if err != nil {
		return 0, err
	}
	if major != majorMap {
		return 0, fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, major, majorMap)
	}
	return length, nil
}

// decodeHeader extracts the major type and the integer value embedded as additional info.
func (d *Decoder) decodeHeader() (uint8, uint64, error) {
	// Ensure there's still data left in the buffer
	if d.pos >= len(d.data) {
		return 0, 0, ErrUnexpectedEOF
	}
	// Extract the type byte and split it apart
	b := d.data[d.pos]
	d.pos++

	major := b >> 5
	info := b & 0x1f

	// Extract the integer embedded in the info
	var value uint64

	switch {
	case info <= 23:
		value = uint64(info)
	case info == infoUint8:
		bytes, err := d.readBytes(1)
		if err != nil {
			return 0, 0, err
		}
		value = uint64(bytes[0])
	case info == infoUint16:
		bytes, err := d.readBytes(2)
		if err != nil {
			return 0, 0, err
		}
		value = uint64(binary.BigEndian.Uint16(bytes))
	case info == infoUint32:
		bytes, err := d.readBytes(4)
		if err != nil {
			return 0, 0, err
		}
		value = uint64(binary.BigEndian.Uint32(bytes))
	case info == infoUint64:
		bytes, err := d.readBytes(8)
		if err != nil {
			return 0, 0, err
		}
		value = binary.BigEndian.Uint64(bytes)
	default:
		return 0, 0, fmt.Errorf("%w: %d", ErrInvalidAdditionalInfo, info)
	}

	// Ensure it was canonical in the first place
	var canonical bool
	switch {
	case info <= 23:
		canonical = value < 24
	case info == infoUint8:
		canonical = value >= 24 && value <= 0xFF
	case info == infoUint16:
		canonical = value > 0xFF && value <= 0xFFFF
	case info == infoUint32:
		canonical = value > 0xFFFF && value <= 0xFFFFFFFF
	case info == infoUint64:
		canonical = value > 0xFFFFFFFF
	}
	if !canonical {
		return 0, 0, ErrNonCanonical
	}
	return major, value, nil
}

// readBytes retrieves the next n bytes from the buffer.
func (d *Decoder) readBytes(n uint64) ([]byte, error) {
	// Ensure n fits in an int to avoid overflow during position arithmetic
	if n > uint64(maxInt) {
		return nil, ErrUnexpectedEOF
	}
	// Ensure there's still enough data left in the buffer
	if int(n) > len(d.data)-d.pos {
		return nil, ErrUnexpectedEOF
	}
	// Retrieve the byte and move the cursor forward
	bytes := d.data[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return bytes, nil
}

// EncodeUint64 encodes a uint64 value to CBOR.
func EncodeUint64(value uint64) []byte {
	enc := NewEncoder()
	enc.EncodeUint(value)
	return enc.Bytes()
}

// DecodeUint64 decodes a uint64 value from CBOR.
func DecodeUint64(data []byte) (uint64, error) {
	dec := NewDecoder(data)
	value, err := dec.DecodeUint()
	if err != nil {
		return 0, err
	}
	if err := dec.Finish(); err != nil {
		return 0, err
	}
	return value, nil
}

// EncodeInt64 encodes an int64 value to CBOR.
func EncodeInt64(value int64) []byte {
	enc := NewEncoder()
	enc.EncodeInt(value)
	return enc.Bytes()
}

// DecodeInt64 decodes an int64 value from CBOR.
func DecodeInt64(data []byte) (int64, error) {
	dec := NewDecoder(data)
	value, err := dec.DecodeInt()
	if err != nil {
		return 0, err
	}
	if err := dec.Finish(); err != nil {
		return 0, err
	}
	return value, nil
}

// EncodeBytes encodes a byte slice to CBOR.
func EncodeBytes(value []byte) []byte {
	enc := NewEncoder()
	enc.EncodeBytes(value)
	return enc.Bytes()
}

// DecodeBytes decodes a byte slice from CBOR.
func DecodeBytes(data []byte) ([]byte, error) {
	dec := NewDecoder(data)
	value, err := dec.DecodeBytes()
	if err != nil {
		return nil, err
	}
	if err := dec.Finish(); err != nil {
		return nil, err
	}
	return value, nil
}

// EncodeString encodes a string to CBOR.
func EncodeString(value string) []byte {
	enc := NewEncoder()
	enc.EncodeText(value)
	return enc.Bytes()
}

// DecodeString decodes a string from CBOR.
func DecodeString(data []byte) (string, error) {
	dec := NewDecoder(data)
	value, err := dec.DecodeText()
	if err != nil {
		return "", err
	}
	if err := dec.Finish(); err != nil {
		return "", err
	}
	return value, nil
}

// mapKeyCmp compares two int64 keys according to CBOR deterministic encoding
// order (RFC 8949 Section 4.2.1): bytewise lexicographic order of encoded keys.
//
// For integers this means: positive integers (0, 1, 2, ...) come before negative
// integers (-1, -2, -3, ...), and within each category they're ordered by their
// encoded length first, then by value.
func mapKeyCmp(a, b int64) int {
	encodeKey := func(k int64) []byte {
		enc := NewEncoder()
		enc.EncodeInt(k)
		return enc.Bytes()
	}
	return slices.Compare(encodeKey(a), encodeKey(b))
}

// EncodeMap encodes a map[int64][]byte to CBOR with deterministic key ordering.
func EncodeMap(m map[int64][]byte) []byte {
	enc := NewEncoder()

	keys := slices.SortedFunc(maps.Keys(m), mapKeyCmp)

	enc.EncodeMapHeader(len(keys))
	for _, key := range keys {
		enc.EncodeInt(key)
		enc.buf = append(enc.buf, m[key]...)
	}
	return enc.Bytes()
}

// DecodeMap decodes a map[int64][]byte from CBOR, validating key ordering.
// The values are returned as raw CBOR data for the caller to decode.
func DecodeMap[V any](data []byte, decodeValue func(*Decoder) (V, error)) (map[int64]V, error) {
	dec := NewDecoder(data)
	m, err := DecodeMapNoTrail(dec, decodeValue)
	if err != nil {
		return nil, err
	}
	if err := dec.Finish(); err != nil {
		return nil, err
	}
	return m, nil
}

// DecodeMapNoTrail decodes a map without checking for trailing bytes.
func DecodeMapNoTrail[V any](dec *Decoder, decodeValue func(*Decoder) (V, error)) (map[int64]V, error) {
	length, err := dec.DecodeMapHeader()
	if err != nil {
		return nil, err
	}
	// Cap pre-allocation to prevent DoS via malicious length values
	capacity := min(int(length), 1024)
	m := make(map[int64]V, capacity)

	var prevKey *int64
	for range length {
		key, err := dec.DecodeInt()
		if err != nil {
			return nil, err
		}
		// Verify deterministic ordering and no duplicates
		if prevKey != nil {
			switch cmp := mapKeyCmp(*prevKey, key); {
			case cmp == 0:
				return nil, fmt.Errorf("%w: %d", ErrDuplicateMapKey, key)
			case cmp > 0:
				return nil, fmt.Errorf("%w: %d must come before %d", ErrInvalidMapKeyOrder, key, *prevKey)
			}
		}
		value, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		m[key] = value
		prevKey = &key
	}
	return m, nil
}

// Verify does a dry-run decoding to verify that only the tiny, strict subset
// of types permitted by this package were used.
func Verify(data []byte) error {
	dec := NewDecoder(data)
	if err := verifyObject(dec); err != nil {
		return err
	}
	return dec.Finish()
}

// verifyObject verifies a single CBOR item without full deserialization.
func verifyObject(dec *Decoder) error {
	major, value, err := dec.decodeHeader()
	if err != nil {
		return err
	}
	switch major {
	case majorUint, majorNint:
		// Integers are valid (canonicalness was already verified in header decoding)
		return nil
	case majorBytes:
		// Opaque bytes are always valid, skip over
		_, err := dec.readBytes(value)
		return err
	case majorText:
		// Verify that the text is indeed UTF-8
		bytes, err := dec.readBytes(value)
		if err != nil {
			return err
		}
		if !utf8.Valid(bytes) {
			return ErrInvalidUTF8
		}
		return nil
	case majorArray:
		// Recursively verify each array element
		for range value {
			if err := verifyObject(dec); err != nil {
				return err
			}
		}
		return nil
	case majorMap:
		// Verify map has integer keys in deterministic order
		var prevKey *int64
		for range value {
			key, err := dec.DecodeInt()
			if err != nil {
				return err
			}
			if prevKey != nil && mapKeyCmp(*prevKey, key) >= 0 {
				return fmt.Errorf("%w: %d must come before %d", ErrInvalidMapKeyOrder, key, *prevKey)
			}
			prevKey = &key
			if err := verifyObject(dec); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: major type %d", ErrUnsupportedType, major)
	}
}

// EncodeStruct encodes a struct as a CBOR array, with fields encoded in order.
// Supported field types: uint64, int64, string, []byte, nested structs, map[int64]V.
func EncodeStruct(v any) []byte {
	enc := NewEncoder()
	encodeValue(enc, reflect.ValueOf(v))
	return enc.Bytes()
}

// encodeValue recursively encodes a reflect.Value to CBOR.
func encodeValue(enc *Encoder, v reflect.Value) {
	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		enc.EncodeUint(v.Uint())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		enc.EncodeInt(v.Int())
	case reflect.String:
		enc.EncodeText(v.String())
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			enc.EncodeBytes(v.Bytes())
		} else {
			enc.EncodeArrayHeader(v.Len())
			for i := range v.Len() {
				encodeValue(enc, v.Index(i))
			}
		}
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			// Convert array to slice for encoding
			slice := make([]byte, v.Len())
			for i := range v.Len() {
				slice[i] = byte(v.Index(i).Uint())
			}
			enc.EncodeBytes(slice)
		} else {
			enc.EncodeArrayHeader(v.Len())
			for i := range v.Len() {
				encodeValue(enc, v.Index(i))
			}
		}
	case reflect.Struct:
		t := v.Type()
		enc.EncodeArrayHeader(t.NumField())
		for i := range t.NumField() {
			encodeValue(enc, v.Field(i))
		}
	case reflect.Map:
		// Must be map[int64]V
		keys := v.MapKeys()
		intKeys := make([]int64, len(keys))
		for i, k := range keys {
			intKeys[i] = k.Int()
		}
		slices.SortFunc(intKeys, mapKeyCmp)

		enc.EncodeMapHeader(len(intKeys))
		for _, key := range intKeys {
			enc.EncodeInt(key)
			encodeValue(enc, v.MapIndex(reflect.ValueOf(key)))
		}
	case reflect.Ptr:
		if v.IsNil() {
			panic("cbor: nil pointer not supported")
		}
		encodeValue(enc, v.Elem())
	default:
		panic(fmt.Sprintf("cbor: unsupported type %s", v.Type()))
	}
}

// DecodeStruct decodes a CBOR array into a struct, with fields decoded in order.
// v must be a pointer to a struct.
func DecodeStruct(data []byte, v any) error {
	dec := NewDecoder(data)
	if err := decodeValue(dec, reflect.ValueOf(v)); err != nil {
		return err
	}
	return dec.Finish()
}

// DecodeStructNoTrail decodes a struct without checking for trailing bytes.
func DecodeStructNoTrail(dec *Decoder, v any) error {
	return decodeValue(dec, reflect.ValueOf(v))
}

// decodeValue recursively decodes CBOR into a reflect.Value.
func decodeValue(dec *Decoder, v reflect.Value) error {
	// Must be a pointer to decode into
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := dec.DecodeUint()
		if err != nil {
			return err
		}
		v.SetUint(val)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := dec.DecodeInt()
		if err != nil {
			return err
		}
		v.SetInt(val)
	case reflect.String:
		val, err := dec.DecodeText()
		if err != nil {
			return err
		}
		v.SetString(val)
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			val, err := dec.DecodeBytes()
			if err != nil {
				return err
			}
			v.SetBytes(val)
		} else {
			length, err := dec.DecodeArrayHeader()
			if err != nil {
				return err
			}
			slice := reflect.MakeSlice(v.Type(), int(length), int(length))
			for i := range length {
				if err := decodeValue(dec, slice.Index(int(i))); err != nil {
					return err
				}
			}
			v.Set(slice)
		}
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			val, err := dec.DecodeBytesFixed(v.Len())
			if err != nil {
				return err
			}
			for i := range v.Len() {
				v.Index(i).SetUint(uint64(val[i]))
			}
		} else {
			length, err := dec.DecodeArrayHeader()
			if err != nil {
				return err
			}
			if int(length) != v.Len() {
				return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, v.Len())
			}
			for i := range length {
				if err := decodeValue(dec, v.Index(int(i))); err != nil {
					return err
				}
			}
		}
	case reflect.Struct:
		length, err := dec.DecodeArrayHeader()
		if err != nil {
			return err
		}
		if int(length) != v.NumField() {
			return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, v.NumField())
		}
		for i := range v.NumField() {
			if err := decodeValue(dec, v.Field(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		length, err := dec.DecodeMapHeader()
		if err != nil {
			return err
		}
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		var prevKey *int64
		for range length {
			key, err := dec.DecodeInt()
			if err != nil {
				return err
			}
			// Verify deterministic ordering and no duplicates
			if prevKey != nil {
				switch cmp := mapKeyCmp(*prevKey, key); {
				case cmp == 0:
					return fmt.Errorf("%w: %d", ErrDuplicateMapKey, key)
				case cmp > 0:
					return fmt.Errorf("%w: %d must come before %d", ErrInvalidMapKeyOrder, key, *prevKey)
				}
			}
			prevKey = &key

			val := reflect.New(v.Type().Elem()).Elem()
			if err := decodeValue(dec, val); err != nil {
				return err
			}
			v.SetMapIndex(reflect.ValueOf(key), val)
		}
	default:
		return fmt.Errorf("cbor: unsupported type %s", v.Type())
	}
	return nil
}
