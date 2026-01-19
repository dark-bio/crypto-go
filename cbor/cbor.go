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
//   - Booleans:                bool
//   - Null:                    structs with cbor:"optional" tag, cbor.Null, cbor.Option
//   - 64bit positive integers: uint64
//   - 64bit signed integers:   int64
//   - UTF-8 text strings:      string
//   - Byte strings:            []byte, [N]byte
//   - Arrays:                  structs with cbor:"_,array" tag
//   - Maps:                    structs with cbor:"N,key" tags (integer keys only)
package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"unicode/utf8"
)

// Supported CBOR major types
const (
	majorUint   = 0
	majorNint   = 1
	majorBytes  = 2
	majorText   = 3
	majorArray  = 4
	majorMap    = 5
	majorSimple = 7
)

// Additional info values
const (
	infoUint8  = 24
	infoUint16 = 25
	infoUint32 = 26
	infoUint64 = 27
)

// Simple values (major type 7)
const (
	simpleFalse = 20
	simpleTrue  = 21
	simpleNull  = 22
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
	ErrUnexpectedNil         = errors.New("unexpected nil value (field not marked optional)")
	ErrUnexpectedNull        = errors.New("unexpected null value (field not marked optional)")
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
// Returns an error if the string contains invalid UTF-8.
func (e *Encoder) EncodeText(value string) error {
	if !utf8.ValidString(value) {
		return ErrInvalidUTF8
	}
	e.encodeLength(majorText, uint64(len(value)))
	e.buf = append(e.buf, value...)
	return nil
}

// EncodeArrayHeader encodes an array size.
func (e *Encoder) EncodeArrayHeader(length int) {
	e.encodeLength(majorArray, uint64(length))
}

// EncodeMapHeader encodes a map size.
func (e *Encoder) EncodeMapHeader(length int) {
	e.encodeLength(majorMap, uint64(length))
}

// EncodeBool encodes a CBOR boolean value.
func (e *Encoder) EncodeBool(value bool) {
	if value {
		e.buf = append(e.buf, majorSimple<<5|simpleTrue)
	} else {
		e.buf = append(e.buf, majorSimple<<5|simpleFalse)
	}
}

// EncodeNull encodes a CBOR null value.
func (e *Encoder) EncodeNull() {
	e.buf = append(e.buf, majorSimple<<5|simpleNull)
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

// DecodeBool decodes a CBOR boolean value.
func (d *Decoder) DecodeBool() (bool, error) {
	if d.pos >= len(d.data) {
		return false, ErrUnexpectedEOF
	}
	b := d.data[d.pos]
	switch b {
	case majorSimple<<5 | simpleFalse:
		d.pos++
		return false, nil
	case majorSimple<<5 | simpleTrue:
		d.pos++
		return true, nil
	default:
		return false, fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, b>>5, majorSimple)
	}
}

// DecodeNull decodes a CBOR null value.
func (d *Decoder) DecodeNull() error {
	if d.pos >= len(d.data) {
		return ErrUnexpectedEOF
	}
	b := d.data[d.pos]
	if b != majorSimple<<5|simpleNull {
		return fmt.Errorf("%w: %d, want %d", ErrInvalidMajorType, b>>5, majorSimple)
	}
	d.pos++
	return nil
}

// PeekNull checks if the next value is null without consuming it.
func (d *Decoder) PeekNull() bool {
	return d.pos < len(d.data) && d.data[d.pos] == majorSimple<<5|simpleNull
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

// Raw is a placeholder type to allow only partially parsing CBOR objects when
// some part might depend on another (e.g. version tag, method in an RPC, etc).
type Raw []byte

// Null is a type that encodes/decodes as CBOR null (0xf6).
// Use this for explicit null values like COSE detached payloads.
type Null struct{}

// skip_object advances the decoder past one CBOR item without validation. It
// does do some minimal type checks as walking the CBOR does require walking
// all the inner fields too.
func skipObject(dec *Decoder) error {
	major, value, err := dec.decodeHeader()
	if err != nil {
		return err
	}
	switch major {
	case majorUint, majorNint:
		return nil

	case majorBytes, majorText:
		_, err := dec.readBytes(value)
		return err

	case majorArray:
		for range value {
			if err := skipObject(dec); err != nil {
				return err
			}
		}
		return nil

	case majorMap:
		for range value {
			if err := skipObject(dec); err != nil {
				return err
			}
			if err := skipObject(dec); err != nil {
				return err
			}
		}
		return nil

	case majorSimple:
		// Only bool and null are permitted
		if value == simpleFalse || value == simpleTrue || value == simpleNull {
			return nil
		}
		return fmt.Errorf("%w: major type %d, simple value %d", ErrUnsupportedType, major, value)

	default:
		return fmt.Errorf("%w: major type %d", ErrUnsupportedType, major)
	}
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

	case majorSimple:
		// Only bool and null are permitted
		if value == simpleFalse || value == simpleTrue || value == simpleNull {
			return nil
		}
		return fmt.Errorf("%w: major type %d, simple value %d", ErrUnsupportedType, major, value)

	default:
		return fmt.Errorf("%w: major type %d", ErrUnsupportedType, major)
	}
}
