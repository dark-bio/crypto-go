// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cbor implements a restricted CBOR encoder and decoder.
//
// https://datatracker.ietf.org/doc/html/rfc8949
//
// This is an implementation of the CBOR spec with an extremely reduced type
// system, focusing on security rather than flexibility or completeness. The
// following types are supported:
//   - Positive integers:  uint, uint8, uint16, uint32, uint64
//   - Signed integers:    int, int8, int16, int32, int64
//   - UTF-8 text strings: string
//   - Byte strings:       []byte, [N]byte
//   - Arrays:             slices, arrays
//   - Maps:               map[int64]V
package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
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
	ErrInvalidAdditionalInfo = errors.New("invalid additional info")
	ErrUnexpectedEOF         = errors.New("unexpected end of data")
	ErrNonCanonical          = errors.New("non-canonical encoding")
	ErrInvalidUTF8           = errors.New("invalid UTF-8 in text string")
	ErrTrailingBytes         = errors.New("unexpected trailing bytes")
	ErrUnsupportedType       = errors.New("unsupported type")
	ErrInvalidMapKeyOrder    = errors.New("invalid map key order")
	ErrIntegerOverflow       = errors.New("integer overflow")
)

// encoder is the encoding mode configured for deterministic output.
var encoder cbor.EncMode

// decoder is the decoding mode configured for strict validation.
var decoder cbor.DecMode

func init() {
	var err error

	encoder, err = cbor.EncOptions{
		Sort:          cbor.SortBytewiseLexical,
		IndefLength:   cbor.IndefLengthForbidden,
		NilContainers: cbor.NilContainerAsEmpty,
		TagsMd:        cbor.TagsForbidden,
	}.EncMode()
	if err != nil {
		panic(err)
	}
	decoder, err = cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
		UTF8:        cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// Marshal encodes a value to CBOR and verifies that the output contains only
// permitted types. Ideally we'd flag the error on the fly, but that requires
// hooking into the encoder, which we cannot do.
func Marshal(v any) ([]byte, error) {
	// Encode the value via the upstream package
	data, err := encoder.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Run the encoded data past the local type restricter
	if err := Verify(data); err != nil {
		return nil, fmt.Errorf("cbor: encoded data failed verification: %w", err)
	}
	return data, nil
}

// Unmarshal verifies that the CBOR data contains only permitted types, then
// decodes it. Ideally we'd flag the error on the fly, but that requires hooking
// into the decoder, which we cannot do.
func Unmarshal(data []byte, v any) error {
	// Run the encoded data past teh local type restricter
	if err := Verify(data); err != nil {
		return err
	}
	// Decode the value via the upstream package
	return decoder.Unmarshal(data, v)
}

// Verify does a dry-run walk of the CBOR data to verify that only the permitted
// subset of types has been used.
func Verify(data []byte) error {
	dec := &verifier{data: data, pos: 0}
	if err := dec.verifyObject(); err != nil {
		return err
	}
	if dec.pos != len(dec.data) {
		return ErrTrailingBytes
	}
	return nil
}

// verifier walks CBOR data to check for disallowed types.
type verifier struct {
	data []byte
	pos  int
}

// verifyObject verifies a single CBOR item without full deserialization.
func (v *verifier) verifyObject() error {
	// Decode the header for the next value
	major, value, err := v.decodeHeader()
	if err != nil {
		return err
	}
	switch major {
	case majorUint, majorNint:
		// Integers are valid (canonicalness was already verified in the
		// header decoding). Overflow checking is done at decode time based
		// on the target type (u64 vs i64).
		return nil

	case majorBytes:
		// Opaque bytes are always valid, skip over
		_, err := v.readBytes(value)
		return err

	case majorText:
		// Verify that the text is indeed UTF-8
		bytes, err := v.readBytes(value)
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
			if err := v.verifyObject(); err != nil {
				return err
			}
		}
		return nil

	case majorMap:
		// Verify map has integer keys in deterministic order
		var prevKey *int64
		for range value {
			// Decode and verify the key is an integer
			key, err := v.decodeMapKey()
			if err != nil {
				return err
			}
			// Verify deterministic ordering
			if prevKey != nil && !mapKeyLess(*prevKey, key) {
				return ErrInvalidMapKeyOrder
			}
			prevKey = &key

			// Recursively verify the value
			if err := v.verifyObject(); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("%w: major type %d", ErrUnsupportedType, major)
	}
}

// decodeMapKey decodes and verifies a map key is an integer (major type 0 or 1).
func (v *verifier) decodeMapKey() (int64, error) {
	major, value, err := v.decodeHeader()
	if err != nil {
		return 0, err
	}
	switch major {
	case majorUint:
		if value > uint64(math.MaxInt64) {
			return 0, ErrIntegerOverflow
		}
		return int64(value), nil
	case majorNint:
		if value > uint64(math.MaxInt64) {
			return 0, ErrIntegerOverflow
		}
		return -1 - int64(value), nil
	default:
		return 0, fmt.Errorf("%w: map key must be integer, got major type %d", ErrUnsupportedType, major)
	}
}

// mapKeyLess returns true if a < b using deterministic CBOR map key ordering
// (RFC 8949 Section 4.2.1): bytewise lexicographic order of encoded keys.
func mapKeyLess(a, b int64) bool {
	aEnc := encodeInt(a)
	bEnc := encodeInt(b)
	for i := range aEnc {
		if i >= len(bEnc) {
			return false
		}
		if aEnc[i] != bEnc[i] {
			return aEnc[i] < bEnc[i]
		}
	}
	return len(aEnc) < len(bEnc)
}

// encodeInt encodes an integer to canonical CBOR format.
func encodeInt(v int64) []byte {
	var major uint8
	var u uint64
	if v >= 0 {
		major = majorUint
		u = uint64(v)
	} else {
		major = majorNint
		u = uint64(-1 - v)
	}
	switch {
	case u < 24:
		return []byte{major<<5 | uint8(u)}
	case u <= 0xFF:
		return []byte{major<<5 | infoUint8, uint8(u)}
	case u <= 0xFFFF:
		return []byte{major<<5 | infoUint16, uint8(u >> 8), uint8(u)}
	case u <= 0xFFFFFFFF:
		return []byte{major<<5 | infoUint32, uint8(u >> 24), uint8(u >> 16), uint8(u >> 8), uint8(u)}
	default:
		return []byte{major<<5 | infoUint64, uint8(u >> 56), uint8(u >> 48), uint8(u >> 40), uint8(u >> 32), uint8(u >> 24), uint8(u >> 16), uint8(u >> 8), uint8(u)}
	}
}

// decodeHeader extracts the major type and the integer value.
func (v *verifier) decodeHeader() (uint8, uint64, error) {
	// Ensure there's still data left in the buffer
	if v.pos >= len(v.data) {
		return 0, 0, ErrUnexpectedEOF
	}
	// Extract the type byte and split it apart
	b := v.data[v.pos]
	v.pos++

	major := b >> 5
	info := b & 0x1f

	// Extract the integer embedded in the info
	var value uint64

	switch {
	case info <= 23:
		value = uint64(info)

	case info == infoUint8:
		bytes, err := v.readBytes(1)
		if err != nil {
			return 0, 0, err
		}
		value = uint64(bytes[0])

	case info == infoUint16:
		bytes, err := v.readBytes(2)
		if err != nil {
			return 0, 0, err
		}
		value = uint64(binary.BigEndian.Uint16(bytes))

	case info == infoUint32:
		bytes, err := v.readBytes(4)
		if err != nil {
			return 0, 0, err
		}
		value = uint64(binary.BigEndian.Uint32(bytes))

	case info == infoUint64:
		bytes, err := v.readBytes(8)
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
func (v *verifier) readBytes(n uint64) ([]byte, error) {
	// Ensure there's still enough data left in the buffer
	if n > uint64(maxInt) {
		return nil, ErrUnexpectedEOF
	}
	if int(n) > len(v.data)-v.pos {
		return nil, ErrUnexpectedEOF
	}
	// Retrieve the byte and move the cursor forward
	bytes := v.data[v.pos : v.pos+int(n)]
	v.pos += int(n)
	return bytes, nil
}
