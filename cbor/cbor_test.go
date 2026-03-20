// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbor

import (
	"bytes"
	"errors"
	"math"
	"strings"
	"testing"
)

// Tests that positive integers encode correctly across the various ranges
// that CBOR special cases.
func TestUintEncoding(t *testing.T) {
	cases := []struct {
		value    uint64
		expected []byte
	}{
		{0, []byte{0x00}},
		{23, []byte{0x17}},
		{24, []byte{0x18, 0x18}},
		{math.MaxUint8, []byte{0x18, 0xff}},
		{math.MaxUint8 + 1, []byte{0x19, 0x01, 0x00}},
		{math.MaxUint16, []byte{0x19, 0xff, 0xff}},
		{math.MaxUint16 + 1, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
		{math.MaxUint32, []byte{0x1a, 0xff, 0xff, 0xff, 0xff}},
		{math.MaxUint32 + 1, []byte{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
		{math.MaxUint64, []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range cases {
		data, err := Marshal(tc.value)
		if err != nil {
			t.Errorf("Marshal(%d) error: %v", tc.value, err)
			continue
		}
		if !bytes.Equal(data, tc.expected) {
			t.Errorf("encoding failed for value %d: got %x, want %x", tc.value, data, tc.expected)
		}
	}
}

// Tests that positive integers decode correctly across the various ranges
// that CBOR special cases.
func TestUintDecoding(t *testing.T) {
	cases := []struct {
		data     []byte
		expected uint64
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x17}, 23},
		{[]byte{0x18, 0x18}, 24},
		{[]byte{0x18, 0xff}, math.MaxUint8},
		{[]byte{0x19, 0x01, 0x00}, math.MaxUint8 + 1},
		{[]byte{0x19, 0xff, 0xff}, math.MaxUint16},
		{[]byte{0x1a, 0x00, 0x01, 0x00, 0x00}, math.MaxUint16 + 1},
		{[]byte{0x1a, 0xff, 0xff, 0xff, 0xff}, math.MaxUint32},
		{[]byte{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, math.MaxUint32 + 1},
		{[]byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxUint64},
	}
	for _, tc := range cases {
		var got uint64
		if err := Unmarshal(tc.data, &got); err != nil {
			t.Errorf("Unmarshal(%x) error: %v", tc.data, err)
			continue
		}
		if got != tc.expected {
			t.Errorf("decoding failed for data %x: got %d, want %d", tc.data, got, tc.expected)
		}
	}
}

// Tests that positive integers are rejected for invalid size / encoding
// combinations.
func TestUintRejection(t *testing.T) {
	// Values 0-23 must use direct embedding
	for value := uint64(0); value < 24; value++ {
		// Should fail with infoUint8
		data := []byte{MajorUint<<5 | infoUint8, byte(value)}
		var got uint64
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint8 should fail", value)
		}

		// Should fail with infoUint16
		data = []byte{MajorUint<<5 | infoUint16, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint16 should fail", value)
		}

		// Should fail with infoUint32
		data = []byte{MajorUint<<5 | infoUint32, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint32 should fail", value)
		}

		// Should fail with infoUint64
		data = []byte{MajorUint<<5 | infoUint64, 0, 0, 0, 0, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint64 should fail", value)
		}
	}

	// Values 24-255 must use infoUint8
	for value := uint64(24); value <= math.MaxUint8; value++ {
		var got uint64

		// Should fail with infoUint16
		data := []byte{MajorUint<<5 | infoUint16, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint16 should fail", value)
		}

		// Should fail with infoUint32
		data = []byte{MajorUint<<5 | infoUint32, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint32 should fail", value)
		}

		// Should fail with infoUint64
		data = []byte{MajorUint<<5 | infoUint64, 0, 0, 0, 0, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint64 should fail", value)
		}
	}

	// Values 256-65535 must use infoUint16
	for _, value := range []uint64{math.MaxUint8 + 1, math.MaxUint16} {
		var got uint64

		// Should fail with infoUint32
		data := []byte{MajorUint<<5 | infoUint32, 0, 0, byte(value >> 8), byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint32 should fail", value)
		}

		// Should fail with infoUint64
		data = []byte{MajorUint<<5 | infoUint64, 0, 0, 0, 0, 0, 0, byte(value >> 8), byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint64 should fail", value)
		}
	}

	// Values 65536-4294967295 must use infoUint32
	for _, value := range []uint64{math.MaxUint16 + 1, math.MaxUint32} {
		var got uint64

		// Should fail with infoUint64
		data := []byte{MajorUint<<5 | infoUint64, 0, 0, 0, 0, byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint64 should fail", value)
		}
	}
}

// Tests that signed integers encode correctly across the various ranges.
func TestIntEncoding(t *testing.T) {
	cases := []struct {
		value    int64
		expected []byte
	}{
		// Positive values use major type 0
		{0, []byte{0x00}},
		{23, []byte{0x17}},
		{24, []byte{0x18, 0x18}},
		{math.MaxInt64, []byte{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		// Negative values use major type 1 with (-1 - n) encoding
		{-1, []byte{0x20}},               // -1 -> wire value 0
		{-24, []byte{0x37}},              // -24 -> wire value 23
		{-25, []byte{0x38, 0x18}},        // -25 -> wire value 24
		{-256, []byte{0x38, 0xff}},       // -256 -> wire value 255
		{-257, []byte{0x39, 0x01, 0x00}}, // -257 -> wire value 256
		{math.MinInt64, []byte{0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range cases {
		data, err := Marshal(tc.value)
		if err != nil {
			t.Errorf("Marshal(%d) error: %v", tc.value, err)
			continue
		}
		if !bytes.Equal(data, tc.expected) {
			t.Errorf("encoding failed for value %d: got %x, want %x", tc.value, data, tc.expected)
		}
	}
}

// Tests that signed integers decode correctly across the various ranges.
func TestIntDecoding(t *testing.T) {
	cases := []struct {
		data     []byte
		expected int64
	}{
		// Positive values (major type 0)
		{[]byte{0x00}, 0},
		{[]byte{0x17}, 23},
		{[]byte{0x18, 0x18}, 24},
		{[]byte{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxInt64},
		// Negative values (major type 1)
		{[]byte{0x20}, -1},
		{[]byte{0x37}, -24},
		{[]byte{0x38, 0x18}, -25},
		{[]byte{0x38, 0xff}, -256},
		{[]byte{0x39, 0x01, 0x00}, -257},
		{[]byte{0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MinInt64},
	}
	for _, tc := range cases {
		var got int64
		if err := Unmarshal(tc.data, &got); err != nil {
			t.Errorf("Unmarshal(%x) error: %v", tc.data, err)
			continue
		}
		if got != tc.expected {
			t.Errorf("decoding failed for data %x: got %d, want %d", tc.data, got, tc.expected)
		}
	}
}

// Tests that signed integers are rejected for overflow conditions.
func TestIntRejection(t *testing.T) {
	// Positive value > i64::MAX (major type 0 with value i64::MAX + 1)
	data := []byte{MajorUint<<5 | infoUint64, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	var got int64
	err := Unmarshal(data, &got)
	if err == nil {
		t.Error("positive overflow should fail")
	} else if !errors.Is(err, ErrIntegerOverflow) {
		t.Errorf("expected ErrIntegerOverflow, got %v", err)
	}

	// Negative value < i64::MIN (major type 1 with wire value > i64::MAX)
	data = []byte{MajorNint<<5 | infoUint64, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	err = Unmarshal(data, &got)
	if err == nil {
		t.Error("negative overflow should fail")
	} else if !errors.Is(err, ErrIntegerOverflow) {
		t.Errorf("expected ErrIntegerOverflow, got %v", err)
	}

	// Non-canonical negative integer encoding
	data = []byte{MajorNint<<5 | infoUint8, 0x10} // -17 with infoUint8
	err = Unmarshal(data, &got)
	if err == nil {
		t.Error("non-canonical encoding should fail")
	} else if !errors.Is(err, ErrNonCanonical) {
		t.Errorf("expected ErrNonCanonical, got %v", err)
	}
}

// Tests that byte strings encode correctly on a bunch of samples.
func TestBytesEncoding(t *testing.T) {
	// Empty bytes
	data, err := Marshal([]byte{})
	if err != nil {
		t.Fatalf("Marshal empty bytes error: %v", err)
	}
	if !bytes.Equal(data, []byte{0x40}) {
		t.Errorf("empty bytes: got %x, want 40", data)
	}

	// 1 byte
	data, err = Marshal([]byte{0xaa})
	if err != nil {
		t.Fatalf("Marshal 1 byte error: %v", err)
	}
	if !bytes.Equal(data, []byte{0x41, 0xaa}) {
		t.Errorf("1 byte: got %x, want 41aa", data)
	}

	// Longer bytes
	data, err = Marshal([]byte{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("Marshal longer bytes error: %v", err)
	}
	if !bytes.Equal(data, []byte{0x44, 0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("longer bytes: got %x, want 44deadbeef", data)
	}

	// Test [N]byte fixed-size array
	data, err = Marshal([3]byte{7, 8, 9})
	if err != nil {
		t.Fatalf("Marshal [3]byte error: %v", err)
	}
	if !bytes.Equal(data, []byte{0x43, 7, 8, 9}) {
		t.Errorf("[3]byte: got %x, want 43070809", data)
	}
}

// Tests that byte strings decode correctly on a bunch of samples.
func TestBytesDecoding(t *testing.T) {
	// Empty bytes
	var got []byte
	if err := Unmarshal([]byte{0x40}, &got); err != nil {
		t.Fatalf("Unmarshal empty bytes error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty bytes: got %x, want empty", got)
	}

	// 1 byte
	if err := Unmarshal([]byte{0x41, 0xaa}, &got); err != nil {
		t.Fatalf("Unmarshal 1 byte error: %v", err)
	}
	if !bytes.Equal(got, []byte{0xaa}) {
		t.Errorf("1 byte: got %x, want aa", got)
	}

	// Longer bytes
	if err := Unmarshal([]byte{0x44, 0xde, 0xad, 0xbe, 0xef}, &got); err != nil {
		t.Fatalf("Unmarshal longer bytes error: %v", err)
	}
	if !bytes.Equal(got, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("longer bytes: got %x, want deadbeef", got)
	}

	// Test fixed-size array decoding
	var fixed [3]byte
	if err := Unmarshal([]byte{0x43, 1, 2, 3}, &fixed); err != nil {
		t.Fatalf("Unmarshal [3]byte error: %v", err)
	}
	if fixed != [3]byte{1, 2, 3} {
		t.Errorf("[3]byte: got %x, want 010203", fixed)
	}

	// Test empty fixed-size array
	var empty [0]byte
	if err := Unmarshal([]byte{0x40}, &empty); err != nil {
		t.Fatalf("Unmarshal [0]byte error: %v", err)
	}
}

// Tests that bytes decoding fails when fixed size lengths don't match.
func TestBytesRejection(t *testing.T) {
	// Try to decode 3 bytes into a 4-byte array
	var arr4 [4]byte
	err := Unmarshal([]byte{0x43, 1, 2, 3}, &arr4)
	if err == nil {
		t.Error("decoding 3 bytes into [4]byte should fail")
	} else if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("expected ErrUnexpectedItemCount, got %v", err)
	}

	// Try to decode 4 bytes into a 2-byte array
	var arr2 [2]byte
	err = Unmarshal([]byte{0x44, 1, 2, 3, 4}, &arr2)
	if err == nil {
		t.Error("decoding 4 bytes into [2]byte should fail")
	} else if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("expected ErrUnexpectedItemCount, got %v", err)
	}
}

// Tests that UTF-8 strings encode correctly on a bunch of samples.
func TestStringEncoding(t *testing.T) {
	// Empty string
	data, err := Marshal("")
	if err != nil {
		t.Fatalf("Marshal empty string error: %v", err)
	}
	if !bytes.Equal(data, []byte{0x60}) {
		t.Errorf("empty string: got %x, want 60", data)
	}

	// 1 character
	data, err = Marshal("a")
	if err != nil {
		t.Fatalf("Marshal 1 char error: %v", err)
	}
	if !bytes.Equal(data, []byte{0x61, 0x61}) {
		t.Errorf("1 char: got %x, want 6161", data)
	}

	// Longer string
	testStr := "Peter says hi!"
	data, err = Marshal(testStr)
	if err != nil {
		t.Fatalf("Marshal longer string error: %v", err)
	}
	expected := append([]byte{0x60 | byte(len(testStr))}, []byte(testStr)...)
	if !bytes.Equal(data, expected) {
		t.Errorf("longer string: got %x, want %x", data, expected)
	}
}

// Tests that UTF-8 strings decode correctly on a bunch of samples.
func TestStringDecoding(t *testing.T) {
	// Empty string
	var got string
	if err := Unmarshal([]byte{0x60}, &got); err != nil {
		t.Fatalf("Unmarshal empty string error: %v", err)
	}
	if got != "" {
		t.Errorf("empty string: got %q, want empty", got)
	}

	// 1 character
	if err := Unmarshal([]byte{0x61, 0x61}, &got); err != nil {
		t.Fatalf("Unmarshal 1 char error: %v", err)
	}
	if got != "a" {
		t.Errorf("1 char: got %q, want 'a'", got)
	}

	// Longer string
	testStr := "Peter says hi!"
	encoded := append([]byte{0x60 | byte(len(testStr))}, []byte(testStr)...)
	if err := Unmarshal(encoded, &got); err != nil {
		t.Fatalf("Unmarshal longer string error: %v", err)
	}
	if got != testStr {
		t.Errorf("longer string: got %q, want %q", got, testStr)
	}
}

// Tests that UTF-8 strings are rejected if containing invalid data.
func TestStringRejection(t *testing.T) {
	// 0xff is not valid UTF-8
	var got string
	err := Unmarshal([]byte{0x61, 0xff}, &got)
	if err == nil {
		t.Error("invalid UTF-8 should fail")
	} else if !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("expected ErrInvalidUTF8, got %v", err)
	}

	// Incomplete multi-byte sequence
	err = Unmarshal([]byte{0x62, 0xc2, 0x00}, &got)
	if err == nil {
		t.Error("incomplete UTF-8 should fail")
	} else if !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("expected ErrInvalidUTF8, got %v", err)
	}
}

// Tests that array structs encode correctly in field declaration order.
func TestArrayEncoding(t *testing.T) {
	type TestArray struct {
		_      struct{} `cbor:"_,array"`
		First  uint64
		Second string
		Third  []byte
	}
	arr := TestArray{First: 42, Second: "hello", Third: []byte{1, 2, 3}}
	encoded, err := Marshal(arr)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Should be: [42, "hello", h'010203']
	expected := []byte{0x83} // array with 3 elements
	uint42, _ := Marshal(uint64(42))
	hello, _ := Marshal("hello")
	bytes123, _ := Marshal([]byte{1, 2, 3})
	expected = append(expected, uint42...)
	expected = append(expected, hello...)
	expected = append(expected, bytes123...)

	if !bytes.Equal(encoded, expected) {
		t.Errorf("encoding mismatch: got %x, want %x", encoded, expected)
	}
}

// Tests that array structs decode correctly.
func TestArrayDecoding(t *testing.T) {
	type TestArray struct {
		_      struct{} `cbor:"_,array"`
		First  uint64
		Second string
		Third  []byte
	}

	data := []byte{0x83} // array with 3 elements
	uint100, _ := Marshal(uint64(100))
	world, _ := Marshal("world")
	bytes456, _ := Marshal([]byte{4, 5, 6})
	data = append(data, uint100...)
	data = append(data, world...)
	data = append(data, bytes456...)

	var decoded TestArray
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.First != 100 {
		t.Errorf("First: got %d, want 100", decoded.First)
	}
	if decoded.Second != "world" {
		t.Errorf("Second: got %q, want 'world'", decoded.Second)
	}
	if !bytes.Equal(decoded.Third, []byte{4, 5, 6}) {
		t.Errorf("Third: got %x, want 040506", decoded.Third)
	}
}

// Tests that array structs are rejected if the size does not match.
func TestArrayRejection(t *testing.T) {
	type TestArray struct {
		_      struct{} `cbor:"_,array"`
		First  uint64
		Second string
		Third  []byte
	}

	// Too few elements (2 instead of 3)
	data := []byte{0x82} // array with 2 elements
	uint42, _ := Marshal(uint64(42))
	test, _ := Marshal("test")
	data = append(data, uint42...)
	data = append(data, test...)

	var decoded TestArray
	err := Unmarshal(data, &decoded)
	if err == nil {
		t.Error("too few elements should fail")
	} else if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("expected ErrUnexpectedItemCount, got %v", err)
	}

	// Too many elements (4 instead of 3)
	data = []byte{0x84} // array with 4 elements
	bytes1, _ := Marshal([]byte{1})
	data = append(data, uint42...)
	data = append(data, test...)
	data = append(data, bytes1...)
	data = append(data, uint42...)

	err = Unmarshal(data, &decoded)
	if err == nil {
		t.Error("too many elements should fail")
	} else if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("expected ErrUnexpectedItemCount, got %v", err)
	}
}

// Tests that array structs with optional and Option fields encode/decode correctly.
func TestArrayOptionalEncoding(t *testing.T) {
	type TestArrayOptional struct {
		_           struct{} `cbor:"_,array"`
		Required    uint64
		OptBytes    []byte `cbor:"_,optional"`
		Nullable    Option[uint64]
		OptNullable Option[uint64] `cbor:"_,optional"`
	}

	// All fields present with values
	arr := TestArrayOptional{
		Required:    42,
		OptBytes:    []byte{0xab},
		Nullable:    MakeSome(uint64(10)),
		OptNullable: MakeSome(uint64(20)),
	}
	data, err := Marshal(arr)
	if err != nil {
		t.Fatalf("Marshal all present: %v", err)
	}
	if data[0] != 0x84 { // array with 4 elements
		t.Errorf("all present: got header %x, want 0x84", data[0])
	}
	var decoded TestArrayOptional
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal all present: %v", err)
	}
	if decoded.Required != 42 || !bytes.Equal(decoded.OptBytes, []byte{0xab}) ||
		!decoded.Nullable.Some || decoded.Nullable.Value != 10 ||
		!decoded.OptNullable.Some || decoded.OptNullable.Value != 20 {
		t.Errorf("all present roundtrip failed: %+v", decoded)
	}

	// Optional fields as nil/None (should encode as null, not be omitted)
	arr = TestArrayOptional{
		Required: 7,
		Nullable: MakeSome(uint64(99)),
	}
	data, err = Marshal(arr)
	if err != nil {
		t.Fatalf("Marshal optionals nil: %v", err)
	}
	if data[0] != 0x84 { // still array with 4 elements
		t.Errorf("optionals nil: got header %x, want 0x84", data[0])
	}
	decoded = TestArrayOptional{}
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal optionals nil: %v", err)
	}
	if decoded.Required != 7 || decoded.OptBytes != nil ||
		!decoded.Nullable.Some || decoded.Nullable.Value != 99 ||
		decoded.OptNullable.Some {
		t.Errorf("optionals nil roundtrip failed: %+v", decoded)
	}

	// All Option fields as None
	arr = TestArrayOptional{Required: 1}
	data, err = Marshal(arr)
	if err != nil {
		t.Fatalf("Marshal all none: %v", err)
	}
	if data[0] != 0x84 { // still array with 4 elements
		t.Errorf("all none: got header %x, want 0x84", data[0])
	}
	decoded = TestArrayOptional{}
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal all none: %v", err)
	}
	if decoded.Required != 1 || decoded.OptBytes != nil ||
		decoded.Nullable.Some || decoded.OptNullable.Some {
		t.Errorf("all none roundtrip failed: %+v", decoded)
	}

	// Non-optional []byte as nil should fail
	type TestArrayNonOptBytes struct {
		_    struct{} `cbor:"_,array"`
		Data []byte
	}
	_, err = Marshal(TestArrayNonOptBytes{})
	if !errors.Is(err, ErrUnexpectedNil) {
		t.Errorf("non-optional nil []byte: got %v, want ErrUnexpectedNil", err)
	}
}

// Tests that maps encode correctly with deterministic key ordering.
func TestMapEncoding(t *testing.T) {
	// Map with positive and negative keys (should be sorted by bytewise order)
	type TestMap struct {
		Key1    uint64 `cbor:"1,key"`
		Key2    uint64 `cbor:"2,key"`
		KeyNeg1 uint64 `cbor:"-1,key"`
	}
	m := TestMap{Key1: 42, Key2: 67, KeyNeg1: 100}
	encoded, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Keys in bytewise order: 0x01, 0x02, 0x20 (1, 2, -1)
	if encoded[0] != 0xa3 {
		t.Errorf("expected map header 0xa3, got %x", encoded[0])
	}
	if encoded[1] != 0x01 {
		t.Errorf("expected key 1 (0x01), got %x", encoded[1])
	}
	if encoded[2] != 0x18 || encoded[3] != 42 {
		t.Errorf("expected value 42, got %x %x", encoded[2], encoded[3])
	}
	if encoded[4] != 0x02 {
		t.Errorf("expected key 2 (0x02), got %x", encoded[4])
	}
	if encoded[5] != 0x18 || encoded[6] != 67 {
		t.Errorf("expected value 67, got %x %x", encoded[5], encoded[6])
	}
	if encoded[7] != 0x20 {
		t.Errorf("expected key -1 (0x20), got %x", encoded[7])
	}
	if encoded[8] != 0x18 || encoded[9] != 100 {
		t.Errorf("expected value 100, got %x %x", encoded[8], encoded[9])
	}
}

// Tests that maps decode correctly.
func TestMapDecoding(t *testing.T) {
	type TestMap struct {
		Key1    uint64 `cbor:"1,key"`
		Key2    uint64 `cbor:"2,key"`
		KeyNeg1 uint64 `cbor:"-1,key"`
	}

	// Multiple entries (in correct deterministic order)
	data := []byte{
		0xa3,             // map with 3 entries
		0x01, 0x18, 0x2a, // 1: 42
		0x02, 0x18, 0x43, // 2: 67
		0x20, 0x18, 0x64, // -1: 100
	}

	var decoded TestMap
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.Key1 != 42 {
		t.Errorf("Key1: got %d, want 42", decoded.Key1)
	}
	if decoded.Key2 != 67 {
		t.Errorf("Key2: got %d, want 67", decoded.Key2)
	}
	if decoded.KeyNeg1 != 100 {
		t.Errorf("KeyNeg1: got %d, want 100", decoded.KeyNeg1)
	}
}

// Tests that maps with invalid key ordering are rejected.
func TestMapRejection(t *testing.T) {
	type TestMap struct {
		Key1    uint64 `cbor:"1,key"`
		Key2    uint64 `cbor:"2,key"`
		KeyNeg1 uint64 `cbor:"-1,key"`
	}

	// Keys out of order: 2 before 1
	data := []byte{
		0xa3,             // map with 3 entries
		0x02, 0x18, 0x43, // 2: 67 (should come after 1)
		0x01, 0x18, 0x2a, // 1: 42
		0x20, 0x18, 0x64, // -1: 100
	}

	var decoded TestMap
	if err := Unmarshal(data, &decoded); err == nil {
		t.Error("out of order keys should fail")
	}

	// Wrong key value
	data = []byte{
		0xa3,             // map with 3 entries
		0x05, 0x18, 0x2a, // 5: 42 (should be 1)
		0x02, 0x18, 0x43, // 2: 67
		0x20, 0x18, 0x64, // -1: 100
	}

	if err := Unmarshal(data, &decoded); err == nil {
		t.Error("wrong key value should fail")
	}
}

// Tests that Raw preserves bytes when re-encoded.
func TestRawEncoding(t *testing.T) {
	// Unsigned integer (42)
	raw := Raw{0x18, 0x2a}
	if encoded, _ := Marshal(raw); !bytes.Equal(encoded, []byte{0x18, 0x2a}) {
		t.Errorf("Raw encode uint: got %x, want 182a", encoded)
	}
	// String "hello"
	raw = Raw{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
	if encoded, _ := Marshal(raw); !bytes.Equal(encoded, []byte{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}) {
		t.Errorf("Raw encode string: got %x, want 6568656c6c6f", encoded)
	}
	// Tuple with Raw inside: ("method", <raw bytes for u64 1>)
	type MethodCall struct {
		_      struct{} `cbor:"_,array"`
		Method string
		Params Raw
	}
	original := MethodCall{Method: "method", Params: Raw{0x01}}
	encoded, _ := Marshal(original)
	want := []byte{
		0x82,                                     // array of 2
		0x66, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, // "method"
		0x01, // raw: u64 1
	}
	if !bytes.Equal(encoded, want) {
		t.Errorf("Raw encode tuple: got %x, want %x", encoded, want)
	}
}

// Tests that Raw captures and defers decoding correctly.
func TestRawDecoding(t *testing.T) {
	// Unsigned integer (42)
	data := []byte{0x18, 0x2a}
	var raw Raw
	if err := Unmarshal(data, &raw); err != nil {
		t.Fatalf("Raw decode uint error: %v", err)
	}
	if !bytes.Equal(raw, []byte{0x18, 0x2a}) {
		t.Errorf("Raw decode uint: got %x, want 182a", raw)
	}
	// String "hello"
	data = []byte{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
	if err := Unmarshal(data, &raw); err != nil {
		t.Fatalf("Raw decode string error: %v", err)
	}
	if !bytes.Equal(raw, []byte{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}) {
		t.Errorf("Raw decode string: got %x, want 6568656c6c6f", raw)
	}
	// Tuple with Raw: ("method", <raw params>)
	type MethodCall struct {
		_      struct{} `cbor:"_,array"`
		Method string
		Params Raw
	}
	data = []byte{
		0x82,                                     // array of 2
		0x66, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, // "method"
		0x82, 0x01, 0x63, 0x61, 0x72, 0x67, // (1, "arg")
	}
	var decoded MethodCall
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal MethodCall error: %v", err)
	}
	if decoded.Method != "method" {
		t.Errorf("Method: got %q, want %q", decoded.Method, "method")
	}
	if !bytes.Equal(decoded.Params, []byte{0x82, 0x01, 0x63, 0x61, 0x72, 0x67}) {
		t.Errorf("Params: got %x, want 82016361726", decoded.Params)
	}
	// Null (regression: pointer-level null check previously short-circuited
	// before reaching the Raw handler, causing Unmarshal into *Raw to fail)
	raw = nil
	if err := Unmarshal([]byte{0xf6}, &raw); err != nil {
		t.Fatalf("Raw decode null error: %v", err)
	}
	if !bytes.Equal(raw, []byte{0xf6}) {
		t.Errorf("Raw decode null: got %x, want f6", raw)
	}
	// Null embedded in an array-mode struct
	type NullPayload struct {
		_       struct{} `cbor:"_,array"`
		Payload Raw
	}
	data = []byte{0x81, 0xf6} // [null]
	var nullDecoded NullPayload
	if err := Unmarshal(data, &nullDecoded); err != nil {
		t.Fatalf("Unmarshal NullPayload error: %v", err)
	}
	if !bytes.Equal(nullDecoded.Payload, []byte{0xf6}) {
		t.Errorf("NullPayload.Payload: got %x, want f6", nullDecoded.Payload)
	}
}

// Tests that Raw rejects unsupported major types.
func TestRawRejection(t *testing.T) {
	// Major type 6 (tags) - unsupported
	tagged := []byte{0xc0, 0x01}
	var raw Raw
	err := Unmarshal(tagged, &raw)
	if err == nil {
		t.Error("Raw should reject tagged data")
	} else if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Expected ErrUnsupportedType, got %v", err)
	}

	// Major type 7 (bools/null) - now supported, floats still unsupported
	boolData := []byte{0xf5} // true
	err = Unmarshal(boolData, &raw)
	if err != nil {
		t.Errorf("Raw should accept bool data, got %v", err)
	}

	// Float16 is still unsupported
	floatData := []byte{0xf9, 0x3c, 0x00}
	err = Unmarshal(floatData, &raw)
	if err == nil {
		t.Error("Raw should reject float data")
	} else if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Expected ErrUnsupportedType, got %v", err)
	}

	// Trailing bytes
	data, _ := Marshal(uint64(42))
	data = append(data, 0x00)
	err = Unmarshal(data, &raw)
	if err == nil {
		t.Error("Raw should reject trailing bytes")
	} else if !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("Expected ErrTrailingBytes, got %v", err)
	}
}

// Tests that the dry-decoding verifier properly restricts the allowed types.
func TestVerify(t *testing.T) {
	type TestMap struct {
		Key1    uint64 `cbor:"1,key"`
		Key2    uint64 `cbor:"2,key"`
		KeyNeg1 uint64 `cbor:"-1,key"`
	}

	// Valid types should pass
	validCases := []any{
		uint64(42),
		int64(-42),
		"hello",
		[]byte{1, 2, 3},
		TestMap{Key1: 1, Key2: 2, KeyNeg1: 3}, // integer keys via struct tags
	}
	for _, v := range validCases {
		data, err := Marshal(v)
		if err != nil {
			t.Errorf("Marshal(%v) error: %v", v, err)
			continue
		}
		if err := Verify(data); err != nil {
			t.Errorf("Verify(%v) should pass, got %v", v, err)
		}
	}

	// Large integers are valid at verify time (overflow is checked at decode)
	largeUint := append([]byte{MajorUint<<5 | infoUint64}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)
	if err := Verify(largeUint); err != nil {
		t.Errorf("Verify large uint should pass, got %v", err)
	}

	largeNint := append([]byte{MajorNint<<5 | infoUint64}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)
	if err := Verify(largeNint); err != nil {
		t.Errorf("Verify large nint should pass, got %v", err)
	}

	// Trailing bytes
	data, _ := Marshal(uint64(42))
	data = append(data, 0x00)
	if err := Verify(data); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("Verify with trailing bytes: expected ErrTrailingBytes, got %v", err)
	}

	// Maps with string keys are rejected (key decoding fails)
	mapStrKey := []byte{0xa1, 0x61, 0x61, 0x61, 0x62} // {"a": "b"}
	err := Verify(mapStrKey)
	if err == nil {
		t.Error("Verify should reject string map keys")
	} else if !errors.Is(err, ErrInvalidMajorType) {
		t.Errorf("Expected ErrInvalidMajorType error for string key, got %v", err)
	}

	// Major type 6 (tags) - unsupported
	taggedData := []byte{0xc0, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2d, 0x30, 0x33, 0x2d, 0x32, 0x31, 0x54, 0x32, 0x30, 0x3a, 0x30, 0x34, 0x3a, 0x30, 0x30, 0x5a}
	if err := Verify(taggedData); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Verify tagged: expected ErrUnsupportedType, got %v", err)
	}

	// Booleans and null are now supported
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"false", []byte{0xf4}},
		{"true", []byte{0xf5}},
		{"null", []byte{0xf6}},
	} {
		if err := Verify(tc.data); err != nil {
			t.Errorf("Verify %s: should pass, got %v", tc.name, err)
		}
	}

	// Floats and undefined are still unsupported
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"undefined", []byte{0xf7}},
		{"float16", []byte{0xf9, 0x3c, 0x00}},
		{"float32", []byte{0xfa, 0x3f, 0x80, 0x00, 0x00}},
		{"float64", []byte{0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	} {
		if err := Verify(tc.data); !errors.Is(err, ErrUnsupportedType) {
			t.Errorf("Verify %s: expected ErrUnsupportedType, got %v", tc.name, err)
		}
	}

	// Invalid UTF-8 in text string
	invalidText := []byte{0x61, 0xff}
	if err := Verify(invalidText); !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("Verify invalid UTF-8: expected ErrInvalidUTF8, got %v", err)
	}

	// Non-canonical encodings
	nonCanonical := []byte{0x18, 0x10} // 16 encoded as infoUint8 instead of direct
	if err := Verify(nonCanonical); !errors.Is(err, ErrNonCanonical) {
		t.Errorf("Verify non-canonical: expected ErrNonCanonical, got %v", err)
	}

	// Nested arrays with booleans are now valid
	nestedBool := []byte{0x81, 0xf4} // [false]
	if err := Verify(nestedBool); err != nil {
		t.Errorf("Verify nested bool: should pass, got %v", err)
	}

	// Nested arrays with floats are still invalid
	nestedFloat := []byte{0x81, 0xf9, 0x3c, 0x00} // [1.0 as float16]
	if err := Verify(nestedFloat); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Verify nested float: expected ErrUnsupportedType, got %v", err)
	}

	// Incomplete data
	incomplete := []byte{0x61} // text string header without data
	if err := Verify(incomplete); !errors.Is(err, ErrUnexpectedEOF) {
		t.Errorf("Verify incomplete: expected ErrUnexpectedEOF, got %v", err)
	}

	// Invalid additional info
	invalidInfo := []byte{0x1c} // UINT with additional info 28 (reserved)
	if err := Verify(invalidInfo); !errors.Is(err, ErrInvalidAdditionalInfo) {
		t.Errorf("Verify invalid info: expected ErrInvalidAdditionalInfo, got %v", err)
	}
}

// Tests that Option[T] encodes and decodes correctly for top-level optional values.
func TestOptionEncoding(t *testing.T) {
	// Some(42) should encode as the inner value
	some := MakeSome[uint64](42)
	data, err := Marshal(some)
	if err != nil {
		t.Fatalf("Marshal(Some(42)) error: %v", err)
	}
	expected := []byte{0x18, 0x2a} // uint 42
	if !bytes.Equal(data, expected) {
		t.Errorf("Marshal(Some(42)): got %x, want %x", data, expected)
	}

	// None should encode as null
	none := MakeNone[uint64]()
	data, err = Marshal(none)
	if err != nil {
		t.Fatalf("Marshal(None) error: %v", err)
	}
	expected = []byte{0xf6} // null
	if !bytes.Equal(data, expected) {
		t.Errorf("Marshal(None): got %x, want %x", data, expected)
	}
}

// Tests that Option[T] decodes correctly from CBOR.
func TestOptionDecoding(t *testing.T) {
	// Decode Some(42)
	var some Option[uint64]
	if err := Unmarshal([]byte{0x18, 0x2a}, &some); err != nil {
		t.Fatalf("Unmarshal(Some(42)) error: %v", err)
	}
	if !some.Some || some.Value != 42 {
		t.Errorf("Unmarshal(Some(42)): got Some=%v, Value=%v, want Some=true, Value=42", some.Some, some.Value)
	}

	// Decode None
	var none Option[uint64]
	if err := Unmarshal([]byte{0xf6}, &none); err != nil {
		t.Fatalf("Unmarshal(None) error: %v", err)
	}
	if none.Some {
		t.Errorf("Unmarshal(None): got Some=true, want Some=false")
	}
}

// Tests that Option[T] works with complex inner types.
func TestOptionComplexTypes(t *testing.T) {
	// Option[string]
	someStr := MakeSome("hello")
	data, err := Marshal(someStr)
	if err != nil {
		t.Fatalf("Marshal(Some(\"hello\")) error: %v", err)
	}
	var decoded Option[string]
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal(Some(\"hello\")) error: %v", err)
	}
	if !decoded.Some || decoded.Value != "hello" {
		t.Errorf("Option[string] roundtrip failed: got %+v", decoded)
	}

	// Option[[]byte]
	someBytes := MakeSome([]byte{1, 2, 3})
	data, err = Marshal(someBytes)
	if err != nil {
		t.Fatalf("Marshal(Some([]byte)) error: %v", err)
	}
	var decodedBytes Option[[]byte]
	if err := Unmarshal(data, &decodedBytes); err != nil {
		t.Fatalf("Unmarshal(Some([]byte)) error: %v", err)
	}
	if !decodedBytes.Some || !bytes.Equal(decodedBytes.Value, []byte{1, 2, 3}) {
		t.Errorf("Option[[]byte] roundtrip failed: got %+v", decodedBytes)
	}
}

// Test struct for map encoding/decoding with optional fields.
type testMapOptional struct {
	Required    uint64         `cbor:"1,key"`
	Optional1   *string        `cbor:"2,key,optional"`
	Optional2   []byte         `cbor:"-1,key,optional"`
	Nullable    Option[uint64] `cbor:"3,key"`
	OptionalU64 Option[uint64] `cbor:"4,key,optional"`
}

// Tests that optional map fields are omitted when nil during encoding.
func TestMapOptionalEncoding(t *testing.T) {
	// All fields present
	s := "hello"
	m := testMapOptional{
		Required:    42,
		Optional1:   &s,
		Optional2:   []byte{1, 2, 3},
		Nullable:    MakeSome(uint64(1)),
		OptionalU64: MakeSome(uint64(99)),
	}
	data, err := Marshal(m)
	if err != nil {
		t.Fatalf("Marshal all fields: %v", err)
	}
	if data[0] != 0xa5 { // map with 5 entries
		t.Errorf("all fields: got header %x, want 0xa5", data[0])
	}
	var decoded testMapOptional
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal all fields: %v", err)
	}
	if decoded.Required != 42 || decoded.Optional1 == nil || *decoded.Optional1 != "hello" ||
		!bytes.Equal(decoded.Optional2, []byte{1, 2, 3}) || decoded.Nullable.Value != uint64(1) ||
		!decoded.OptionalU64.Some || decoded.OptionalU64.Value != 99 {
		t.Errorf("all fields roundtrip failed: %+v", decoded)
	}

	// Only required fields (both optionals nil, nullable encodes as null)
	m = testMapOptional{Required: 42}
	data, err = Marshal(m)
	if err != nil {
		t.Fatalf("Marshal required only: %v", err)
	}
	if data[0] != 0xa2 { // map with 2 entries (Required + Nullable)
		t.Errorf("required only: got header %x, want 0xa2", data[0])
	}
	if !bytes.Equal(data, []byte{0xa2, 0x01, 0x18, 0x2a, 0x03, 0xf6}) {
		t.Errorf("required only: got %x, want a201182a03f6", data)
	}
	decoded = testMapOptional{}
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal required only: %v", err)
	}
	if decoded.Required != 42 || decoded.Optional1 != nil || decoded.Optional2 != nil || decoded.Nullable.Some || decoded.OptionalU64.Some {
		t.Errorf("required only roundtrip failed: %+v", decoded)
	}

	// One optional present, one absent
	s = "hi"
	m = testMapOptional{Required: 42, Optional1: &s}
	data, err = Marshal(m)
	if err != nil {
		t.Fatalf("Marshal one optional: %v", err)
	}
	if data[0] != 0xa3 { // map with 3 entries (Required + Optional1 + Nullable)
		t.Errorf("one optional: got header %x, want 0xa3", data[0])
	}
	decoded = testMapOptional{}
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal one optional: %v", err)
	}
	if decoded.Required != 42 || decoded.Optional1 == nil || *decoded.Optional1 != "hi" || decoded.Optional2 != nil || decoded.Nullable.Some || decoded.OptionalU64.Some {
		t.Errorf("one optional roundtrip failed: %+v", decoded)
	}

	// Other optional present
	m = testMapOptional{Required: 42, Optional2: []byte{0xff}}
	data, err = Marshal(m)
	if err != nil {
		t.Fatalf("Marshal other optional: %v", err)
	}
	if data[0] != 0xa3 { // map with 3 entries (Required + Nullable + Optional2)
		t.Errorf("other optional: got header %x, want 0xa3", data[0])
	}
	decoded = testMapOptional{}
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal other optional: %v", err)
	}
	if decoded.Required != 42 || decoded.Optional1 != nil || !bytes.Equal(decoded.Optional2, []byte{0xff}) || decoded.Nullable.Some || decoded.OptionalU64.Some {
		t.Errorf("other optional roundtrip failed: %+v", decoded)
	}

	// Optional Option[uint64] present (should be included in map)
	m = testMapOptional{Required: 42, OptionalU64: MakeSome(uint64(7))}
	data, err = Marshal(m)
	if err != nil {
		t.Fatalf("Marshal optional uint64: %v", err)
	}
	if data[0] != 0xa3 { // map with 3 entries (Required + Nullable + OptionalU64)
		t.Errorf("optional uint64: got header %x, want 0xa3", data[0])
	}
	decoded = testMapOptional{}
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal optional uint64: %v", err)
	}
	if decoded.Required != 42 || decoded.Optional1 != nil || decoded.Optional2 != nil || decoded.Nullable.Some ||
		!decoded.OptionalU64.Some || decoded.OptionalU64.Value != 7 {
		t.Errorf("optional uint64 roundtrip failed: %+v", decoded)
	}
}

// Tests that optional map fields decode as nil when keys are missing.
func TestMapOptionalDecoding(t *testing.T) {
	// Decode a map with only the required fields (Nullable as null)
	var decoded testMapOptional
	err := Unmarshal([]byte{
		0xa2,             // map with 2 entries
		0x01, 0x18, 0x2a, // 1: 42
		0x03, 0xf6, // 3: null
	}, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal required only: %v", err)
	}
	if decoded.Required != 42 || decoded.Optional1 != nil || decoded.Optional2 != nil || decoded.Nullable.Some || decoded.OptionalU64.Some {
		t.Errorf("required only: %+v", decoded)
	}

	// Decode a map with required + first optional
	decoded = testMapOptional{}
	err = Unmarshal([]byte{
		0xa3,       // map with 3 entries
		0x01, 0x00, // 1: 0
		0x02, 0x62, 0x68, 0x69, // 2: "hi"
		0x03, 0xf6, // 3: null
	}, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal required + optional1: %v", err)
	}
	if decoded.Required != 0 || decoded.Optional1 == nil || *decoded.Optional1 != "hi" || decoded.Optional2 != nil || decoded.Nullable.Some || decoded.OptionalU64.Some {
		t.Errorf("required + optional1: %+v", decoded)
	}

	// Decode a map with required + second optional (key -1)
	decoded = testMapOptional{}
	err = Unmarshal([]byte{
		0xa3,       // map with 3 entries
		0x01, 0x05, // 1: 5
		0x03, 0xf6, // 3: null
		0x20, 0x41, 0xab, // -1: h'ab'
	}, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal required + optional2: %v", err)
	}
	if decoded.Required != 5 || decoded.Optional1 != nil || !bytes.Equal(decoded.Optional2, []byte{0xab}) || decoded.Nullable.Some || decoded.OptionalU64.Some {
		t.Errorf("required + optional2: %+v", decoded)
	}
}

// Tests that decoding into a reused destination zeros absent optional fields
// instead of leaving stale values from a previous decode.
func TestMapOptionalReusedDestination(t *testing.T) {
	stale := "stale"
	dest := testMapOptional{
		Required:    99,
		Optional1:   &stale,
		Optional2:   []byte{0xde, 0xad},
		Nullable:    Option[uint64]{Some: true, Value: 7},
		OptionalU64: Option[uint64]{Some: true, Value: 8},
	}
	// Wire: {1: 1, 3: null} — only required + nullable, optionals absent
	data := []byte{
		0xa2,       // map(2)
		0x01, 0x01, // key 1, uint 1
		0x03, 0xf6, // key 3, null
	}
	if err := Unmarshal(data, &dest); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if dest.Required != 1 {
		t.Errorf("Required: got %d, want 1", dest.Required)
	}
	if dest.Optional1 != nil {
		t.Errorf("Optional1: got %v, want nil (stale pointer not cleared)", dest.Optional1)
	}
	if dest.Optional2 != nil {
		t.Errorf("Optional2: got %v, want nil (stale slice not cleared)", dest.Optional2)
	}
	if dest.Nullable.Some {
		t.Errorf("Nullable: got %+v, want None", dest.Nullable)
	}
	if dest.OptionalU64.Some {
		t.Errorf("OptionalU64: got %+v, want None (stale option not cleared)", dest.OptionalU64)
	}
}

// Tests that maps with optional fields still reject invalid data.
func TestMapOptionalRejection(t *testing.T) {
	// Too many entries
	err := Unmarshal([]byte{
		0xa6,       // map with 6 entries (max is 5)
		0x01, 0x00, // 1: 0
		0x02, 0x60, // 2: ""
		0x03, 0xf6, // 3: null
		0x04, 0x00, // 4: 0
		0x05, 0x00, // 5: 0 (unknown key)
		0x20, 0x40, // -1: h''
	}, &testMapOptional{})
	if err == nil {
		t.Error("too many entries should fail")
	}

	// Required field missing (map has optional key but not the required one)
	err = Unmarshal([]byte{
		0xa1,       // map with 1 entry
		0x02, 0x60, // 2: "" (key 1 is required but missing)
	}, &testMapOptional{})
	if err == nil {
		t.Error("missing required field should fail")
	}

	// Optional *string field present but with null value (should fail:
	// optional means omitempty, not nullable)
	err = Unmarshal([]byte{
		0xa3,       // map with 3 entries
		0x01, 0x00, // 1: 0
		0x02, 0xf6, // 2: null (optional *string, but key is present)
		0x03, 0xf6, // 3: null
	}, &testMapOptional{})
	if !errors.Is(err, ErrUnexpectedNull) {
		t.Errorf("optional field with null value: got %v, want ErrUnexpectedNull", err)
	}

	// Optional []byte field present but with null value (should fail)
	err = Unmarshal([]byte{
		0xa3,       // map with 3 entries
		0x01, 0x00, // 1: 0
		0x03, 0xf6, // 3: null
		0x20, 0xf6, // -1: null (optional []byte, but key is present)
	}, &testMapOptional{})
	if !errors.Is(err, ErrUnexpectedNull) {
		t.Errorf("optional []byte with null value: got %v, want ErrUnexpectedNull", err)
	}

	// Optional Option[uint64] present but with null value (should fail:
	// optional means the key can be omitted, not that null is valid)
	err = Unmarshal([]byte{
		0xa3,       // map with 3 entries
		0x01, 0x00, // 1: 0
		0x03, 0xf6, // 3: null
		0x04, 0xf6, // 4: null (optional Option[uint64], but key is present)
	}, &testMapOptional{})
	if !errors.Is(err, ErrUnexpectedNull) {
		t.Errorf("optional Option[uint64] with null value: got %v, want ErrUnexpectedNull", err)
	}

	// Non-nilable types tagged optional should fail at marshal/unmarshal time
	type badOptionalString struct {
		Name string `cbor:"1,key,optional"`
	}
	_, err = Marshal(badOptionalString{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("optional string field: got %v, want ErrUnsupportedType", err)
	}
	err = Unmarshal([]byte{0xa1, 0x01, 0x60}, &badOptionalString{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("optional string field decode: got %v, want ErrUnsupportedType", err)
	}

	type badOptionalUint struct {
		Val uint64 `cbor:"1,key,optional"`
	}
	_, err = Marshal(badOptionalUint{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("optional uint64 field: got %v, want ErrUnsupportedType", err)
	}
}

// Tests that embedded struct fields produce identical CBOR to a flat struct
// with the same fields and keys.
func TestMapEmbedFlat(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Embedded struct {
		Inner
		C uint64 `cbor:"3,key"`
	}
	type Flat struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
		C uint64 `cbor:"3,key"`
	}
	embedded := Embedded{Inner: Inner{A: 1, B: "two"}, C: 3}
	flat := Flat{A: 1, B: "two", C: 3}

	embData, err := Marshal(embedded)
	if err != nil {
		t.Fatalf("Marshal embedded: %v", err)
	}
	flatData, err := Marshal(flat)
	if err != nil {
		t.Fatalf("Marshal flat: %v", err)
	}
	if !bytes.Equal(embData, flatData) {
		t.Errorf("embedded %x != flat %x", embData, flatData)
	}
	// Decode embedded bytes back into the embedded type
	var decoded Embedded
	if err := Unmarshal(embData, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.A != 1 || decoded.B != "two" || decoded.C != 3 {
		t.Errorf("roundtrip failed: got %+v", decoded)
	}
}

// Tests that multiple embedded structs merge into a single flat map.
func TestMapEmbedMultiple(t *testing.T) {
	type Identity struct {
		Iss string `cbor:"1,key"`
		Sub string `cbor:"2,key"`
	}
	type Temporal struct {
		Exp uint64 `cbor:"4,key"`
		Nbf uint64 `cbor:"5,key"`
	}
	type Token struct {
		Identity
		Temporal
		Aud string `cbor:"3,key"`
	}
	original := Token{
		Identity: Identity{Iss: "dark-bio", Sub: "device-1"},
		Temporal: Temporal{Exp: 2000, Nbf: 1000},
		Aud:      "api.dark.bio",
	}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if data[0] != 0xa5 { // map with 5 entries
		t.Errorf("expected map header 0xa5, got %x", data[0])
	}
	var decoded Token
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.Iss != "dark-bio" || decoded.Sub != "device-1" ||
		decoded.Aud != "api.dark.bio" || decoded.Exp != 2000 || decoded.Nbf != 1000 {
		t.Errorf("roundtrip failed: got %+v", decoded)
	}
}

// Tests that deeply nested embedding (A embeds B embeds C) works correctly.
func TestMapEmbedNested(t *testing.T) {
	type A struct {
		X uint64 `cbor:"1,key"`
	}
	type B struct {
		A
		Y uint64 `cbor:"2,key"`
	}
	type C struct {
		B
		Z uint64 `cbor:"3,key"`
	}
	original := C{B: B{A: A{X: 10}, Y: 20}, Z: 30}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if data[0] != 0xa3 { // map with 3 entries
		t.Errorf("expected map header 0xa3, got %x", data[0])
	}
	var decoded C
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.X != 10 || decoded.Y != 20 || decoded.Z != 30 {
		t.Errorf("roundtrip failed: got %+v", decoded)
	}
}

// Tests that anonymous embedded pointers are flattened like value embeds.
func TestMapEmbedPointer(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Embedded struct {
		*Inner
		C uint64 `cbor:"3,key"`
	}
	// Non-nil pointer embed: all fields present
	original := Embedded{Inner: &Inner{A: 1, B: "two"}, C: 3}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal with pointer: %v", err)
	}
	if data[0] != 0xa3 { // map with 3 entries
		t.Errorf("with pointer: expected map header 0xa3, got %x", data[0])
	}
	var decoded Embedded
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal with pointer: %v", err)
	}
	if decoded.Inner == nil || decoded.A != 1 || decoded.B != "two" || decoded.C != 3 {
		t.Errorf("with pointer roundtrip failed: got %+v", decoded)
	}

	// Nil pointer embed: Inner fields omitted from map
	nilOriginal := Embedded{C: 3}
	data, err = Marshal(nilOriginal)
	if err != nil {
		t.Fatalf("Marshal nil pointer: %v", err)
	}
	if data[0] != 0xa1 { // map with 1 entry (only key 3)
		t.Errorf("nil pointer: expected map header 0xa1, got %x", data[0])
	}
	var nilDecoded Embedded
	if err := Unmarshal(data, &nilDecoded); err != nil {
		t.Fatalf("Unmarshal nil pointer: %v", err)
	}
	if nilDecoded.Inner != nil {
		t.Errorf("nil pointer roundtrip: expected Inner == nil, got %+v", nilDecoded.Inner)
	}
	if nilDecoded.C != 3 {
		t.Errorf("nil pointer roundtrip: expected C == 3, got %d", nilDecoded.C)
	}
}

// Tests that a pointer embed with only some mandatory keys present is rejected.
// Wire data has key 1 (from *Inner) but not key 2 — partial pointer embed.
func TestMapEmbedPointerPartialRejected(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Outer struct {
		*Inner
		C uint64 `cbor:"3,key"`
	}
	// Hand-craft: {1: 42, 3: 7} — key 1 present (allocates *Inner) but key 2 missing
	data := []byte{
		0xa2,             // map(2)
		0x01, 0x18, 0x2a, // key 1, uint 42
		0x03, 0x07, // key 3, uint 7
	}
	var decoded Outer
	if err := Unmarshal(data, &decoded); err == nil {
		t.Fatal("expected error for partial pointer embed, got nil")
	}
}

// Tests that a pointer embed with all mandatory keys present but tag-optional
// ones missing is accepted.
func TestMapEmbedPointerOptionalFields(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B []byte `cbor:"2,key,optional"`
	}
	type Outer struct {
		*Inner
		C uint64 `cbor:"3,key"`
	}
	// All present: round-trip with optional field set
	original := Outer{Inner: &Inner{A: 42, B: []byte{0xab}}, C: 7}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal all present: %v", err)
	}
	if data[0] != 0xa3 { // map(3)
		t.Errorf("all present: expected 0xa3, got %x", data[0])
	}
	var decoded Outer
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal all present: %v", err)
	}
	if decoded.Inner == nil || decoded.A != 42 || !bytes.Equal(decoded.B, []byte{0xab}) || decoded.C != 7 {
		t.Errorf("all present roundtrip failed: %+v", decoded)
	}

	// Mandatory key present, optional key omitted
	original = Outer{Inner: &Inner{A: 42}, C: 7}
	data, err = Marshal(original)
	if err != nil {
		t.Fatalf("Marshal optional omitted: %v", err)
	}
	if data[0] != 0xa2 { // map(2): keys 1 and 3, optional key 2 omitted
		t.Errorf("optional omitted: expected 0xa2, got %x", data[0])
	}
	var decoded2 Outer
	if err := Unmarshal(data, &decoded2); err != nil {
		t.Fatalf("Unmarshal optional omitted: %v", err)
	}
	if decoded2.Inner == nil || decoded2.A != 42 || decoded2.B != nil || decoded2.C != 7 {
		t.Errorf("optional omitted roundtrip failed: %+v", decoded2)
	}

	// Nil pointer embed: all fields absent
	original = Outer{C: 7}
	data, err = Marshal(original)
	if err != nil {
		t.Fatalf("Marshal nil embed: %v", err)
	}
	if data[0] != 0xa1 { // map(1): only key 3
		t.Errorf("nil embed: expected 0xa1, got %x", data[0])
	}
	var decoded3 Outer
	if err := Unmarshal(data, &decoded3); err != nil {
		t.Fatalf("Unmarshal nil embed: %v", err)
	}
	if decoded3.Inner != nil {
		t.Errorf("nil embed: expected Inner == nil, got %+v", decoded3.Inner)
	}
	if decoded3.C != 7 {
		t.Errorf("nil embed: expected C == 7, got %d", decoded3.C)
	}
}

// Tests that a pointer embed containing a mandatory value embed enforces
// all-or-none: either all keys from the pointer embed (including its
// sub-embed) are present, or none.
func TestMapEmbedPointerNestedAllOrNone(t *testing.T) {
	type Sub struct {
		X uint64 `cbor:"1,key"`
	}
	type Inner struct {
		Sub
		Y uint64 `cbor:"2,key"`
	}
	type Outer struct {
		*Inner
		Z uint64 `cbor:"3,key"`
	}
	// All present: round-trip
	original := Outer{Inner: &Inner{Sub: Sub{X: 1}, Y: 2}, Z: 3}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal all: %v", err)
	}
	if data[0] != 0xa3 { // map(3)
		t.Errorf("all: expected 0xa3, got %x", data[0])
	}
	var decoded Outer
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal all: %v", err)
	}
	if decoded.Inner == nil || decoded.X != 1 || decoded.Y != 2 || decoded.Z != 3 {
		t.Errorf("all roundtrip failed: %+v", decoded)
	}

	// None present (nil pointer): only Z
	nilOriginal := Outer{Z: 3}
	data, err = Marshal(nilOriginal)
	if err != nil {
		t.Fatalf("Marshal none: %v", err)
	}
	if data[0] != 0xa1 { // map(1)
		t.Errorf("none: expected 0xa1, got %x", data[0])
	}
	var decoded2 Outer
	if err := Unmarshal(data, &decoded2); err != nil {
		t.Fatalf("Unmarshal none: %v", err)
	}
	if decoded2.Inner != nil {
		t.Errorf("none: expected Inner == nil, got %+v", decoded2.Inner)
	}

	// Partial: only key 1 (X from Sub) but not key 2 (Y) — rejected
	partial := []byte{
		0xa2,       // map(2)
		0x01, 0x01, // key 1, uint 1
		0x03, 0x03, // key 3, uint 3
	}
	var decoded3 Outer
	if err := Unmarshal(partial, &decoded3); err == nil {
		t.Fatal("expected error for partial nested pointer embed, got nil")
	}
}

// Tests that nested pointer embeds (*A containing *B) propagate group
// activity upward: decoding a key from *B activates *A's group too,
// so missing required keys in *A are rejected.
func TestMapEmbedNestedPointerAllOrNone(t *testing.T) {
	type B struct {
		Y uint64 `cbor:"2,key"`
	}
	type A struct {
		X uint64 `cbor:"1,key"`
		*B
	}
	type O struct {
		*A
		Z uint64 `cbor:"3,key"`
	}
	// All present: round-trip
	original := O{A: &A{X: 1, B: &B{Y: 2}}, Z: 3}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal all: %v", err)
	}
	var decoded O
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal all: %v", err)
	}
	if decoded.A == nil || decoded.B == nil || decoded.X != 1 || decoded.Y != 2 || decoded.Z != 3 {
		t.Errorf("all roundtrip: got %+v", decoded)
	}

	// Both pointer embeds nil: only Z present
	nilOuter := O{Z: 3}
	data, err = Marshal(nilOuter)
	if err != nil {
		t.Fatalf("Marshal none: %v", err)
	}
	var decoded2 O
	if err := Unmarshal(data, &decoded2); err != nil {
		t.Fatalf("Unmarshal none: %v", err)
	}
	if decoded2.A != nil {
		t.Errorf("none: expected A == nil, got %+v", decoded2.A)
	}

	// Outer active, inner nil: X present, Y absent — valid (*B is nil)
	outerOnly := O{A: &A{X: 1}, Z: 3}
	data, err = Marshal(outerOnly)
	if err != nil {
		t.Fatalf("Marshal outer-only: %v", err)
	}
	var decoded3 O
	if err := Unmarshal(data, &decoded3); err != nil {
		t.Fatalf("Unmarshal outer-only: %v", err)
	}
	if decoded3.A == nil || decoded3.X != 1 || decoded3.B != nil {
		t.Errorf("outer-only: got %+v", decoded3)
	}

	// Bug case: inner key present (Y from *B), outer key missing (X from *A).
	// Wire {2: val, 3: val} must fail — *B's activity propagates to *A,
	// making X required.
	partial := []byte{
		0xa2,       // map(2)
		0x02, 0x02, // key 2, uint 2
		0x03, 0x03, // key 3, uint 3
	}
	var decoded4 O
	if err := Unmarshal(partial, &decoded4); err == nil {
		t.Fatal("expected error for inner-active-outer-missing, got nil")
	} else if !errors.Is(err, ErrMissingMapKey) {
		t.Fatalf("expected ErrMissingMapKey, got %v", err)
	}
}

// Tests that out-of-order keys in a pointer embed produce ErrInvalidMapKeyOrder
// (not ErrUnexpectedItemCount) for consistent error semantics.
func TestMapEmbedPointerKeyOrderRejected(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Outer struct {
		*Inner
		C uint64 `cbor:"3,key"`
	}
	// Wire: {2: "x", 1: 42, 3: 7} — keys 2,1 out of order
	data := []byte{
		0xa3,             // map(3)
		0x02, 0x61, 0x78, // key 2, text "x"
		0x01, 0x18, 0x2a, // key 1, uint 42
		0x03, 0x07, // key 3, uint 7
	}
	var decoded Outer
	err := Unmarshal(data, &decoded)
	if !errors.Is(err, ErrInvalidMapKeyOrder) {
		t.Fatalf("expected ErrInvalidMapKeyOrder, got %v", err)
	}
}

// Tests that decoding into a pre-initialized struct with a non-nil pointer
// embed nils it out when the wire data omits all embed keys, preventing
// stale data from surviving.
func TestMapEmbedPointerReusedDestination(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Outer struct {
		*Inner
		C uint64 `cbor:"3,key"`
	}
	// Wire data: {3: 7} — only the direct field, no embed keys
	data := []byte{
		0xa1,       // map(1)
		0x03, 0x07, // key 3, uint 7
	}
	// Destination has a pre-existing non-nil Inner — decode must nil it out
	dest := Outer{Inner: &Inner{A: 99, B: "stale"}, C: 0}
	if err := Unmarshal(data, &dest); err != nil {
		t.Fatalf("Unmarshal into pre-initialized dest: %v", err)
	}
	if dest.C != 7 {
		t.Errorf("expected C == 7, got %d", dest.C)
	}
	if dest.Inner != nil {
		t.Errorf("expected Inner == nil (stale pointer cleared), got %+v", dest.Inner)
	}
}

// Tests that anonymous embedded fields with a cbor tag but without key marker
// are rejected instead of silently ignored.
func TestMapEmbedAnonymousTaggedRejected(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
	}
	type Bad struct {
		Inner `cbor:",optional"`
		B     uint64 `cbor:"2,key"`
	}
	_, err := Marshal(Bad{Inner: Inner{A: 1}, B: 2})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("tagged anonymous embed marshal: got %v, want ErrUnsupportedType", err)
	}
	err = Unmarshal([]byte{0xa2, 0x01, 0x01, 0x02, 0x02}, &Bad{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("tagged anonymous embed unmarshal: got %v, want ErrUnsupportedType", err)
	}
}

// Tests that embedding an array-mode struct into a map-mode struct is rejected
// rather than silently contributing no keys.
func TestMapEmbedArrayModeRejected(t *testing.T) {
	type InnerArray struct {
		_ struct{} `cbor:"_,array"`
		A uint64
	}
	type OuterMap struct {
		InnerArray
		B uint64 `cbor:"1,key"`
	}
	_, err := Marshal(OuterMap{InnerArray: InnerArray{A: 7}, B: 1})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("array-mode embed marshal: got %v, want ErrUnsupportedType", err)
	}
	err = Unmarshal([]byte{0xa1, 0x01, 0x01}, &OuterMap{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("array-mode embed unmarshal: got %v, want ErrUnsupportedType", err)
	}
}

// Tests that an array-mode struct with keyed fields is also rejected when
// embedded into a map-mode struct (the keyed fields would otherwise slip
// through and produce context-dependent CBOR).
func TestMapEmbedArrayModeHybridRejected(t *testing.T) {
	type Hybrid struct {
		_ struct{} `cbor:"_,array"`
		X uint64   `cbor:"1,key"`
	}
	type Outer struct {
		Hybrid
		Y uint64 `cbor:"2,key"`
	}
	_, err := Marshal(Outer{Hybrid: Hybrid{X: 42}, Y: 7})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("hybrid embed marshal: got %v, want ErrUnsupportedType", err)
	}
	err = Unmarshal([]byte{0xa2, 0x01, 0x2a, 0x02, 0x07}, &Outer{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("hybrid embed unmarshal: got %v, want ErrUnsupportedType", err)
	}
}

// Tests that optional fields inside embedded structs work correctly.
func TestMapEmbedOptional(t *testing.T) {
	type Base struct {
		ID    uint64 `cbor:"1,key"`
		Extra []byte `cbor:"2,key,optional"`
	}
	type Extended struct {
		Base
		Name string `cbor:"3,key"`
	}
	// With optional present
	original := Extended{Base: Base{ID: 42, Extra: []byte{0xab}}, Name: "test"}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal with optional: %v", err)
	}
	if data[0] != 0xa3 { // map with 3 entries
		t.Errorf("with optional: expected map header 0xa3, got %x", data[0])
	}
	var decoded Extended
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal with optional: %v", err)
	}
	if decoded.ID != 42 || !bytes.Equal(decoded.Extra, []byte{0xab}) || decoded.Name != "test" {
		t.Errorf("with optional roundtrip failed: %+v", decoded)
	}

	// Without optional (nil Extra omitted from map)
	original = Extended{Base: Base{ID: 42}, Name: "test"}
	data, err = Marshal(original)
	if err != nil {
		t.Fatalf("Marshal without optional: %v", err)
	}
	if data[0] != 0xa2 { // map with 2 entries
		t.Errorf("without optional: expected map header 0xa2, got %x", data[0])
	}
	decoded = Extended{}
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal without optional: %v", err)
	}
	if decoded.ID != 42 || decoded.Extra != nil || decoded.Name != "test" {
		t.Errorf("without optional roundtrip failed: %+v", decoded)
	}
}

// Tests that duplicate CBOR keys across embedded structs are detected.
func TestMapEmbedDuplicateKey(t *testing.T) {
	type A struct {
		X uint64 `cbor:"1,key"`
	}
	type B struct {
		Y uint64 `cbor:"1,key"` // same key as A.X
	}
	type Bad struct {
		A
		B
	}
	_, err := Marshal(Bad{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("duplicate key marshal: got %v, want ErrUnsupportedType", err)
	}
	err = Unmarshal([]byte{0xa1, 0x01, 0x00}, &Bad{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("duplicate key unmarshal: got %v, want ErrUnsupportedType", err)
	}
}

// Tests that embedded fields are correctly sorted with direct fields, including
// negative keys which sort after positives in CBOR deterministic encoding.
func TestMapEmbedKeyOrder(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type WithNeg struct {
		Inner
		Neg uint64 `cbor:"-1,key"`
	}
	original := WithNeg{Inner: Inner{A: 10, B: "hi"}, Neg: 99}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	// Keys should be sorted: 1, 2, -1 (positives before negatives in CBOR)
	if data[0] != 0xa3 {
		t.Errorf("expected map header 0xa3, got %x", data[0])
	}
	var decoded WithNeg
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.A != 10 || decoded.B != "hi" || decoded.Neg != 99 {
		t.Errorf("roundtrip failed: got %+v", decoded)
	}
}

// Tests that a direct field key colliding with an embedded field key is
// detected on both marshal and unmarshal.
func TestMapEmbedDirectCollision(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Clash struct {
		Inner
		X uint64 `cbor:"1,key"` // same key as Inner.A
	}
	_, err := Marshal(Clash{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("duplicate key marshal: got %v, want ErrUnsupportedType", err)
	}
	err = Unmarshal([]byte{0xa2, 0x01, 0x00, 0x02, 0x60}, &Clash{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("duplicate key unmarshal: got %v, want ErrUnsupportedType", err)
	}
}

// Tests that a self-referential pointer embed is rejected with
// ErrUnsupportedType rather than causing a stack overflow.
func TestMapEmbedRecursiveRejected(t *testing.T) {
	type Tree struct {
		*Tree
		Val uint64 `cbor:"1,key"`
	}
	_, err := Marshal(Tree{Val: 42})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("recursive embed marshal: got %v, want ErrUnsupportedType", err)
	}
	err = Unmarshal([]byte{0xa1, 0x01, 0x2a}, &Tree{})
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("recursive embed unmarshal: got %v, want ErrUnsupportedType", err)
	}
}

// Tests that the same type embedded via two sibling branches is not
// falsely rejected as recursive. The visited set must behave as a
// recursion stack (pop after return), not a global ever-seen set.
func TestMapEmbedSiblingsSameType(t *testing.T) {
	type Shared struct {
		X uint64 `cbor:"1,key"`
	}
	type Left struct {
		Shared
		L uint64 `cbor:"2,key"`
	}
	type Right struct {
		Shared
		R uint64 `cbor:"3,key"`
	}
	// Shared appears in both Left and Right — keys will collide (duplicate
	// key 1), but the error must be about duplicate keys, not "recursive embed".
	type Root struct {
		Left
		Right
	}
	_, err := Marshal(Root{})
	if err == nil {
		t.Fatal("expected error for duplicate key from sibling embeds, got nil")
	}
	if !errors.Is(err, ErrUnsupportedType) {
		t.Fatalf("expected ErrUnsupportedType, got %v", err)
	}
	// Verify it's a duplicate-key error, not a recursive-embed error.
	if strings.Contains(err.Error(), "recursive") {
		t.Errorf("false recursive detection: %v", err)
	}
}

// Tests that wire data containing a key not claimed by any field or embed
// is rejected during unmarshal.
func TestMapEmbedUnknownKey(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Embedded struct {
		Inner
		C uint64 `cbor:"3,key"`
	}
	// Hand-craft CBOR: {1: 1, 2: "two", 3: 3, 99: 0} — key 99 is unknown
	enc := NewEncoder()
	enc.EncodeMapHeader(4)
	enc.EncodeInt(1)
	enc.EncodeUint(1)
	enc.EncodeInt(2)
	enc.EncodeText("two")
	enc.EncodeInt(3)
	enc.EncodeUint(3)
	enc.EncodeInt(99)
	enc.EncodeUint(0)

	err := Unmarshal(enc.Bytes(), &Embedded{})
	if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("unknown key: got %v, want ErrUnexpectedItemCount", err)
	}
}

// Tests that out-of-order keys in wire data are rejected during unmarshal
// of a struct with embedded fields. The sorted-walk decoder cannot
// distinguish "missing" from "late", so it reports the first absent
// required key as ErrMissingMapKey.
func TestMapEmbedKeyOrderRejected(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Embedded struct {
		Inner
		C uint64 `cbor:"3,key"`
	}
	// Hand-craft CBOR with keys out of order: {2: "x", 1: 1, 3: 3}
	enc := NewEncoder()
	enc.EncodeMapHeader(3)
	enc.EncodeInt(2)
	enc.EncodeText("x")
	enc.EncodeInt(1)
	enc.EncodeUint(1)
	enc.EncodeInt(3)
	enc.EncodeUint(3)

	err := Unmarshal(enc.Bytes(), &Embedded{})
	if !errors.Is(err, ErrMissingMapKey) {
		t.Errorf("out-of-order keys: got %v, want ErrMissingMapKey", err)
	}
}

// Tests that wire data with a literally repeated key is rejected during
// unmarshal of a struct with embedded fields. When the duplicate causes
// the header count to exceed the field count, ErrUnexpectedItemCount
// fires at the header check before the walk even begins.
func TestMapEmbedWireDuplicateKey(t *testing.T) {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B string `cbor:"2,key"`
	}
	type Embedded struct {
		Inner
		C uint64 `cbor:"3,key"`
	}
	// Hand-craft CBOR: {1: 1, 1: 2, 2: "x", 3: 3} — duplicate key 1
	// Header = 4 but only 3 fields → caught at header count check.
	enc := NewEncoder()
	enc.EncodeMapHeader(4)
	enc.EncodeInt(1)
	enc.EncodeUint(1)
	enc.EncodeInt(1)
	enc.EncodeUint(2)
	enc.EncodeInt(2)
	enc.EncodeText("x")
	enc.EncodeInt(3)
	enc.EncodeUint(3)

	err := Unmarshal(enc.Bytes(), &Embedded{})
	if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("duplicate wire key (header overflow): got %v, want ErrUnexpectedItemCount", err)
	}
}

// Tests that a duplicate key detected during the walk (an already-decoded
// key reappearing) produces ErrDuplicateMapKey, not ErrInvalidMapKeyOrder.
func TestMapWireDuplicateKeyMidWalk(t *testing.T) {
	type S struct {
		A uint64 `cbor:"1,key"`
		B uint64 `cbor:"2,key"`
		C uint64 `cbor:"3,key"`
	}
	// Wire: {1: 1, 1: 2, 3: 3} — header=3, fields=3, duplicate key 1
	// Walk consumes key 1, then encounters key 1 again while expecting key 2.
	enc := NewEncoder()
	enc.EncodeMapHeader(3)
	enc.EncodeInt(1)
	enc.EncodeUint(1)
	enc.EncodeInt(1)
	enc.EncodeUint(2)
	enc.EncodeInt(3)
	enc.EncodeUint(3)

	err := Unmarshal(enc.Bytes(), &S{})
	if !errors.Is(err, ErrDuplicateMapKey) {
		t.Errorf("mid-walk duplicate: got %v, want ErrDuplicateMapKey", err)
	}
}

// Tests that a duplicate of the last expected key (trailing duplicate)
// produces ErrDuplicateMapKey, not the nonsensical "N must come before N".
func TestMapWireDuplicateKeyTrailing(t *testing.T) {
	type S struct {
		A *uint64 `cbor:"1,key,optional"`
		B uint64  `cbor:"3,key"`
	}
	// Wire: {3: 7, 3: 8} — header=2, fields=2, duplicate key 3.
	// Walk: key 1 (optional) absent, key 3 matches and is consumed,
	// then remaining=1 with another key 3 trailing.
	enc := NewEncoder()
	enc.EncodeMapHeader(2)
	enc.EncodeInt(3)
	enc.EncodeUint(7)
	enc.EncodeInt(3)
	enc.EncodeUint(8)

	err := Unmarshal(enc.Bytes(), &S{})
	if !errors.Is(err, ErrDuplicateMapKey) {
		t.Errorf("trailing duplicate: got %v, want ErrDuplicateMapKey", err)
	}
}

// Tests that an unknown key falling between expected keys produces
// ErrUnexpectedItemCount (not ErrInvalidMapKeyOrder).
func TestMapEmbedUnknownKeyMidRange(t *testing.T) {
	type S struct {
		A uint64 `cbor:"1,key"`
		B uint64 `cbor:"3,key"`
		C uint64 `cbor:"5,key"`
	}
	// Wire: {1: 1, 2: 2, 5: 5} — key 2 is unknown, between expected 1 and 3
	enc := NewEncoder()
	enc.EncodeMapHeader(3)
	enc.EncodeInt(1)
	enc.EncodeUint(1)
	enc.EncodeInt(2)
	enc.EncodeUint(2)
	enc.EncodeInt(5)
	enc.EncodeUint(5)

	err := Unmarshal(enc.Bytes(), &S{})
	if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("unknown mid-range key: got %v, want ErrUnexpectedItemCount", err)
	}
}

// Tests that a trailing unknown key within the expected range produces
// ErrUnexpectedItemCount, consistent with mid-walk unknown key handling.
func TestMapUnknownKeyTrailing(t *testing.T) {
	type S struct {
		A *uint64 `cbor:"1,key,optional"`
		B uint64  `cbor:"3,key"`
	}
	// Wire: {3: 7, 2: 2} — key 2 is unknown, trailing after walk.
	enc := NewEncoder()
	enc.EncodeMapHeader(2)
	enc.EncodeInt(3)
	enc.EncodeUint(7)
	enc.EncodeInt(2)
	enc.EncodeUint(2)

	err := Unmarshal(enc.Bytes(), &S{})
	if !errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("trailing unknown key: got %v, want ErrUnexpectedItemCount", err)
	}
}

// Tests that a non-integer trailing key surfaces the parse error rather
// than being masked by a generic order/count error.
func TestMapTrailingNonIntegerKey(t *testing.T) {
	type S struct {
		A *uint64 `cbor:"1,key,optional"`
		B uint64  `cbor:"3,key"`
	}
	// Wire: map(2), key 3: uint 7, text "x": uint 2
	// Field A (optional) is absent, B matches. The trailing text key "x"
	// is unconsumed after the walk; PeekInt must surface the type error.
	data := []byte{
		0xa2,       // map(2)
		0x03, 0x07, // key 3, uint 7
		0x61, 0x78, 0x02, // text "x" (key), uint 2 (value)
	}
	err := Unmarshal(data, &S{})
	if err == nil {
		t.Fatal("expected error for non-integer trailing key, got nil")
	}
	// Must NOT be ErrInvalidMapKeyOrder or ErrUnexpectedItemCount —
	// those would mask the real problem (non-integer key type).
	if errors.Is(err, ErrInvalidMapKeyOrder) {
		t.Errorf("got ErrInvalidMapKeyOrder, want type/parse error: %v", err)
	}
	if errors.Is(err, ErrUnexpectedItemCount) {
		t.Errorf("got ErrUnexpectedItemCount, want type/parse error: %v", err)
	}
}

// Tests that EncodeRaw appends pre-encoded bytes and DecodeRaw captures a
// complete CBOR item, round-tripping through the encoder/decoder.
func TestEncodeDecodeRaw(t *testing.T) {
	// Encode a map manually, then DecodeRaw each value
	enc := NewEncoder()
	enc.EncodeMapHeader(2)
	enc.EncodeInt(1)
	enc.EncodeRaw(Raw{0x18, 0x2a}) // uint 42
	enc.EncodeInt(2)
	enc.EncodeRaw(Raw{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}) // "hello"

	dec := NewDecoder(enc.Bytes())
	length, err := dec.DecodeMapHeader()
	if err != nil {
		t.Fatalf("DecodeMapHeader: %v", err)
	}
	if length != 2 {
		t.Fatalf("map length: got %d, want 2", length)
	}
	for i := range int(length) {
		if _, err := dec.DecodeInt(); err != nil {
			t.Fatalf("entry %d key: %v", i, err)
		}
		raw, err := dec.DecodeRaw()
		if err != nil {
			t.Fatalf("entry %d DecodeRaw: %v", i, err)
		}
		if i == 0 {
			if !bytes.Equal(raw, Raw{0x18, 0x2a}) {
				t.Errorf("entry 0: got %x, want 182a", raw)
			}
		} else {
			if !bytes.Equal(raw, Raw{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}) {
				t.Errorf("entry 1: got %x, want 6568656c6c6f", raw)
			}
		}
	}
	if err := dec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

// Tests that deeply nested CBOR structures are rejected with an error instead
// of causing a stack overflow, but nesting up to the maximum depth is still
// accepted.
func TestMaxNestingDepth(t *testing.T) {
	atLimit := make([]byte, maxDepth)
	for i := range atLimit {
		atLimit[i] = 0x81
	}
	atLimit[maxDepth-1] = 0x00
	if err := Verify(atLimit); err != nil {
		t.Fatalf("Verify at max depth should succeed: %v", err)
	}

	overLimit := make([]byte, maxDepth+2)
	for i := range overLimit {
		overLimit[i] = 0x81
	}
	overLimit[maxDepth+1] = 0x00
	if err := Verify(overLimit); !errors.Is(err, ErrMaxDepthExceeded) {
		t.Fatalf("Verify over max depth should fail with ErrMaxDepthExceeded, got: %v", err)
	}
}

// customValue is a test type with a pointer-receiver MarshalCBOR that wraps an
// unexported field. This mimics real types (like CWT confirmation keys) where
// the custom encoding is essential and reflection-based fallback would silently
// produce wrong output.
type customValue struct {
	secret uint64
}

func (c *customValue) MarshalCBOR(enc *Encoder) error {
	return enc.Encode(&struct {
		V uint64 `cbor:"1,key"`
	}{V: c.secret})
}

func (c *customValue) UnmarshalCBOR(dec *Decoder) error {
	var wrapper struct {
		V uint64 `cbor:"1,key"`
	}
	if err := dec.Decode(&wrapper); err != nil {
		return err
	}
	c.secret = wrapper.V
	return nil
}

// Tests that a pointer-receiver Marshaler on a struct field works identically
// whether the top-level value is passed by value or by pointer. Before the fix,
// passing by value made the field non-addressable, causing the pointer-receiver
// MarshalCBOR to be silently skipped and the unexported field to be lost.
func TestMarshalerPointerReceiver(t *testing.T) {
	type Outer struct {
		Name  string      `cbor:"1,key"`
		Inner customValue `cbor:"2,key"`
	}
	val := Outer{Name: "test", Inner: customValue{secret: 42}}

	byPtr, err := Marshal(&val)
	if err != nil {
		t.Fatalf("Marshal(&val) error: %v", err)
	}
	byVal, err := Marshal(val)
	if err != nil {
		t.Fatalf("Marshal(val) error: %v", err)
	}
	if !bytes.Equal(byPtr, byVal) {
		t.Fatalf("Marshal by value %x != by pointer %x", byVal, byPtr)
	}
	// Verify roundtrip: the custom encoding must be present and decodable
	var decoded Outer
	if err := Unmarshal(byVal, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.Name != "test" || decoded.Inner.secret != 42 {
		t.Errorf("roundtrip failed: got %+v", decoded)
	}
}

// Tests that a pointer-receiver Marshaler works on an embedded struct field
// passed through a top-level value (the realistic CWT claims pattern).
func TestMarshalerPointerReceiverEmbedded(t *testing.T) {
	type Identity struct {
		Iss string `cbor:"1,key"`
	}
	type Confirm struct {
		Cnf customValue `cbor:"8,key"`
	}
	type Claims struct {
		Identity
		Confirm
	}
	val := Claims{
		Identity: Identity{Iss: "test"},
		Confirm:  Confirm{Cnf: customValue{secret: 99}},
	}

	byPtr, err := Marshal(&val)
	if err != nil {
		t.Fatalf("Marshal(&val) error: %v", err)
	}
	byVal, err := Marshal(val)
	if err != nil {
		t.Fatalf("Marshal(val) error: %v", err)
	}
	if !bytes.Equal(byPtr, byVal) {
		t.Fatalf("Marshal by value %x != by pointer %x", byVal, byPtr)
	}
	// Verify roundtrip
	var decoded Claims
	if err := Unmarshal(byVal, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if decoded.Iss != "test" || decoded.Cnf.secret != 99 {
		t.Errorf("roundtrip failed: got Iss=%q secret=%d", decoded.Iss, decoded.Cnf.secret)
	}
}

// Tests that generic slices []T encode as CBOR arrays and roundtrip correctly.
func TestSliceRoundtrip(t *testing.T) {
	t.Run("uint64", func(t *testing.T) {
		input := []uint64{1, 2, 3}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output []uint64
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 3 || output[0] != 1 || output[1] != 2 || output[2] != 3 {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("string", func(t *testing.T) {
		input := []string{"hello", "world"}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output []string
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 2 || output[0] != "hello" || output[1] != "world" {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("bool", func(t *testing.T) {
		input := []bool{true, false, true}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output []bool
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 3 || output[0] != true || output[1] != false || output[2] != true {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("int64", func(t *testing.T) {
		input := []int64{-1, 0, 42}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output []int64
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 3 || output[0] != -1 || output[1] != 0 || output[2] != 42 {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("byte_slices", func(t *testing.T) {
		input := [][]byte{{0x01, 0x02}, {0x03}}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output [][]byte
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 2 || !bytes.Equal(output[0], []byte{0x01, 0x02}) || !bytes.Equal(output[1], []byte{0x03}) {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("empty", func(t *testing.T) {
		input := []uint64{}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		// Empty array should encode as 0x80 (array of length 0)
		if !bytes.Equal(data, []byte{0x80}) {
			t.Errorf("empty slice encoding: got %x, want 80", data)
		}
		var output []uint64
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 0 {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("nested", func(t *testing.T) {
		input := [][]uint64{{1, 2}, {3, 4}}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output [][]uint64
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 2 || len(output[0]) != 2 || len(output[1]) != 2 {
			t.Fatalf("roundtrip wrong shape: got %v", output)
		}
		if output[0][0] != 1 || output[0][1] != 2 || output[1][0] != 3 || output[1][1] != 4 {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
}

// Tests that slices of structs (both array-mode and map-mode) roundtrip correctly.
func TestSliceOfStructsRoundtrip(t *testing.T) {
	type arrayStruct struct {
		_    struct{} `cbor:"_,array"`
		Name string
		Age  uint64
	}
	type mapStruct struct {
		Name string `cbor:"1,key"`
		Age  uint64 `cbor:"2,key"`
	}
	t.Run("array_mode", func(t *testing.T) {
		input := []arrayStruct{
			{Name: "alice", Age: 30},
			{Name: "bob", Age: 25},
		}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output []arrayStruct
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 2 || output[0].Name != "alice" || output[0].Age != 30 || output[1].Name != "bob" || output[1].Age != 25 {
			t.Errorf("roundtrip failed: got %+v", output)
		}
	})
	t.Run("map_mode", func(t *testing.T) {
		input := []mapStruct{
			{Name: "alice", Age: 30},
			{Name: "bob", Age: 25},
		}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output []mapStruct
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output) != 2 || output[0].Name != "alice" || output[0].Age != 30 || output[1].Name != "bob" || output[1].Age != 25 {
			t.Errorf("roundtrip failed: got %+v", output)
		}
	})
}

// Tests that slices of types implementing Marshaler/Unmarshaler roundtrip correctly.
func TestSliceOfMarshalersRoundtrip(t *testing.T) {
	input := []customValue{{secret: 10}, {secret: 20}}
	data, err := Marshal(input)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var output []customValue
	if err := Unmarshal(data, &output); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if len(output) != 2 || output[0].secret != 10 || output[1].secret != 20 {
		t.Errorf("roundtrip failed: got %+v", output)
	}
}

// Tests that nil slices produce errors when not optional and encode as null when optional.
func TestSliceNilHandling(t *testing.T) {
	t.Run("nil_not_optional", func(t *testing.T) {
		var input []uint64 // nil
		_, err := Marshal(input)
		if !errors.Is(err, ErrUnexpectedNil) {
			t.Errorf("Marshal(nil) error: got %v, want %v", err, ErrUnexpectedNil)
		}
	})
	t.Run("null_decode_not_optional", func(t *testing.T) {
		data := []byte{0xf6} // CBOR null
		var output []uint64
		err := Unmarshal(data, &output)
		if !errors.Is(err, ErrUnexpectedNull) {
			t.Errorf("Unmarshal(null) error: got %v, want %v", err, ErrUnexpectedNull)
		}
	})
	t.Run("optional_in_struct", func(t *testing.T) {
		type s struct {
			Items []uint64 `cbor:"1,key,optional"`
		}
		// Nil slice: key should be omitted
		data, err := Marshal(s{Items: nil})
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		// Should be an empty map (1 byte: 0xa0)
		if !bytes.Equal(data, []byte{0xa0}) {
			t.Errorf("nil optional encoding: got %x, want a0", data)
		}
		// Non-nil slice: key should be present
		data, err = Marshal(s{Items: []uint64{1, 2}})
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output s
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if len(output.Items) != 2 || output.Items[0] != 1 || output.Items[1] != 2 {
			t.Errorf("roundtrip failed: got %v", output.Items)
		}
		// Decode empty map back: optional field should be nil
		var output2 s
		output2.Items = []uint64{99} // pre-fill to verify it gets cleared
		if err := Unmarshal([]byte{0xa0}, &output2); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if output2.Items != nil {
			t.Errorf("missing optional should be nil, got %v", output2.Items)
		}
	})
}

// Tests that decoding into a pre-allocated longer slice truncates correctly.
func TestSliceDecodeReuse(t *testing.T) {
	input := []uint64{10, 20}
	data, err := Marshal(input)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	output := []uint64{1, 2, 3, 4, 5} // longer than input
	if err := Unmarshal(data, &output); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if len(output) != 2 || output[0] != 10 || output[1] != 20 {
		t.Errorf("reuse decode failed: got %v", output)
	}
}

// Tests that fixed-size arrays [N]T encode and decode as CBOR arrays.
func TestFixedArrayRoundtrip(t *testing.T) {
	t.Run("uint64", func(t *testing.T) {
		input := [3]uint64{1, 2, 3}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output [3]uint64
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if output != [3]uint64{1, 2, 3} {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("string", func(t *testing.T) {
		input := [2]string{"a", "b"}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output [2]string
		if err := Unmarshal(data, &output); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if output != [2]string{"a", "b"} {
			t.Errorf("roundtrip failed: got %v", output)
		}
	})
	t.Run("length_mismatch", func(t *testing.T) {
		input := [3]uint64{1, 2, 3}
		data, err := Marshal(input)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var output [2]uint64
		err = Unmarshal(data, &output)
		if !errors.Is(err, ErrUnexpectedItemCount) {
			t.Errorf("length mismatch error: got %v, want %v", err, ErrUnexpectedItemCount)
		}
	})
}

// Tests that the CBOR encoding of []T matches the expected wire format.
func TestSliceEncoding(t *testing.T) {
	// [1, 2, 3] should be: 83 (array of 3) 01 02 03
	data, err := Marshal([]uint64{1, 2, 3})
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	expected := []byte{0x83, 0x01, 0x02, 0x03}
	if !bytes.Equal(data, expected) {
		t.Errorf("encoding: got %x, want %x", data, expected)
	}
}

// Tests that Verify accepts CBOR arrays produced by slice encoding.
func TestSliceVerify(t *testing.T) {
	data, err := Marshal([]uint64{1, 2, 3})
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if err := Verify(data); err != nil {
		t.Errorf("Verify error: %v", err)
	}
}
