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
		data := []byte{majorUint<<5 | infoUint8, byte(value)}
		var got uint64
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint8 should fail", value)
		}

		// Should fail with infoUint16
		data = []byte{majorUint<<5 | infoUint16, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint16 should fail", value)
		}

		// Should fail with infoUint32
		data = []byte{majorUint<<5 | infoUint32, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint32 should fail", value)
		}

		// Should fail with infoUint64
		data = []byte{majorUint<<5 | infoUint64, 0, 0, 0, 0, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint64 should fail", value)
		}
	}

	// Values 24-255 must use infoUint8
	for value := uint64(24); value <= math.MaxUint8; value++ {
		var got uint64

		// Should fail with infoUint16
		data := []byte{majorUint<<5 | infoUint16, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint16 should fail", value)
		}

		// Should fail with infoUint32
		data = []byte{majorUint<<5 | infoUint32, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint32 should fail", value)
		}

		// Should fail with infoUint64
		data = []byte{majorUint<<5 | infoUint64, 0, 0, 0, 0, 0, 0, 0, byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint64 should fail", value)
		}
	}

	// Values 256-65535 must use infoUint16
	for _, value := range []uint64{math.MaxUint8 + 1, math.MaxUint16} {
		var got uint64

		// Should fail with infoUint32
		data := []byte{majorUint<<5 | infoUint32, 0, 0, byte(value >> 8), byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint32 should fail", value)
		}

		// Should fail with infoUint64
		data = []byte{majorUint<<5 | infoUint64, 0, 0, 0, 0, 0, 0, byte(value >> 8), byte(value)}
		if err := Unmarshal(data, &got); err == nil {
			t.Errorf("value %d with infoUint64 should fail", value)
		}
	}

	// Values 65536-4294967295 must use infoUint32
	for _, value := range []uint64{math.MaxUint16 + 1, math.MaxUint32} {
		var got uint64

		// Should fail with infoUint64
		data := []byte{majorUint<<5 | infoUint64, 0, 0, 0, 0, byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
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
	data := []byte{majorUint<<5 | infoUint64, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	var got int64
	err := Unmarshal(data, &got)
	if err == nil {
		t.Error("positive overflow should fail")
	} else if !errors.Is(err, ErrIntegerOverflow) {
		t.Errorf("expected ErrIntegerOverflow, got %v", err)
	}

	// Negative value < i64::MIN (major type 1 with wire value > i64::MAX)
	data = []byte{majorNint<<5 | infoUint64, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	err = Unmarshal(data, &got)
	if err == nil {
		t.Error("negative overflow should fail")
	} else if !errors.Is(err, ErrIntegerOverflow) {
		t.Errorf("expected ErrIntegerOverflow, got %v", err)
	}

	// Non-canonical negative integer encoding
	data = []byte{majorNint<<5 | infoUint8, 0x10} // -17 with infoUint8
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

	// Major type 7 (floats/bools) - unsupported
	floatData := []byte{0xf5}
	err = Unmarshal(floatData, &raw)
	if err == nil {
		t.Error("Raw should reject float/bool data")
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
	largeUint := append([]byte{majorUint<<5 | infoUint64}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)
	if err := Verify(largeUint); err != nil {
		t.Errorf("Verify large uint should pass, got %v", err)
	}

	largeNint := append([]byte{majorNint<<5 | infoUint64}, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}...)
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

	// Major type 7 (floats/booleans/null/undefined) - unsupported
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"false", []byte{0xf4}},
		{"true", []byte{0xf5}},
		{"null", []byte{0xf6}},
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

	// Nested arrays with invalid content
	nestedInvalid := []byte{0x81, 0xf4} // [false]
	if err := Verify(nestedInvalid); !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Verify nested invalid: expected ErrUnsupportedType, got %v", err)
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
