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
		got := EncodeUint64(tc.value)
		if !bytes.Equal(got, tc.expected) {
			t.Errorf("EncodeUint64(%d) = %x, want %x", tc.value, got, tc.expected)
		}
	}
}

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
		got, err := DecodeUint64(tc.data)
		if err != nil {
			t.Errorf("DecodeUint64(%x) error: %v", tc.data, err)
			continue
		}
		if got != tc.expected {
			t.Errorf("DecodeUint64(%x) = %d, want %d", tc.data, got, tc.expected)
		}
	}
}

func TestUintRejection(t *testing.T) {
	// Values 0-23 must use direct embedding
	for value := uint64(0); value < 24; value++ {
		// Should fail with infoUint8
		data := []byte{majorUint<<5 | infoUint8, uint8(value)}
		if _, err := DecodeUint64(data); err == nil {
			t.Errorf("DecodeUint64 should reject non-canonical encoding for %d", value)
		}
	}
	// Values 24-255 must use infoUint8
	for _, value := range []uint64{24, math.MaxUint8} {
		// Should fail with infoUint16
		data := []byte{majorUint<<5 | infoUint16, 0, uint8(value)}
		if _, err := DecodeUint64(data); err == nil {
			t.Errorf("DecodeUint64 should reject non-canonical encoding for %d with infoUint16", value)
		}
	}
}

func TestIntEncoding(t *testing.T) {
	cases := []struct {
		value    int64
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{23, []byte{0x17}},
		{24, []byte{0x18, 0x18}},
		{-1, []byte{0x20}},
		{-24, []byte{0x37}},
		{-25, []byte{0x38, 0x18}},
		{-256, []byte{0x38, 0xff}},
		{-257, []byte{0x39, 0x01, 0x00}},
		{math.MaxInt64, []byte{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{math.MinInt64, []byte{0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range cases {
		got := EncodeInt64(tc.value)
		if !bytes.Equal(got, tc.expected) {
			t.Errorf("EncodeInt64(%d) = %x, want %x", tc.value, got, tc.expected)
		}
	}
}

func TestIntDecoding(t *testing.T) {
	cases := []struct {
		data     []byte
		expected int64
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x01}, 1},
		{[]byte{0x17}, 23},
		{[]byte{0x18, 0x18}, 24},
		{[]byte{0x20}, -1},
		{[]byte{0x37}, -24},
		{[]byte{0x38, 0x18}, -25},
		{[]byte{0x38, 0xff}, -256},
		{[]byte{0x39, 0x01, 0x00}, -257},
		{[]byte{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxInt64},
		{[]byte{0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MinInt64},
	}
	for _, tc := range cases {
		got, err := DecodeInt64(tc.data)
		if err != nil {
			t.Errorf("DecodeInt64(%x) error: %v", tc.data, err)
			continue
		}
		if got != tc.expected {
			t.Errorf("DecodeInt64(%x) = %d, want %d", tc.data, got, tc.expected)
		}
	}
}

func TestIntOverflow(t *testing.T) {
	// Positive integer too large for int64
	data := []byte{0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := DecodeInt64(data)
	if err == nil {
		t.Error("DecodeInt64 should reject overflow")
	}
	if !errors.Is(err, ErrIntegerOverflow) {
		t.Errorf("expected ErrIntegerOverflow, got %T", err)
	}

	// Negative integer too large
	data = []byte{0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err = DecodeInt64(data)
	if err == nil {
		t.Error("DecodeInt64 should reject negative overflow")
	}
}

func TestBytesEncoding(t *testing.T) {
	cases := []struct {
		value    []byte
		expected []byte
	}{
		{[]byte{}, []byte{0x40}},
		{[]byte{1, 2, 3}, []byte{0x43, 0x01, 0x02, 0x03}},
	}
	for _, tc := range cases {
		got := EncodeBytes(tc.value)
		if !bytes.Equal(got, tc.expected) {
			t.Errorf("EncodeBytes(%x) = %x, want %x", tc.value, got, tc.expected)
		}
	}
}

func TestBytesDecoding(t *testing.T) {
	cases := []struct {
		data     []byte
		expected []byte
	}{
		{[]byte{0x40}, []byte{}},
		{[]byte{0x43, 0x01, 0x02, 0x03}, []byte{1, 2, 3}},
	}
	for _, tc := range cases {
		got, err := DecodeBytes(tc.data)
		if err != nil {
			t.Errorf("DecodeBytes(%x) error: %v", tc.data, err)
			continue
		}
		if !bytes.Equal(got, tc.expected) {
			t.Errorf("DecodeBytes(%x) = %x, want %x", tc.data, got, tc.expected)
		}
	}
}

func TestStringEncoding(t *testing.T) {
	cases := []struct {
		value    string
		expected []byte
	}{
		{"", []byte{0x60}},
		{"hello", []byte{0x65, 'h', 'e', 'l', 'l', 'o'}},
		{"日本語", []byte{0x69, 0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac, 0xe8, 0xaa, 0x9e}},
	}
	for _, tc := range cases {
		got := EncodeString(tc.value)
		if !bytes.Equal(got, tc.expected) {
			t.Errorf("EncodeString(%q) = %x, want %x", tc.value, got, tc.expected)
		}
	}
}

func TestStringDecoding(t *testing.T) {
	cases := []struct {
		data     []byte
		expected string
	}{
		{[]byte{0x60}, ""},
		{[]byte{0x65, 'h', 'e', 'l', 'l', 'o'}, "hello"},
		{[]byte{0x69, 0xe6, 0x97, 0xa5, 0xe6, 0x9c, 0xac, 0xe8, 0xaa, 0x9e}, "日本語"},
	}
	for _, tc := range cases {
		got, err := DecodeString(tc.data)
		if err != nil {
			t.Errorf("DecodeString(%x) error: %v", tc.data, err)
			continue
		}
		if got != tc.expected {
			t.Errorf("DecodeString(%x) = %q, want %q", tc.data, got, tc.expected)
		}
	}
}

func TestStringInvalidUTF8(t *testing.T) {
	data := []byte{0x61, 0xff} // text string with invalid UTF-8
	_, err := DecodeString(data)
	if !errors.Is(err, ErrInvalidUTF8) {
		t.Errorf("expected ErrInvalidUTF8, got %v", err)
	}
}

func TestMapEncoding(t *testing.T) {
	// Empty map
	m := map[int64][]byte{}
	got := EncodeMap(m)
	if !bytes.Equal(got, []byte{0xa0}) {
		t.Errorf("EncodeMap({}) = %x, want a0", got)
	}

	// Single entry
	m = map[int64][]byte{1: EncodeUint64(42)}
	got = EncodeMap(m)
	expected := []byte{0xa1, 0x01, 0x18, 0x2a}
	if !bytes.Equal(got, expected) {
		t.Errorf("EncodeMap({1:42}) = %x, want %x", got, expected)
	}

	// Multiple entries - verify deterministic ordering
	m = map[int64][]byte{
		2:  EncodeUint64(67),
		1:  EncodeUint64(42),
		-1: EncodeUint64(100),
	}
	got = EncodeMap(m)
	// Expected order: 1, 2, -1 (positive before negative, shorter before longer)
	expected = []byte{
		0xa3,             // map with 3 entries
		0x01, 0x18, 0x2a, // 1: 42
		0x02, 0x18, 0x43, // 2: 67
		0x20, 0x18, 0x64, // -1: 100
	}
	if !bytes.Equal(got, expected) {
		t.Errorf("EncodeMap with multiple entries = %x, want %x", got, expected)
	}
}

func TestMapDecoding(t *testing.T) {
	decodeUint := func(d *Decoder) (uint64, error) {
		return d.DecodeUint()
	}

	// Empty map
	m, err := DecodeMap([]byte{0xa0}, decodeUint)
	if err != nil {
		t.Fatalf("DecodeMap empty error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("DecodeMap empty = %v, want empty", m)
	}

	// Single entry
	data := []byte{0xa1, 0x01, 0x18, 0x2a}
	m, err = DecodeMap(data, decodeUint)
	if err != nil {
		t.Fatalf("DecodeMap single error: %v", err)
	}
	if m[1] != 42 {
		t.Errorf("DecodeMap single = %v, want {1:42}", m)
	}

	// Multiple entries
	data = []byte{
		0xa3,             // map with 3 entries
		0x01, 0x18, 0x2a, // 1: 42
		0x02, 0x18, 0x43, // 2: 67
		0x20, 0x18, 0x64, // -1: 100
	}
	m, err = DecodeMap(data, decodeUint)
	if err != nil {
		t.Fatalf("DecodeMap multiple error: %v", err)
	}
	if m[1] != 42 || m[2] != 67 || m[-1] != 100 {
		t.Errorf("DecodeMap multiple = %v, want {1:42, 2:67, -1:100}", m)
	}
}

func TestMapRejection(t *testing.T) {
	decodeUint := func(d *Decoder) (uint64, error) {
		return d.DecodeUint()
	}

	// Keys out of order: 2 before 1
	data := []byte{
		0xa2,             // map with 2 entries
		0x02, 0x18, 0x2a, // 2: 42
		0x01, 0x18, 0x43, // 1: 67 (should come before 2)
	}
	_, err := DecodeMap(data, decodeUint)
	if err == nil {
		t.Error("DecodeMap should reject out-of-order keys")
	}
	if !errors.Is(err, ErrInvalidMapKeyOrder) {
		t.Errorf("expected ErrInvalidMapKeyOrder, got %T: %v", err, err)
	}

	// Negative before positive
	data = []byte{
		0xa2,             // map with 2 entries
		0x20, 0x18, 0x2a, // -1: 42
		0x01, 0x18, 0x43, // 1: 67 (should come before -1)
	}
	_, err = DecodeMap(data, decodeUint)
	if err == nil {
		t.Error("DecodeMap should reject negative before positive")
	}

	// Duplicate keys
	data = []byte{
		0xa2,             // map with 2 entries
		0x01, 0x18, 0x2a, // 1: 42
		0x01, 0x18, 0x43, // 1: 67 (duplicate)
	}
	_, err = DecodeMap(data, decodeUint)
	if err == nil {
		t.Error("DecodeMap should reject duplicate keys")
	}
	if !errors.Is(err, ErrDuplicateMapKey) {
		t.Errorf("expected ErrDuplicateMapKey, got %T: %v", err, err)
	}
}

func TestVerify(t *testing.T) {
	// Valid types should pass
	validCases := [][]byte{
		EncodeUint64(42),
		EncodeInt64(-42),
		EncodeString("hello"),
		EncodeBytes([]byte{1, 2, 3}),
		{0x80},                   // empty array
		{0x82, 0x18, 0x2a, 0x01}, // [42, 1]
		{0xa0},                   // empty map
		{0xa1, 0x01, 0x18, 0x2a}, // {1: 42}
	}
	for _, data := range validCases {
		if err := Verify(data); err != nil {
			t.Errorf("Verify(%x) should pass, got %v", data, err)
		}
	}

	// Trailing bytes
	data := append(EncodeUint64(42), 0x00)
	if err := Verify(data); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("Verify with trailing bytes: expected ErrTrailingBytes, got %v", err)
	}

	// Maps with string keys are rejected
	mapStrKey := []byte{0xa1, 0x61, 0x61, 0x61, 0x62} // {"a": "b"}
	err := Verify(mapStrKey)
	if err == nil {
		t.Error("Verify should reject map with string keys")
	}

	// Major type 6 (tags) - unsupported
	taggedData := []byte{0xc0, 0x74, 0x32, 0x30, 0x31, 0x33}
	err = Verify(taggedData)
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Verify tagged: expected ErrUnsupportedType, got %v", err)
	}

	// Major type 7 (floats/booleans/null) - unsupported
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
		err := Verify(tc.data)
		if !errors.Is(err, ErrUnsupportedType) {
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
	err = Verify(nestedInvalid)
	if !errors.Is(err, ErrUnsupportedType) {
		t.Errorf("Verify nested invalid: expected ErrUnsupportedType, got %v", err)
	}

	// Incomplete data
	incomplete := []byte{0x61} // text string header without data
	if err := Verify(incomplete); !errors.Is(err, ErrUnexpectedEOF) {
		t.Errorf("Verify incomplete: expected ErrUnexpectedEOF, got %v", err)
	}

	// Invalid additional info
	invalidInfo := []byte{0x1c} // UINT with additional info 28 (reserved)
	err = Verify(invalidInfo)
	if !errors.Is(err, ErrInvalidAdditionalInfo) {
		t.Errorf("Verify invalid info: expected ErrInvalidAdditionalInfo, got %v", err)
	}
}

// Tests a length overflow issue caught by the fuzzer in crypto-rs:
// https://github.com/dark-bio/crypto-rs/pull/3
func TestIssue3(t *testing.T) {
	encoded := []byte{123, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	_, err := DecodeString(encoded)
	if err == nil {
		t.Error("DecodeString should reject malformed data")
	}
}

func TestEncodeDecodeStruct(t *testing.T) {
	type Inner struct {
		Value uint64
		Name  string
	}
	type Outer struct {
		Protected   []byte
		Unprotected map[int64]string
		Payload     []byte
		Inner       Inner
	}

	original := Outer{
		Protected:   []byte{1, 2, 3},
		Unprotected: map[int64]string{1: "alg", 2: "kid"},
		Payload:     []byte("hello world"),
		Inner:       Inner{Value: 42, Name: "test"},
	}

	encoded := EncodeStruct(original)

	var decoded Outer
	err := DecodeStruct(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeStruct error: %v", err)
	}

	if !bytes.Equal(decoded.Protected, original.Protected) {
		t.Errorf("Protected mismatch: got %x, want %x", decoded.Protected, original.Protected)
	}
	if !bytes.Equal(decoded.Payload, original.Payload) {
		t.Errorf("Payload mismatch: got %x, want %x", decoded.Payload, original.Payload)
	}
	if decoded.Unprotected[1] != "alg" || decoded.Unprotected[2] != "kid" {
		t.Errorf("Unprotected mismatch: got %v", decoded.Unprotected)
	}
	if decoded.Inner.Value != 42 || decoded.Inner.Name != "test" {
		t.Errorf("Inner mismatch: got %+v", decoded.Inner)
	}
}

func TestEncodeDecodeStructWithFixedArray(t *testing.T) {
	type WithFixedArray struct {
		Hash [32]byte
		Data []byte
	}

	original := WithFixedArray{
		Hash: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Data: []byte("test data"),
	}

	encoded := EncodeStruct(original)

	var decoded WithFixedArray
	err := DecodeStruct(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeStruct error: %v", err)
	}

	if decoded.Hash != original.Hash {
		t.Errorf("Hash mismatch: got %x, want %x", decoded.Hash, original.Hash)
	}
	if !bytes.Equal(decoded.Data, original.Data) {
		t.Errorf("Data mismatch: got %x, want %x", decoded.Data, original.Data)
	}
}

func TestEncodeDecodeNestedStruct(t *testing.T) {
	type Level3 struct {
		Value int64
	}
	type Level2 struct {
		L3 Level3
	}
	type Level1 struct {
		L2 Level2
	}

	original := Level1{L2: Level2{L3: Level3{Value: -42}}}
	encoded := EncodeStruct(original)

	var decoded Level1
	err := DecodeStruct(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeStruct error: %v", err)
	}

	if decoded.L2.L3.Value != -42 {
		t.Errorf("Nested value mismatch: got %d, want -42", decoded.L2.L3.Value)
	}
}

func TestEncodeDecodeMapInStruct(t *testing.T) {
	type WithMap struct {
		Headers map[int64]uint64
	}

	original := WithMap{
		Headers: map[int64]uint64{1: 100, 2: 200, -1: 300},
	}

	encoded := EncodeStruct(original)

	var decoded WithMap
	err := DecodeStruct(encoded, &decoded)
	if err != nil {
		t.Fatalf("DecodeStruct error: %v", err)
	}

	if decoded.Headers[1] != 100 || decoded.Headers[2] != 200 || decoded.Headers[-1] != 300 {
		t.Errorf("Map mismatch: got %v", decoded.Headers)
	}
}

func TestRoundtrip(t *testing.T) {
	// Test uint64 roundtrip
	for _, v := range []uint64{0, 1, 23, 24, 255, 256, 65535, 65536, math.MaxUint32, math.MaxUint64} {
		encoded := EncodeUint64(v)
		decoded, err := DecodeUint64(encoded)
		if err != nil {
			t.Errorf("uint64 roundtrip %d: %v", v, err)
		}
		if decoded != v {
			t.Errorf("uint64 roundtrip %d: got %d", v, decoded)
		}
	}

	// Test int64 roundtrip
	for _, v := range []int64{0, 1, -1, 23, 24, -24, -25, 255, -256, math.MaxInt64, math.MinInt64} {
		encoded := EncodeInt64(v)
		decoded, err := DecodeInt64(encoded)
		if err != nil {
			t.Errorf("int64 roundtrip %d: %v", v, err)
		}
		if decoded != v {
			t.Errorf("int64 roundtrip %d: got %d", v, decoded)
		}
	}

	// Test string roundtrip
	for _, v := range []string{"", "hello", "日本語", "🎉"} {
		encoded := EncodeString(v)
		decoded, err := DecodeString(encoded)
		if err != nil {
			t.Errorf("string roundtrip %q: %v", v, err)
		}
		if decoded != v {
			t.Errorf("string roundtrip %q: got %q", v, decoded)
		}
	}

	// Test bytes roundtrip
	for _, v := range [][]byte{{}, {0}, {1, 2, 3}, make([]byte, 256)} {
		encoded := EncodeBytes(v)
		decoded, err := DecodeBytes(encoded)
		if err != nil {
			t.Errorf("bytes roundtrip %x: %v", v, err)
		}
		if !bytes.Equal(decoded, v) {
			t.Errorf("bytes roundtrip %x: got %x", v, decoded)
		}
	}
}
