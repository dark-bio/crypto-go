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

func TestMarshalUnmarshalUint64(t *testing.T) {
	cases := []uint64{0, 1, 23, 24, 255, 256, 65535, 65536, math.MaxUint32, math.MaxUint64}
	for _, v := range cases {
		data, err := Marshal(v)
		if err != nil {
			t.Errorf("Marshal(%d) error: %v", v, err)
			continue
		}
		var got uint64
		if err := Unmarshal(data, &got); err != nil {
			t.Errorf("Unmarshal(%d) error: %v", v, err)
			continue
		}
		if got != v {
			t.Errorf("roundtrip %d: got %d", v, got)
		}
	}
}

func TestMarshalUnmarshalInt64(t *testing.T) {
	cases := []int64{0, 1, -1, 23, 24, -24, -25, 255, -256, math.MaxInt64, math.MinInt64}
	for _, v := range cases {
		data, err := Marshal(v)
		if err != nil {
			t.Errorf("Marshal(%d) error: %v", v, err)
			continue
		}
		var got int64
		if err := Unmarshal(data, &got); err != nil {
			t.Errorf("Unmarshal(%d) error: %v", v, err)
			continue
		}
		if got != v {
			t.Errorf("roundtrip %d: got %d", v, got)
		}
	}
}

func TestMarshalUnmarshalBytes(t *testing.T) {
	cases := [][]byte{{}, {0}, {1, 2, 3}, make([]byte, 256)}
	for _, v := range cases {
		data, err := Marshal(v)
		if err != nil {
			t.Errorf("Marshal(%x) error: %v", v, err)
			continue
		}
		var got []byte
		if err := Unmarshal(data, &got); err != nil {
			t.Errorf("Unmarshal(%x) error: %v", v, err)
			continue
		}
		if !bytes.Equal(got, v) {
			t.Errorf("roundtrip %x: got %x", v, got)
		}
	}
}

func TestMarshalUnmarshalString(t *testing.T) {
	cases := []string{"", "hello", "日本語", "🎉"}
	for _, v := range cases {
		data, err := Marshal(v)
		if err != nil {
			t.Errorf("Marshal(%q) error: %v", v, err)
			continue
		}
		var got string
		if err := Unmarshal(data, &got); err != nil {
			t.Errorf("Unmarshal(%q) error: %v", v, err)
			continue
		}
		if got != v {
			t.Errorf("roundtrip %q: got %q", v, got)
		}
	}
}

func TestMarshalStructRejectsStringKeys(t *testing.T) {
	// Structs encode field names as string keys, which are not permitted
	// in our restricted CBOR subset (integer keys only).
	type Simple struct {
		Value uint64
	}
	_, err := Marshal(Simple{Value: 42})
	if err == nil {
		t.Fatal("Marshal should reject struct (string keys)")
	}
}

func TestMarshalNestedArrays(t *testing.T) {
	// Test nested arrays (slices) which are valid
	original := [][]int64{{1, 2, 3}, {-1, -2}}
	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded [][]int64
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if len(decoded) != 2 || len(decoded[0]) != 3 || decoded[0][0] != 1 || decoded[1][1] != -2 {
		t.Errorf("Nested arrays mismatch: got %v", decoded)
	}
}

func TestMarshalMapRejectsStringKeys(t *testing.T) {
	// String-keyed maps are not permitted in our restricted CBOR subset.
	original := map[string]uint64{"a": 1, "b": 2}
	_, err := Marshal(original)
	if err == nil {
		t.Fatal("Marshal should reject map[string]... (string keys)")
	}
}

func TestMarshalUnmarshalIntKeyMap(t *testing.T) {
	original := map[int64]string{1: "one", 2: "two", -1: "neg"}

	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded map[int64]string
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded[1] != "one" || decoded[2] != "two" || decoded[-1] != "neg" {
		t.Errorf("Map mismatch: got %v", decoded)
	}
}

func TestVerify(t *testing.T) {
	// Valid types should pass
	validCases := []any{
		uint64(42),
		int64(-42),
		"hello",
		[]byte{1, 2, 3},
		[]int{1, 2, 3},
		map[int64]int{1: 1, 2: 2}, // integer keys only
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

	// String-keyed maps should be rejected
	stringKeyMap := []byte{0xa1, 0x61, 0x61, 0x01} // {"a": 1}
	if err := Verify(stringKeyMap); err == nil {
		t.Error("Verify should reject string map keys")
	}

	// Trailing bytes
	data, _ := Marshal(uint64(42))
	data = append(data, 0x00)
	if err := Verify(data); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("Verify with trailing bytes: expected ErrTrailingBytes, got %v", err)
	}

	// Major type 6 (tags) - unsupported
	taggedData := []byte{0xc0, 0x74, 0x32, 0x30, 0x31, 0x33}
	err := Verify(taggedData)
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
	var s string
	err := Unmarshal(encoded, &s)
	if err == nil {
		t.Error("Unmarshal should reject malformed data")
	}
}

func TestMarshalUnmarshalFixedByteArray(t *testing.T) {
	// Test fixed-size byte arrays directly (not in structs)
	original := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	data, err := Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded [32]byte
	if err := Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded != original {
		t.Errorf("Fixed array mismatch: got %x, want %x", decoded, original)
	}
}
