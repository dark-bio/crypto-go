// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbor

import (
	"reflect"
	"testing"
)

func FuzzRoundtrip(f *testing.F) {
	// Add some seed corpus
	f.Add([]byte{0x00})                   // uint 0
	f.Add([]byte{0x20})                   // int -1
	f.Add([]byte{0x60})                   // empty text
	f.Add([]byte{0x40})                   // empty bytes
	f.Add([]byte{0x80})                   // empty array
	f.Add([]byte{0xa0})                   // empty map
	f.Add([]byte{0x65, 'h', 'e', 'l', 'l', 'o'}) // text "hello"

	f.Fuzz(func(t *testing.T, data []byte) {
		roundtrip[string](t, data)
		roundtrip[uint64](t, data)
		roundtrip[int64](t, data)
		roundtrip[[]byte](t, data)
		roundtrip[struct{}](t, data)
		roundtrip[struct{ A string }](t, data)
		roundtrip[struct{ A uint64 }](t, data)
		roundtrip[struct{ A int64 }](t, data)
		roundtrip[struct {
			A string
			B uint64
		}](t, data)
		roundtrip[struct {
			A string
			B int64
		}](t, data)
		roundtrip[struct {
			A uint64
			B string
		}](t, data)
		roundtrip[struct {
			A int64
			B string
		}](t, data)
		roundtrip[struct {
			A string
			B string
		}](t, data)
		roundtrip[struct {
			A uint64
			B int64
		}](t, data)
		roundtrip[struct {
			A int64
			B uint64
		}](t, data)
		roundtrip[[1]byte](t, data)
		roundtrip[[2]byte](t, data)
		roundtrip[[4]byte](t, data)
		roundtrip[[8]byte](t, data)
		roundtrip[struct {
			A struct {
				X uint64
				Y [4]byte
			}
			B struct {
				X string
				Y uint64
			}
		}](t, data)
		roundtrip[struct {
			A struct {
				X int64
				Y [4]byte
			}
			B struct {
				X string
				Y int64
			}
		}](t, data)
		roundtrip[map[int64]uint64](t, data)
		roundtrip[map[int64]string](t, data)
		roundtrip[map[int64][]byte](t, data)
		roundtrip[map[int64]map[int64]uint64](t, data)
	})
}

func roundtrip[T any](t *testing.T, data []byte) {
	var decoded T
	if err := DecodeStruct(data, &decoded); err != nil {
		return
	}
	encoded := EncodeStruct(decoded)

	var decoded2 T
	if err := DecodeStruct(encoded, &decoded2); err != nil {
		t.Fatalf("failed to decode re-encoded data for %T: %v", decoded, err)
	}
	if !reflect.DeepEqual(decoded, decoded2) {
		t.Fatalf("roundtrip failed for type %T: got %v, want %v", decoded, decoded2, decoded)
	}
}
