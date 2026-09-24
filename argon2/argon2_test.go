// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from Go's x/crypto/argon2 package.
// Copyright 2017 The Go Authors. All rights reserved.
// https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.39.0:argon2/argon2_test.go
func TestKey(t *testing.T) {
	tests := []struct {
		time    uint32
		memory  uint32
		threads uint8
		hash    string
	}{
		{time: 1, memory: 64, threads: 1, hash: "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"},
		{time: 2, memory: 64, threads: 1, hash: "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"},
		{time: 2, memory: 64, threads: 2, hash: "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"},
		{time: 3, memory: 256, threads: 2, hash: "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"},
		{time: 4, memory: 4096, threads: 4, hash: "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a"},
		{time: 4, memory: 1024, threads: 8, hash: "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f"},
		{time: 2, memory: 64, threads: 3, hash: "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079"},
		{time: 3, memory: 1024, threads: 6, hash: "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016"},
	}
	password := []byte("password")
	salt := []byte("somesalt")

	for _, tc := range tests {
		want, _ := hex.DecodeString(tc.hash)
		got := Key(password, salt, tc.time, tc.memory, tc.threads, uint32(len(want)))
		if !bytes.Equal(got, want) {
			t.Errorf("Key(time=%d, memory=%d, threads=%d) = %x, want %x",
				tc.time, tc.memory, tc.threads, got, want)
		}
	}
}

// Tests that the smallest inputs within the limits derive a key and that each
// input just outside them panics.
func TestKeyLimits(t *testing.T) {
	password, salt := []byte("password"), []byte("somesalt")
	if key := Key(password, salt, 1, 8, 1, 4); len(key) != 4 {
		t.Fatalf("Key() = %d bytes, want 4", len(key))
	}
	tests := []struct {
		name    string
		salt    []byte
		time    uint32
		memory  uint32
		threads uint8
		keyLen  uint32
	}{
		{name: "zero time", salt: salt, time: 0, memory: 8, threads: 1, keyLen: 4},
		{name: "zero threads", salt: salt, time: 1, memory: 8, threads: 0, keyLen: 4},
		{name: "memory below 8 KiB per thread", salt: salt, time: 1, memory: 15, threads: 2, keyLen: 4},
		{name: "salt below 8 bytes", salt: salt[:7], time: 1, memory: 8, threads: 1, keyLen: 4},
		{name: "key below 4 bytes", salt: salt, time: 1, memory: 8, threads: 1, keyLen: 3},
	}
	for _, tt := range tests {
		func() {
			defer func() {
				if recover() == nil {
					t.Error(tt.name)
				}
			}()
			Key(password, tt.salt, tt.time, tt.memory, tt.threads, tt.keyLen)
		}()
	}
}
