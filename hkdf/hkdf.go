// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hkdf provides HKDF-SHA256 key derivation.
//
// https://datatracker.ietf.org/doc/html/rfc5869
package hkdf

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Key derives a key of length n from the secret, salt, and info using
// HKDF-SHA256. The salt and info may be nil or empty.
//
// Panics if n exceeds the maximum output length for SHA-256 HKDF, which is
// 255 * 32 = 8160 bytes.
func Key(secret, salt, info []byte, n int) []byte {
	r := hkdf.New(sha256.New, secret, salt, info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		panic("hkdf: " + err.Error())
	}
	return out
}
