// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hkdf provides HKDF-SHA256 key derivation.
//
// https://datatracker.ietf.org/doc/html/rfc5869
//
// Derives one or more keys bound to a context string from a high-entropy
// secret, such as a shared secret or file key. For passwords, use the argon2
// package instead.
package hkdf

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// Key derives a key of length n from secret, salt, and info using HKDF-SHA256.
// salt and info may be nil or empty.
//
// Key panics if n is negative or exceeds the 8160-byte (255 * 32) HKDF-SHA256
// limit.
func Key(secret, salt, info []byte, n int) []byte {
	if n < 0 {
		panic("hkdf: negative output length")
	}
	out, err := hkdf.Key(sha256.New, secret, salt, string(info), n)
	if err != nil {
		panic(err.Error())
	}
	return out
}

// Extract derives a 32-byte pseudorandom key for use with Expand from secret
// and an optional salt.
//
// Use Extract only when reusing the pseudorandom key across multiple Expand
// calls with different contexts. Most callers should use Key instead.
func Extract(secret, salt []byte) [32]byte {
	blob, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		panic(err.Error())
	}
	if len(blob) != 32 {
		panic("hkdf: incorrect pseudorandom key length")
	}
	var prk [32]byte
	copy(prk[:], blob)
	return prk
}

// Expand derives a key of length n from a 32-byte pseudorandom key and optional
// info, skipping extraction.
//
// Pass a key produced by Extract or another uniformly random secret per RFC
// 5869 Section 3.3. Most callers should use Key instead.
//
// Expand panics if n is negative or exceeds the 8160-byte (255 * 32)
// HKDF-SHA256 limit.
func Expand(prk [32]byte, info []byte, n int) []byte {
	if n < 0 {
		panic("hkdf: negative output length")
	}
	out, err := hkdf.Expand(sha256.New, prk[:], string(info), n)
	if err != nil {
		panic(err.Error())
	}
	return out
}
