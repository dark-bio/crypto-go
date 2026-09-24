// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package argon2 provides Argon2id key derivation.
//
// https://datatracker.ietf.org/doc/html/rfc9106
//
// It turns a password and a salt into key material, made deliberately slow and
// memory hungry so guessing passwords is expensive. For stretching a secret
// that is already random, see the hkdf package instead.
package argon2

import "golang.org/x/crypto/argon2"

// Key derives a key from the password, salt, and cost parameters using Argon2id,
// returning a byte slice of the requested length that can be used as a
// cryptographic key.
//
// RFC 9106 Section 4 recommends time=1, memory=2*1024*1024 (2 GiB) and
// threads=4. Its second recommendation uses time=3, memory=64*1024 (64 MiB)
// and threads=4. Both use a random 16-byte salt and a 32-byte output, and the
// RFC requires salts of at least 8 bytes.
//
// The time parameter is the number of passes and memory is the total working
// memory in KiB. The threads parameter is Argon2's lane count, an algorithm
// parameter that changes the derived key. The lanes run concurrently, but the
// count must not follow the CPU count, or one password derives different keys
// on different devices. Store the salt and all cost parameters so the same key
// can be reproduced elsewhere.
//
// Key panics if time or threads is zero.
//
// https://www.rfc-editor.org/rfc/rfc9106.html#section-4
func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}
