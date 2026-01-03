// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package argon2 provides Argon2id key derivation.
//
// https://datatracker.ietf.org/doc/html/rfc9106
package argon2

import "golang.org/x/crypto/argon2"

// Key derives a key from the password, salt, and cost parameters using Argon2id,
// returning a byte slice of the requested length, that can be used as a
// cryptographic key. The CPU cost and parallelism degree must be greater than
// zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.Key([]byte("password"), []byte("salt"), 1, 64*1024, 4, 32)
//
// RFC 9106 Section 7.4 recommends time=1, and memory=2048*1024 as a sensible
// number. If using that amount of memory (2GB) is not possible in some contexts
// then the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. The number of threads
// can be adjusted to the numbers of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
//
// https://www.rfc-editor.org/rfc/rfc9106.html#section-7.4
func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}
