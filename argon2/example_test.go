// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package argon2_test

import (
	"fmt"

	"github.com/dark-bio/crypto-go/argon2"
)

// Derives a 32-byte key using RFC 9106's second recommended profile, the one
// for memory-constrained environments.
func ExampleKey() {
	// Example salt only; generate and store a fresh random 16-byte salt in real code
	salt := []byte("example salt1234")

	key := argon2.Key([]byte("password"), salt, 3, 64*1024, 4, 32)
	fmt.Println(len(key))
	// Output: 32
}
