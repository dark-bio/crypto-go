// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hkdf_test

import (
	"bytes"
	"fmt"

	"github.com/dark-bio/crypto-go/hkdf"
)

// Derives two independent keys from one secret, each bound to its own context.
func Example() {
	secret := bytes.Repeat([]byte{42}, 32)

	encryption := hkdf.Key(secret, nil, []byte("example encryption key"), 32)
	authentication := hkdf.Key(secret, nil, []byte("example authentication key"), 32)
	fmt.Println(bytes.Equal(encryption, authentication))
	// Output: false
}
