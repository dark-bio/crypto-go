// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mldsa_test

import (
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/mldsa"
)

// Signs a message under a context string and verifies it with the public key.
func Example() {
	secret := mldsa.GenerateKey()

	signature, err := secret.Sign([]byte("hello"), []byte("example-context"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.PublicKey().Verify([]byte("hello"), []byte("example-context"), signature))
	// Output: <nil>
}
