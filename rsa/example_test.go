// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsa_test

import (
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/rsa"
)

// Signs a message and verifies the signature with the public key.
func Example() {
	secret := rsa.GenerateKey()

	signature, err := secret.Sign([]byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.PublicKey().Verify([]byte("hello"), signature))
	// Output: <nil>
}
