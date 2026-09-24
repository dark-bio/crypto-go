// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cose_test

import (
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/cose"
	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// Signs a payload and verifies it, then seals a payload to a recipient and
// opens it back, each time binding a second message supplied separately.
func Example() {
	signer := xdsa.GenerateKey()
	drift := uint64(60)

	// Sign a payload, binding a second message supplied separately
	envelope, err := cose.Sign("hello", "context", signer, []byte("example"))
	if err != nil {
		log.Fatal(err)
	}
	payload, err := cose.Verify[string](envelope, "context", signer.PublicKey(), []byte("example"), &drift)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(payload)

	// Sign and encrypt to a recipient in one step, then open and verify it back
	recipient := xhpke.GenerateKey()
	sealed, err := cose.Seal("secret", "context", signer, recipient.PublicKey(), []byte("example"))
	if err != nil {
		log.Fatal(err)
	}
	opened, err := cose.Open[string](sealed, "context", recipient, signer.PublicKey(), []byte("example"), &drift)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(opened)
	// Output:
	// hello
	// secret
}
