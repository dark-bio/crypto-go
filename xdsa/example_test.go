// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xdsa_test

import (
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/xdsa"
)

// Signs a message, rejects a tampered one, and restores the public key from PEM.
func Example() {
	secret := xdsa.GenerateKey()
	public := secret.PublicKey()

	signature, err := secret.Sign([]byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(public.Verify([]byte("hello"), signature))
	fmt.Println(public.Verify([]byte("tampered"), signature))

	restored, err := xdsa.ParsePublicKeyPEM(public.MarshalPEM())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(restored.Fingerprint() == public.Fingerprint())
	// Output:
	// <nil>
	// xdsa: signature verification failed
	// true
}

// Signs with the two halves of a composite key as separate signers.
func ExampleSplitSign() {
	secret := xdsa.GenerateKey()
	mlKey, edKey := secret.Split()

	signature, err := xdsa.SplitSign(mlKey, edKey, []byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.PublicKey().Verify([]byte("hello"), signature))
	// Output: <nil>
}
