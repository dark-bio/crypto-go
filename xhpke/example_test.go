// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke_test

import (
	"errors"
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/xhpke"
)

// Encrypts a message to a public key, binding a header that travels separately,
// and opens it with the secret key.
func Example() {
	secret := xhpke.GenerateKey()

	encapKey, ciphertext, err := secret.PublicKey().Seal([]byte("secret"), []byte("header"), []byte("example"))
	if err != nil {
		log.Fatal(err)
	}
	plaintext, err := secret.Open(&encapKey, ciphertext, []byte("header"), []byte("example"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext))

	// A tampered header fails authentication
	_, err = secret.Open(&encapKey, ciphertext, []byte("other"), []byte("example"))
	fmt.Println(errors.Is(err, xhpke.ErrOpenFailed))
	// Output:
	// secret
	// true
}

// Seals several messages under one encapsulated key and opens them in order.
func Example_senderReceiver() {
	secret := xhpke.GenerateKey()

	sender, encapKey, err := secret.PublicKey().NewSender([]byte("example"))
	if err != nil {
		log.Fatal(err)
	}
	receiver, err := secret.NewReceiver(&encapKey, []byte("example"))
	if err != nil {
		log.Fatal(err)
	}
	for _, message := range []string{"first", "second"} {
		ciphertext, err := sender.Seal([]byte(message), nil)
		if err != nil {
			log.Fatal(err)
		}
		plaintext, err := receiver.Open(ciphertext, nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(plaintext))
	}
	// Output:
	// first
	// second
}
