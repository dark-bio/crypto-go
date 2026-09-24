// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pem_test

import (
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/pem"
)

// Encodes a payload into a PEM block and decodes it back.
func Example() {
	encoded := pem.Encode("EXAMPLE", []byte("hello"))
	fmt.Print(string(encoded))

	kind, data, err := pem.Decode(encoded)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(kind, string(data))
	// Output:
	// -----BEGIN EXAMPLE-----
	// aGVsbG8=
	// -----END EXAMPLE-----
	// EXAMPLE hello
}
