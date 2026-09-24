// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream_test

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/dark-bio/crypto-go/stream"
)

// Encrypts a message into a stream and decrypts it back.
func Example() {
	// Derive a fresh key per stream in real code, never reuse one
	var key stream.PayloadKey
	copy(key[:], bytes.Repeat([]byte{7}, stream.PayloadKeySize))

	var ciphertext bytes.Buffer
	writer := stream.Encrypt(key, &ciphertext)
	if _, err := writer.Write([]byte("hello stream")); err != nil {
		log.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		log.Fatal(err)
	}
	plaintext, err := io.ReadAll(stream.Decrypt(key, &ciphertext))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext))
	// Output: hello stream
}

// Decrypts a range from the middle of a stream without reading the rest.
func ExampleDecryptAt() {
	// Derive a fresh key per stream in real code, never reuse one
	var key stream.PayloadKey
	copy(key[:], bytes.Repeat([]byte{7}, stream.PayloadKeySize))

	var ciphertext bytes.Buffer
	writer := stream.Encrypt(key, &ciphertext)
	if _, err := writer.Write([]byte("hello random access")); err != nil {
		log.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		log.Fatal(err)
	}
	reader, err := stream.DecryptAt(key, bytes.NewReader(ciphertext.Bytes()), int64(ciphertext.Len()))
	if err != nil {
		log.Fatal(err)
	}
	word := make([]byte, 6)
	if _, err := reader.ReadAt(word, 6); err != nil {
		log.Fatal(err)
	}
	fmt.Println(reader.Size(), string(word))
	// Output: 19 random
}
