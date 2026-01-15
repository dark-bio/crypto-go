// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eddsa

import (
	"testing"
)

// Tests signing and verifying messages. Note, this test is not meant to test
// cryptography, it is mostly an API sanity check to verify that everything
// seems to work.
//
// TODO(karalabe): Get some live test vectors for a bit more sanity
func TestSignVerify(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	message := []byte("message to authenticate")
	signature, _ := secret.Sign(message)

	if err := public.Verify(message, signature); err != nil {
		t.Fatalf("failed to verify message: %v", err)
	}
	// Verify wrong message fails
	if err := public.Verify([]byte("wrong message"), signature); err == nil {
		t.Fatal("expected verification to fail for wrong message")
	}
}
