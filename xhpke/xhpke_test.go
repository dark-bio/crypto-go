// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke

import (
	"bytes"
	"testing"
)

// Tests that a private key can be serialized to bytes and parsed back.
func TestSecretKeyBytesRoundtrip(t *testing.T) {
	key := GenerateKey()
	keyBytes := key.Marshal()
	parsed := ParseSecretKey(keyBytes)
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("secret key bytes roundtrip failed")
	}
}

// Tests that a public key can be serialized to bytes and parsed back.
func TestPublicKeyBytesRoundtrip(t *testing.T) {
	key := GenerateKey().PublicKey()
	keyBytes := key.Marshal()
	parsed, err := ParsePublicKey(keyBytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("public key bytes roundtrip failed")
	}
}

// Tests that a private key can be serialized to DER and parsed back.
func TestSecretKeyDERRoundtrip(t *testing.T) {
	key := GenerateKey()
	der := key.MarshalDER()
	parsed, err := ParseSecretKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse DER: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("secret key DER roundtrip failed")
	}
}

// Tests that a private key can be serialized to PEM and parsed back.
func TestSecretKeyPEMRoundtrip(t *testing.T) {
	key := GenerateKey()
	pemStr := key.MarshalPEM()
	parsed, err := ParseSecretKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("failed to parse PEM: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("secret key PEM roundtrip failed")
	}
}

// Tests that a public key can be serialized to DER and parsed back.
func TestPublicKeyDERRoundtrip(t *testing.T) {
	key := GenerateKey().PublicKey()
	der := key.MarshalDER()
	parsed, err := ParsePublicKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse DER: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("public key DER roundtrip failed")
	}
}

// Tests that a public key can be serialized to PEM and parsed back.
func TestPublicKeyPEMRoundtrip(t *testing.T) {
	key := GenerateKey().PublicKey()
	pemStr := key.MarshalPEM()
	parsed, err := ParsePublicKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("failed to parse PEM: %v", err)
	}
	if key.Marshal() != parsed.Marshal() {
		t.Fatal("public key PEM roundtrip failed")
	}
}

// Tests sealing and opening various combinations of messages.
func TestSealOpen(t *testing.T) {
	// Create the keys
	secret := GenerateKey()
	public := secret.PublicKey()

	// Run a bunch of different authentication/encryption combinations
	tests := []struct {
		name    string
		sealMsg []byte
		authMsg []byte
	}{
		// Only message to authenticate
		{
			sealMsg: []byte{},
			authMsg: []byte("message to authenticate"),
		},
		// Only message to encrypt
		{
			sealMsg: []byte("message to encrypt"),
			authMsg: []byte{},
		},
		// Both message to authenticate and to encrypt
		{
			sealMsg: []byte("message to encrypt"),
			authMsg: []byte("message to authenticate"),
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Seal the message to the public key
			sessionKey, ciphertext, err := public.Seal(tt.sealMsg, tt.authMsg, "test")
			if err != nil {
				t.Fatalf("test %d: failed to seal: %v", i, err)
			}
			// Open the sealed message with the secret key
			plaintext, err := secret.Open(&sessionKey, ciphertext, tt.authMsg, "test")
			if err != nil {
				t.Fatalf("test %d: failed to open: %v", i, err)
			}
			// Validate that the cleartext matches our expected encrypted payload
			if !bytes.Equal(plaintext, tt.sealMsg) {
				t.Fatalf("test %d: plaintext mismatch: got %q, want %q", i, plaintext, tt.sealMsg)
			}
		})
	}
}
