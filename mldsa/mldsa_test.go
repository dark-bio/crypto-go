// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mldsa

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors - fill in from OpenSSL
var testVectors = struct {
	SecretKeyDER string // PKCS#8 DER hex
	PublicKeyDER string // SPKI DER hex
}{
	SecretKeyDER: "", // openssl genpkey -algorithm ml-dsa-65 -outform DER | xxd -p
	PublicKeyDER: "", // openssl pkey -in key.pem -outform DER -pubout | xxd -p
}

// TestSecretKeyDERCodec tests DER encoding/decoding of secret keys.
func TestSecretKeyDERCodec(t *testing.T) {
	if testVectors.SecretKeyDER == "" {
		t.Skip("no test vector provided")
	}
	der, _ := hex.DecodeString(testVectors.SecretKeyDER)

	key, err := ParseSecretKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse DER: %v", err)
	}
	encoded := key.MarshalDER()
	if !bytes.Equal(encoded, der) {
		t.Fatal("re-encoded DER does not match")
	}
}

// TestPublicKeyDERCodec tests DER encoding/decoding of public keys.
func TestPublicKeyDERCodec(t *testing.T) {
	if testVectors.PublicKeyDER == "" {
		t.Skip("no test vector provided")
	}
	der, _ := hex.DecodeString(testVectors.PublicKeyDER)

	key, err := ParsePublicKeyDER(der)
	if err != nil {
		t.Fatalf("failed to parse DER: %v", err)
	}
	encoded := key.MarshalDER()
	if !bytes.Equal(encoded, der) {
		t.Fatal("re-encoded DER does not match")
	}
}

// TestSignVerify tests signing and verifying messages.
func TestSignVerify(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	tests := []struct {
		message []byte
		ctx     []byte
	}{
		{message: []byte("message to authenticate"), ctx: nil},
		{message: []byte("message to authenticate"), ctx: []byte("application context")},
	}
	for _, tt := range tests {
		signature := secret.Sign(tt.message, tt.ctx)
		if err := public.Verify(tt.message, tt.ctx, signature); err != nil {
			t.Fatalf("failed to verify message: %v", err)
		}
		// Verify wrong context fails
		if err := public.Verify(tt.message, []byte("wrong context"), signature); err == nil {
			t.Fatal("expected verification to fail for wrong context")
		}
	}
}

// TestPEMCodec tests PEM encoding/decoding.
func TestPEMCodec(t *testing.T) {
	secret := GenerateKey()

	secretPEM := secret.MarshalPEM()
	parsedSecret, err := ParseSecretKeyPEM(secretPEM)
	if err != nil {
		t.Fatalf("failed to parse secret key PEM: %v", err)
	}
	if parsedSecret.Marshal() != secret.Marshal() {
		t.Fatal("parsed secret key does not match original")
	}

	public := secret.PublicKey()
	publicPEM := public.MarshalPEM()
	parsedPublic, err := ParsePublicKeyPEM(publicPEM)
	if err != nil {
		t.Fatalf("failed to parse public key PEM: %v", err)
	}
	if parsedPublic.Marshal() != public.Marshal() {
		t.Fatal("parsed public key does not match original")
	}
}

// TestFingerprint tests that fingerprints are consistent.
func TestFingerprint(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	if secret.Fingerprint() != public.Fingerprint() {
		t.Fatal("secret and public key fingerprints do not match")
	}
}
