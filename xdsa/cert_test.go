// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xdsa

import (
	"testing"
	"time"

	"github.com/dark-bio/crypto-go/x509"
)

// TestCertParse tests that certificates can be created and then parsed and verified.
func TestCertParse(t *testing.T) {
	// Create the keys for Alice (subject) and Bobby (issuer)
	aliceSecret := GenerateKey()
	bobbySecret := GenerateKey()
	alicePublic := aliceSecret.PublicKey()
	bobbyPublic := bobbySecret.PublicKey()

	// Create a certificate for Alice, signed by Bobby
	start := uint64(time.Now().Unix())
	until := start + 3600

	// Test PEM roundtrip (end-entity cert)
	pemCert := alicePublic.MarshalCertPEM(bobbySecret, &x509.Params{
		SubjectName: "Alice",
		IssuerName:  "Bobby",
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        false,
		PathLen:     nil,
	})

	parsedKey, parsedStart, parsedUntil, err := ParseCertPEM(pemCert, bobbyPublic)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}
	if parsedKey.Marshal() != alicePublic.Marshal() {
		t.Error("parsed public key does not match original")
	}
	if parsedStart != start {
		t.Errorf("parsed notBefore %d does not match %d", parsedStart, start)
	}
	if parsedUntil != until {
		t.Errorf("parsed notAfter %d does not match %d", parsedUntil, until)
	}

	// Test DER roundtrip (CA cert with path_len=0)
	pathLen := uint8(0)
	derCert := alicePublic.MarshalCertDER(bobbySecret, &x509.Params{
		SubjectName: "Alice",
		IssuerName:  "Bobby",
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        true,
		PathLen:     &pathLen,
	})

	parsedKey, parsedStart, parsedUntil, err = ParseCertDER(derCert, bobbyPublic)
	if err != nil {
		t.Fatalf("ParseCertDER failed: %v", err)
	}
	if parsedKey.Marshal() != alicePublic.Marshal() {
		t.Error("parsed public key does not match original")
	}
	if parsedStart != start {
		t.Errorf("parsed notBefore %d does not match %d", parsedStart, start)
	}
	if parsedUntil != until {
		t.Errorf("parsed notAfter %d does not match %d", parsedUntil, until)
	}
}

// TestCertInvalidSigner tests that certificates signed by one key cannot be
// verified by another.
func TestCertInvalidSigner(t *testing.T) {
	// Create the keys for Alice (subject), Bobby (issuer) and Wrong (3rd party)
	aliceSecret := GenerateKey()
	bobbySecret := GenerateKey()
	wrongSecret := GenerateKey()

	alicePublic := aliceSecret.PublicKey()

	// Create a certificate for Alice, signed by Bobby
	start := uint64(time.Now().Unix())
	until := start + 3600

	// Sign a new certificate and verify with the wrong signer
	pemCert := alicePublic.MarshalCertPEM(bobbySecret, &x509.Params{
		SubjectName: "Alice",
		IssuerName:  "Bobby",
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        false,
		PathLen:     nil,
	})

	_, _, _, err := ParseCertPEM(pemCert, wrongSecret.PublicKey())
	if err == nil {
		t.Error("expected verification to fail with wrong signer")
	}
}

// TestCertSelfSigned tests self-signed certificate creation and verification.
func TestCertSelfSigned(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	start := uint64(time.Now().Unix())
	until := start + 3600

	pathLen := uint8(1)
	derCert := public.MarshalCertDER(secret, &x509.Params{
		SubjectName: "Self",
		IssuerName:  "Self",
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        true,
		PathLen:     &pathLen,
	})

	parsedKey, _, _, err := ParseCertDER(derCert, public)
	if err != nil {
		t.Fatalf("ParseCertDER failed for self-signed cert: %v", err)
	}
	if parsedKey.Marshal() != public.Marshal() {
		t.Error("parsed public key does not match original")
	}
}
