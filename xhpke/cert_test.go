// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke

import (
	"testing"
	"time"

	"github.com/dark-bio/crypto-go/x509"
	"github.com/dark-bio/crypto-go/xdsa"
)

// Define some helpers to emulate remote signing with possible failures
type xdsaFailableSigner struct{ *xdsa.SecretKey }

func (s xdsaFailableSigner) Sign(msg []byte) (*xdsa.Signature, error) {
	return s.SecretKey.Sign(msg), nil
}

// TestCertParse tests that certificates can be created and then parsed and verified.
func TestCertParse(t *testing.T) {
	// Create the keys for Alice (HPKE) and Bobby (xDSA signer)
	aliceSecret := GenerateKey()
	bobbySecret := xdsa.GenerateKey()
	alicePublic := aliceSecret.PublicKey()
	bobbyPublic := bobbySecret.PublicKey()

	// Create a certificate for Alice, signed by Bobby
	start := uint64(time.Now().Unix())
	until := start + 3600

	// Test PEM roundtrip
	pemCert, err := alicePublic.MarshalCertPEM(xdsaFailableSigner{bobbySecret}, &x509.Params{
		SubjectName: "Alice",
		IssuerName:  "Bobby",
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        false,
		PathLen:     nil,
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
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

	// Test DER roundtrip
	derCert, err := alicePublic.MarshalCertDER(xdsaFailableSigner{bobbySecret}, &x509.Params{
		SubjectName: "Alice",
		IssuerName:  "Bobby",
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        false,
		PathLen:     nil,
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
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
	// Create the keys for Alice (HPKE), Bobby (issuer) and Wrong (3rd party)
	aliceSecret := GenerateKey()
	bobbySecret := xdsa.GenerateKey()
	wrongSecret := xdsa.GenerateKey()

	alicePublic := aliceSecret.PublicKey()

	// Create a certificate for Alice, signed by Bobby
	start := uint64(time.Now().Unix())
	until := start + 3600

	// Sign a new certificate and verify with the wrong signer
	pemCert, err := alicePublic.MarshalCertPEM(xdsaFailableSigner{bobbySecret}, &x509.Params{
		SubjectName: "Alice",
		IssuerName:  "Bobby",
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        false,
		PathLen:     nil,
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	if _, _, _, err = ParseCertPEM(pemCert, wrongSecret.PublicKey()); err == nil {
		t.Error("expected verification to fail with wrong signer")
	}
}
