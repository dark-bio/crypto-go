// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xdsa

import (
	"crypto/x509/pkix"
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
	start := time.Now().Truncate(time.Second)
	until := start.Add(time.Hour)

	// Test PEM roundtrip (end-entity cert)
	pemCert, err := alicePublic.MarshalCertPEM(bobbySecret, &x509.Params{
		SubjectName: pkix.Name{CommonName: "Alice"},
		IssuerName:  pkix.Name{CommonName: "Bobby"},
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        false,
		PathLen:     nil,
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	parsedKey, parsedCert, err := ParseCertPEM(pemCert, bobbyPublic)
	if err != nil {
		t.Fatalf("ParseCertPEM failed: %v", err)
	}
	if parsedKey.Marshal() != alicePublic.Marshal() {
		t.Error("parsed public key does not match original")
	}
	if !parsedCert.NotBefore.Equal(start) {
		t.Errorf("parsed notBefore %v does not match %v", parsedCert.NotBefore, start)
	}
	if !parsedCert.NotAfter.Equal(until) {
		t.Errorf("parsed notAfter %v does not match %v", parsedCert.NotAfter, until)
	}
	// Test DER roundtrip (CA cert with path_len=0)
	pathLen := uint8(0)
	derCert, err := alicePublic.MarshalCertDER(bobbySecret, &x509.Params{
		SubjectName: pkix.Name{CommonName: "Alice"},
		IssuerName:  pkix.Name{CommonName: "Bobby"},
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        true,
		PathLen:     &pathLen,
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	parsedKey, parsedCert, err = ParseCertDER(derCert, bobbyPublic)
	if err != nil {
		t.Fatalf("ParseCertDER failed: %v", err)
	}
	if parsedKey.Marshal() != alicePublic.Marshal() {
		t.Error("parsed public key does not match original")
	}
	if !parsedCert.NotBefore.Equal(start) {
		t.Errorf("parsed notBefore %v does not match %v", parsedCert.NotBefore, start)
	}
	if !parsedCert.NotAfter.Equal(until) {
		t.Errorf("parsed notAfter %v does not match %v", parsedCert.NotAfter, until)
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
	start := time.Now().Truncate(time.Second)
	until := start.Add(time.Hour)

	// Sign a new certificate and verify with the wrong signer
	pemCert, err := alicePublic.MarshalCertPEM(bobbySecret, &x509.Params{
		SubjectName: pkix.Name{CommonName: "Alice"},
		IssuerName:  pkix.Name{CommonName: "Bobby"},
		NotBefore:   start,
		NotAfter:    until,
		IsCA:        false,
		PathLen:     nil,
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	if _, _, err = ParseCertPEM(pemCert, wrongSecret.PublicKey()); err == nil {
		t.Error("expected verification to fail with wrong signer")
	}
}
