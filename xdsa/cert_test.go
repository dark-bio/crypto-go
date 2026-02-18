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
	pemCert, err := IssueCertPEM(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Alice"},
		Issuer:    pkix.Name{CommonName: "Bobby"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleLeaf(),
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	parsed, err := VerifyCertPEM(pemCert, bobbyPublic, x509.ValidityNow())
	if err != nil {
		t.Fatalf("VerifyCertPEM failed: %v", err)
	}
	if parsed.PublicKey.Marshal() != alicePublic.Marshal() {
		t.Error("parsed public key does not match original")
	}
	if !parsed.Certificate.NotBefore.Equal(start) {
		t.Errorf("parsed notBefore %v does not match %v", parsed.Certificate.NotBefore, start)
	}
	if !parsed.Certificate.NotAfter.Equal(until) {
		t.Errorf("parsed notAfter %v does not match %v", parsed.Certificate.NotAfter, until)
	}
	// Test DER roundtrip (CA cert with path_len=0)
	pathLen := uint8(0)
	derCert, err := IssueCertDER(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Alice"},
		Issuer:    pkix.Name{CommonName: "Bobby"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleAuthority(&pathLen),
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	parsed, err = VerifyCertDER(derCert, bobbyPublic, x509.ValidityNow())
	if err != nil {
		t.Fatalf("VerifyCertDER failed: %v", err)
	}
	if parsed.PublicKey.Marshal() != alicePublic.Marshal() {
		t.Error("parsed public key does not match original")
	}
	if !parsed.Certificate.NotBefore.Equal(start) {
		t.Errorf("parsed notBefore %v does not match %v", parsed.Certificate.NotBefore, start)
	}
	if !parsed.Certificate.NotAfter.Equal(until) {
		t.Errorf("parsed notAfter %v does not match %v", parsed.Certificate.NotAfter, until)
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
	pemCert, err := IssueCertPEM(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Alice"},
		Issuer:    pkix.Name{CommonName: "Bobby"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleLeaf(),
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	if _, err = VerifyCertPEM(pemCert, wrongSecret.PublicKey(), x509.ValidityDisabled()); err == nil {
		t.Error("expected verification to fail with wrong signer")
	}
}

// TestCertValidityCheck tests that time-based validity checking works.
func TestCertValidityCheck(t *testing.T) {
	aliceSecret := GenerateKey()
	bobbySecret := GenerateKey()
	alicePublic := aliceSecret.PublicKey()
	bobbyPublic := bobbySecret.PublicKey()

	start := time.Now().Truncate(time.Second)
	until := start.Add(time.Hour)

	derCert, err := IssueCertDER(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Alice"},
		Issuer:    pkix.Name{CommonName: "Bobby"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleLeaf(),
	})
	if err != nil {
		t.Fatalf("signing certificate failed: %v", err)
	}
	// Should succeed with current time (within validity window)
	if _, err = VerifyCertDER(derCert, bobbyPublic, x509.ValidityNow()); err != nil {
		t.Fatalf("ValidityNow should succeed: %v", err)
	}
	// Should succeed with disabled time check
	if _, err = VerifyCertDER(derCert, bobbyPublic, x509.ValidityDisabled()); err != nil {
		t.Fatalf("ValidityDisabled should succeed: %v", err)
	}
	// Should fail with a time before the validity window
	if _, err = VerifyCertDER(derCert, bobbyPublic, x509.ValidityAt(start.Add(-time.Hour))); err == nil {
		t.Error("expected verification to fail with time before validity window")
	}
	// Should fail with a time after the validity window
	if _, err = VerifyCertDER(derCert, bobbyPublic, x509.ValidityAt(until.Add(time.Hour))); err == nil {
		t.Error("expected verification to fail with time after validity window")
	}
}

// TestCertChainVerification tests the WithIssuerCert chain verification.
func TestCertChainVerification(t *testing.T) {
	rootSecret := GenerateKey()
	childSecret := GenerateKey()
	rootPublic := rootSecret.PublicKey()

	start := time.Now().Truncate(time.Second)
	until := start.Add(time.Hour)

	// Issue a CA certificate (self-signed for test)
	pathLen := uint8(0)
	rootDER, err := IssueCertDER(rootPublic, rootSecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Root"},
		Issuer:    pkix.Name{CommonName: "Root"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleAuthority(&pathLen),
	})
	if err != nil {
		t.Fatalf("issuing root cert failed: %v", err)
	}
	rootCert, err := VerifyCertDER(rootDER, rootPublic, x509.ValidityNow())
	if err != nil {
		t.Fatalf("verifying root cert failed: %v", err)
	}
	// Issue a child leaf cert signed by root
	childDER, err := IssueCertDER(childSecret.PublicKey(), rootSecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Child"},
		Issuer:    pkix.Name{CommonName: "Root"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleLeaf(),
	})
	if err != nil {
		t.Fatalf("issuing child cert failed: %v", err)
	}
	// Should succeed with correct issuer cert
	if _, err = VerifyCertDERWithIssuer(childDER, rootCert, x509.ValidityNow()); err != nil {
		t.Fatalf("chain verification should succeed: %v", err)
	}
}

// TestCertTemplateValidation tests that invalid templates are rejected.
func TestCertTemplateValidation(t *testing.T) {
	aliceSecret := GenerateKey()
	bobbySecret := GenerateKey()
	alicePublic := aliceSecret.PublicKey()

	start := time.Now().Truncate(time.Second)
	until := start.Add(time.Hour)

	// Empty subject
	if _, err := IssueCertDER(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{},
		Issuer:    pkix.Name{CommonName: "Bobby"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleLeaf(),
	}); err == nil {
		t.Error("expected error for empty subject")
	}
	// Empty issuer
	if _, err := IssueCertDER(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Alice"},
		Issuer:    pkix.Name{},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleLeaf(),
	}); err == nil {
		t.Error("expected error for empty issuer")
	}
	// Invalid validity window (not_before >= not_after)
	if _, err := IssueCertDER(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Alice"},
		Issuer:    pkix.Name{CommonName: "Bobby"},
		NotBefore: until,
		NotAfter:  start,
		Role:      x509.RoleLeaf(),
	}); err == nil {
		t.Error("expected error for invalid validity window")
	}
}
