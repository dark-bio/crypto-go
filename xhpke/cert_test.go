// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke

import (
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/dark-bio/crypto-go/x509"
	"github.com/dark-bio/crypto-go/xdsa"
)

// TestCertParse tests that certificates can be created and then parsed and verified.
func TestCertParse(t *testing.T) {
	// Create the keys for Alice (HPKE) and Bobby (xDSA signer)
	aliceSecret := GenerateKey()
	bobbySecret := xdsa.GenerateKey()
	alicePublic := aliceSecret.PublicKey()
	bobbyPublic := bobbySecret.PublicKey()

	// Create a certificate for Alice, signed by Bobby
	start := time.Now().Truncate(time.Second)
	until := start.Add(time.Hour)

	// Test PEM roundtrip
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
	if parsed.Certificate.KeyUsage != stdx509.KeyUsageKeyAgreement {
		t.Errorf("parsed keyUsage %v does not match %v", parsed.Certificate.KeyUsage, stdx509.KeyUsageKeyAgreement)
	}
	// Test DER roundtrip
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
	if parsed.Certificate.KeyUsage != stdx509.KeyUsageKeyAgreement {
		t.Errorf("parsed keyUsage %v does not match %v", parsed.Certificate.KeyUsage, stdx509.KeyUsageKeyAgreement)
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

// TestCertRejectsCA tests that issuing an xHPKE certificate with a CA role is rejected.
func TestCertRejectsCA(t *testing.T) {
	aliceSecret := GenerateKey()
	bobbySecret := xdsa.GenerateKey()
	alicePublic := aliceSecret.PublicKey()

	start := time.Now().Truncate(time.Second)
	until := start.Add(time.Hour)

	pathLen := uint8(0)
	_, err := IssueCertDER(alicePublic, bobbySecret, &x509.Template{
		Subject:   pkix.Name{CommonName: "Alice"},
		Issuer:    pkix.Name{CommonName: "Bobby"},
		NotBefore: start,
		NotAfter:  until,
		Role:      x509.RoleAuthority(&pathLen),
	})
	if err == nil {
		t.Error("expected error when issuing xHPKE certificate with CA role")
	}
}
