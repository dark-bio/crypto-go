// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xdsa

import (
	stdx509 "crypto/x509"
	"errors"

	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/internal/x509ext"
	"github.com/dark-bio/crypto-go/pem"
	"github.com/dark-bio/crypto-go/x509"
)

// xdsaSigner implements x509.Signer through an XDSA secret key.
type xdsaSigner struct {
	key *SecretKey
}

// Sign signs the message and returns the signature.
func (s *xdsaSigner) Sign(message []byte) [SignatureSize]byte {
	return *s.key.Sign(message)
}

// PublicKey returns the issuer's public key.
func (s *xdsaSigner) PublicKey() [PublicKeySize]byte {
	return s.key.PublicKey().Marshal()
}

// MarshalCertDER generates a DER-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
func (k *PublicKey) MarshalCertDER(signer *SecretKey, params *x509.Params) []byte {
	return x509ext.New[[PublicKeySize]byte](k, &xdsaSigner{signer}, params)
}

// MarshalCertPEM generates a PEM-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
func (k *PublicKey) MarshalCertPEM(signer *SecretKey, params *x509.Params) string {
	return string(pem.Encode("CERTIFICATE", k.MarshalCertDER(signer, params)))
}

// ParseCertDER parses a public key from a DER-encoded X.509 certificate,
// verifying the signature against the provided signer's public key.
// Returns the public key and validity period.
func ParseCertDER(der []byte, signer *PublicKey) (*PublicKey, uint64, uint64, error) {
	// Parse the certificate
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil, 0, 0, errors.New("xdsa: " + err.Error())
	}
	// Validate the content against the provided signer (composite signature)
	if len(cert.Signature) != SignatureSize {
		return nil, 0, 0, errors.New("xdsa: invalid signature length")
	}
	var sig Signature
	copy(sig[:], cert.Signature)

	if err := signer.Verify(cert.RawTBSCertificate, &sig); err != nil {
		return nil, 0, 0, err
	}
	// Extract the embedded public key (ML-DSA-65 1952 bytes || Ed25519 32 bytes)
	spki, err := asn1ext.ParseSubjectPublicKeyInfo(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, 0, 0, errors.New("xdsa: " + err.Error())
	}
	if spki.SubjectPublicKey.BitLength%8 != 0 {
		return nil, 0, 0, errors.New("xdsa: invalid public key bit string")
	}
	if len(spki.SubjectPublicKey.Bytes) != PublicKeySize {
		return nil, 0, 0, errors.New("xdsa: invalid public key length in certificate")
	}
	var blob [PublicKeySize]byte
	copy(blob[:], spki.SubjectPublicKey.Bytes)

	key, err := ParsePublicKey(blob)
	if err != nil {
		return nil, 0, 0, err
	}
	// Extract the validity period
	return key, uint64(cert.NotBefore.Unix()), uint64(cert.NotAfter.Unix()), nil
}

// MustParseCertDER parses a public key from a DER-encoded X.509 certificate.
// It panics if the parsing or verification fails.
func MustParseCertDER(der []byte, signer *PublicKey) (*PublicKey, uint64, uint64) {
	key, start, until, err := ParseCertDER(der, signer)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key, start, until
}

// ParseCertPEM parses a public key from a PEM-encoded X.509 certificate,
// verifying the signature against the provided signer's public key.
// Returns the public key and validity period.
func ParseCertPEM(s string, signer *PublicKey) (*PublicKey, uint64, uint64, error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, 0, 0, err
	}
	if kind != "CERTIFICATE" {
		return nil, 0, 0, errors.New("xdsa: invalid PEM type: " + kind)
	}
	return ParseCertDER(blob, signer)
}

// MustParseCertPEM parses a public key from a PEM-encoded X.509 certificate.
// It panics if the parsing or verification fails.
func MustParseCertPEM(s string, signer *PublicKey) (*PublicKey, uint64, uint64) {
	key, start, until, err := ParseCertPEM(s, signer)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key, start, until
}
