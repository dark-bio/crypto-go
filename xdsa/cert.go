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
	signer Signer
}

// Sign signs the message and returns the signature.
func (s *xdsaSigner) Sign(message []byte) (*[SignatureSize]byte, error) {
	sig, err := s.signer.Sign(message)
	if err != nil {
		return nil, err
	}
	return (*[SignatureSize]byte)(sig), nil
}

// PublicKey returns the issuer's public key.
func (s *xdsaSigner) PublicKey() *[PublicKeySize]byte {
	pub := s.signer.PublicKey().Marshal()
	return &pub
}

// MarshalCertDER generates a DER-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
func (k *PublicKey) MarshalCertDER(signer Signer, params *x509.Params) ([]byte, error) {
	return x509ext.New[[PublicKeySize]byte](k, &xdsaSigner{signer}, params)
}

// MarshalCertPEM generates a PEM-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
func (k *PublicKey) MarshalCertPEM(signer Signer, params *x509.Params) (string, error) {
	der, err := k.MarshalCertDER(signer, params)
	if err != nil {
		return "", err
	}
	return string(pem.Encode("CERTIFICATE", der)), nil
}

// ParseCertDER parses a public key from a DER-encoded X.509 certificate,
// verifying the signature against the provided signer's public key.
// Returns the public key and validity period.
func ParseCertDER(der []byte, signer *PublicKey) (*PublicKey, *stdx509.Certificate, error) {
	// Parse the certificate
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil, nil, errors.New("xdsa: " + err.Error())
	}
	// Validate the content against the provided signer (composite signature)
	if len(cert.Signature) != SignatureSize {
		return nil, nil, errors.New("xdsa: invalid signature length")
	}
	var sig Signature
	copy(sig[:], cert.Signature)

	if err := signer.Verify(cert.RawTBSCertificate, &sig); err != nil {
		return nil, nil, err
	}
	// Extract the embedded public key (ML-DSA-65 1952 bytes || Ed25519 32 bytes)
	spki, err := asn1ext.ParseSubjectPublicKeyInfo(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, nil, errors.New("xdsa: " + err.Error())
	}
	if spki.SubjectPublicKey.BitLength%8 != 0 {
		return nil, nil, errors.New("xdsa: invalid public key bit string")
	}
	if len(spki.SubjectPublicKey.Bytes) != PublicKeySize {
		return nil, nil, errors.New("xdsa: invalid public key length in certificate")
	}
	var blob [PublicKeySize]byte
	copy(blob[:], spki.SubjectPublicKey.Bytes)

	key, err := ParsePublicKey(blob)
	if err != nil {
		return nil, nil, err
	}
	// Extract the validity period
	return key, cert, nil
}

// MustParseCertDER parses a public key from a DER-encoded X.509 certificate.
// It panics if the parsing or verification fails.
func MustParseCertDER(der []byte, signer *PublicKey) (*PublicKey, *stdx509.Certificate) {
	key, cert, err := ParseCertDER(der, signer)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key, cert
}

// ParseCertPEM parses a public key from a PEM-encoded X.509 certificate,
// verifying the signature against the provided signer's public key.
// Returns the public key and validity period.
func ParseCertPEM(s string, signer *PublicKey) (*PublicKey, *stdx509.Certificate, error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, nil, err
	}
	if kind != "CERTIFICATE" {
		return nil, nil, errors.New("xdsa: invalid PEM type: " + kind)
	}
	return ParseCertDER(blob, signer)
}

// MustParseCertPEM parses a public key from a PEM-encoded X.509 certificate.
// It panics if the parsing or verification fails.
func MustParseCertPEM(s string, signer *PublicKey) (*PublicKey, *stdx509.Certificate) {
	key, cert, err := ParseCertPEM(s, signer)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key, cert
}
