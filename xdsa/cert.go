// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xdsa

import (
	"encoding/asn1"
	"errors"

	"github.com/dark-bio/crypto-go/pem"
	"github.com/dark-bio/crypto-go/x509"
)

// secretKeySigner wraps SecretKey to implement x509.Signer.
type secretKeySigner struct {
	key *SecretKey
}

func (s *secretKeySigner) Sign(message []byte) []byte {
	sig := s.key.Sign(message)
	return sig[:]
}

func (s *secretKeySigner) SignatureOID() asn1.ObjectIdentifier {
	return OID
}

func (s *secretKeySigner) IssuerPublicKeyBytes() []byte {
	pk := s.key.PublicKey().Marshal()
	return pk[:]
}

// Bytes returns the raw public key bytes for embedding in certificates.
func (k *PublicKey) Bytes() []byte {
	b := k.Marshal()
	return b[:]
}

// AlgorithmOID returns the OID for xDSA (MLDSA65-Ed25519-SHA512).
func (k *PublicKey) AlgorithmOID() asn1.ObjectIdentifier {
	return OID
}

// MarshalCertDER generates a DER-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
func (k *PublicKey) MarshalCertDER(signer *SecretKey, params *x509.Params) []byte {
	return x509.New(k, &secretKeySigner{signer}, params)
}

// MarshalCertPEM generates a PEM-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
func (k *PublicKey) MarshalCertPEM(signer *SecretKey, params *x509.Params) string {
	return string(pem.Encode("CERTIFICATE", k.MarshalCertDER(signer, params)))
}

// ParseCertDER parses a public key from a DER-encoded X.509 certificate,
// verifying the signature against the provided signer's public key.
// Returns the public key and validity period (notBefore, notAfter).
func ParseCertDER(der []byte, signer *PublicKey) (*PublicKey, uint64, uint64, error) {
	cert, err := x509.Parse(der)
	if err != nil {
		return nil, 0, 0, err
	}

	// Verify the signature
	if len(cert.Signature) != SignatureSize {
		return nil, 0, 0, errors.New("xdsa: invalid signature length")
	}
	var sig [SignatureSize]byte
	copy(sig[:], cert.Signature)

	if err := signer.Verify(cert.TBSRaw, sig); err != nil {
		return nil, 0, 0, err
	}

	// Extract the public key
	if len(cert.PublicKey) != PublicKeySize {
		return nil, 0, 0, errors.New("xdsa: invalid public key length in certificate")
	}
	var pkBytes [PublicKeySize]byte
	copy(pkBytes[:], cert.PublicKey)

	pk, err := ParsePublicKey(pkBytes)
	if err != nil {
		return nil, 0, 0, err
	}

	return pk, cert.NotBefore, cert.NotAfter, nil
}

// MustParseCertDER parses a public key from a DER-encoded X.509 certificate.
// It panics if the parsing or verification fails.
func MustParseCertDER(der []byte, signer *PublicKey) (*PublicKey, uint64, uint64) {
	pk, notBefore, notAfter, err := ParseCertDER(der, signer)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return pk, notBefore, notAfter
}

// ParseCertPEM parses a public key from a PEM-encoded X.509 certificate,
// verifying the signature against the provided signer's public key.
// Returns the public key and validity period (notBefore, notAfter).
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
	pk, notBefore, notAfter, err := ParseCertPEM(s, signer)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return pk, notBefore, notAfter
}
