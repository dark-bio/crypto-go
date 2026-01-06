// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke

import (
	stdx509 "crypto/x509"
	"encoding/asn1"
	"errors"

	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/internal/x509ext"
	"github.com/dark-bio/crypto-go/pem"
	"github.com/dark-bio/crypto-go/x509"
	"github.com/dark-bio/crypto-go/xdsa"
)

// xdsaSigner wraps xdsa.SecretKey to implement x509.Signer.
type xdsaSigner struct {
	key *xdsa.SecretKey
}

func (s *xdsaSigner) Sign(message []byte) []byte {
	sig := s.key.Sign(message)
	return sig[:]
}

func (s *xdsaSigner) SignatureOID() asn1.ObjectIdentifier {
	return xdsa.OID
}

func (s *xdsaSigner) IssuerPublicKeyBytes() []byte {
	pk := s.key.PublicKey().Marshal()
	return pk[:]
}

// Bytes returns the raw public key bytes for embedding in certificates.
func (k *PublicKey) Bytes() []byte {
	b := k.Marshal()
	return b[:]
}

// AlgorithmOID returns the OID for X-Wing.
func (k *PublicKey) AlgorithmOID() asn1.ObjectIdentifier {
	return OID
}

// MarshalCertDER generates a DER-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
//
// Note: HPKE certificates are always end-entity certificates. The IsCA
// and PathLen fields in params are ignored and set to false/nil.
func (k *PublicKey) MarshalCertDER(signer *xdsa.SecretKey, params *x509.Params) []byte {
	// Force end-entity parameters
	eeParams := &x509.Params{
		SubjectName: params.SubjectName,
		IssuerName:  params.IssuerName,
		NotBefore:   params.NotBefore,
		NotAfter:    params.NotAfter,
		IsCA:        false,
		PathLen:     nil,
	}
	return x509ext.New(k, &xdsaSigner{signer}, eeParams)
}

// MarshalCertPEM generates a PEM-encoded X.509 certificate for this public key,
// signed by an xDSA issuer.
//
// Note: HPKE certificates are always end-entity certificates. The IsCA
// and PathLen fields in params are ignored and set to false/nil.
func (k *PublicKey) MarshalCertPEM(signer *xdsa.SecretKey, params *x509.Params) string {
	return string(pem.Encode("CERTIFICATE", k.MarshalCertDER(signer, params)))
}

// ParseCertDER parses a public key from a DER-encoded X.509 certificate,
// verifying the signature against the provided xDSA signer's public key.
// Returns the public key and validity period.
func ParseCertDER(der []byte, signer *xdsa.PublicKey) (*PublicKey, uint64, uint64, error) {
	// Parse the certificate
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil, 0, 0, errors.New("xhpke: " + err.Error())
	}
	// Validate the content against the provided signer (composite signature)
	if len(cert.Signature) != xdsa.SignatureSize {
		return nil, 0, 0, errors.New("xhpke: invalid signature length")
	}
	var sig [xdsa.SignatureSize]byte
	copy(sig[:], cert.Signature)

	if err := signer.Verify(cert.RawTBSCertificate, sig); err != nil {
		return nil, 0, 0, err
	}
	// Extract the embedded public key
	spki, err := asn1ext.ParseSubjectPublicKeyInfo(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, 0, 0, errors.New("xhpke: " + err.Error())
	}
	if spki.SubjectPublicKey.BitLength%8 != 0 {
		return nil, 0, 0, errors.New("xhpke: invalid public key bit string")
	}
	if len(spki.SubjectPublicKey.Bytes) != PublicKeySize {
		return nil, 0, 0, errors.New("xhpke: invalid public key length in certificate")
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
func MustParseCertDER(der []byte, signer *xdsa.PublicKey) (*PublicKey, uint64, uint64) {
	key, start, until, err := ParseCertDER(der, signer)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return key, start, until
}

// ParseCertPEM parses a public key from a PEM-encoded X.509 certificate,
// verifying the signature against the provided xDSA signer's public key.
// Returns the public key and validity period.
func ParseCertPEM(s string, signer *xdsa.PublicKey) (*PublicKey, uint64, uint64, error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, 0, 0, err
	}
	if kind != "CERTIFICATE" {
		return nil, 0, 0, errors.New("xhpke: invalid PEM type: " + kind)
	}
	return ParseCertDER(blob, signer)
}

// MustParseCertPEM parses a public key from a PEM-encoded X.509 certificate.
// It panics if the parsing or verification fails.
func MustParseCertPEM(s string, signer *xdsa.PublicKey) (*PublicKey, uint64, uint64) {
	key, start, until, err := ParseCertPEM(s, signer)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return key, start, until
}
