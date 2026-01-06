// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke

import (
	"encoding/asn1"
	"errors"

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
	return x509.New(k, &xdsaSigner{signer}, eeParams)
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
// Returns the public key and validity period (notBefore, notAfter).
func ParseCertDER(der []byte, signer *xdsa.PublicKey) (*PublicKey, uint64, uint64, error) {
	cert, err := x509.Parse(der)
	if err != nil {
		return nil, 0, 0, err
	}

	// Verify the signature with xDSA
	if len(cert.Signature) != xdsa.SignatureSize {
		return nil, 0, 0, errors.New("xhpke: invalid signature length")
	}
	var sig [xdsa.SignatureSize]byte
	copy(sig[:], cert.Signature)

	if err := signer.Verify(cert.TBSRaw, sig); err != nil {
		return nil, 0, 0, err
	}

	// Extract the public key
	if len(cert.PublicKey) != PublicKeySize {
		return nil, 0, 0, errors.New("xhpke: invalid public key length in certificate")
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
func MustParseCertDER(der []byte, signer *xdsa.PublicKey) (*PublicKey, uint64, uint64) {
	pk, notBefore, notAfter, err := ParseCertDER(der, signer)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return pk, notBefore, notAfter
}

// ParseCertPEM parses a public key from a PEM-encoded X.509 certificate,
// verifying the signature against the provided xDSA signer's public key.
// Returns the public key and validity period (notBefore, notAfter).
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
	pk, notBefore, notAfter, err := ParseCertPEM(s, signer)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return pk, notBefore, notAfter
}
