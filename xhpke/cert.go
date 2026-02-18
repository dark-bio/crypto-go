// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xhpke

import (
	stdx509 "crypto/x509"
	"errors"

	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/internal/x509ext"
	"github.com/dark-bio/crypto-go/pem"
	"github.com/dark-bio/crypto-go/x509"
	"github.com/dark-bio/crypto-go/xdsa"
)

// xdsaSigner implements x509ext.Signer through an XDSA secret key.
type xdsaSigner struct {
	signer xdsa.Signer
}

// Sign signs the message and returns the signature.
func (s *xdsaSigner) Sign(message []byte) (*[xdsa.SignatureSize]byte, error) {
	sig, err := s.signer.Sign(message)
	if err != nil {
		return nil, err
	}
	return (*[xdsa.SignatureSize]byte)(sig), nil
}

// PublicKey returns the issuer's public key.
func (s *xdsaSigner) PublicKey() *[xdsa.PublicKeySize]byte {
	pub := s.signer.PublicKey().Marshal()
	return &pub
}

// IssueCertDER generates a DER-encoded X.509 certificate for the subject public
// key, signed by an xDSA issuer.
//
// xHPKE certificates are always end-entity certificates. If the template asks
// for a CA role, ErrMustBeLeaf is returned.
func IssueCertDER(subject *PublicKey, issuer xdsa.Signer, template *x509.Template) ([]byte, error) {
	if template.Role.IsCA() {
		return nil, x509.ErrMustBeLeaf
	}
	return x509ext.New[[PublicKeySize]byte](subject, &xdsaSigner{issuer}, template)
}

// IssueCertPEM generates a PEM-encoded X.509 certificate for the subject public
// key, signed by an xDSA issuer.
//
// xHPKE certificates are always end-entity certificates. If the template asks
// for a CA role, ErrMustBeLeaf is returned.
func IssueCertPEM(subject *PublicKey, issuer xdsa.Signer, template *x509.Template) (string, error) {
	der, err := IssueCertDER(subject, issuer, template)
	if err != nil {
		return "", err
	}
	return string(pem.Encode("CERTIFICATE", der)), nil
}

// VerifyCertDER parses and verifies a DER-encoded X.509 certificate against the
// xDSA issuer's public key, checking signature validity and optionally time
// validity.
func VerifyCertDER(der []byte, issuer *xdsa.PublicKey, validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
	// Parse the certificate
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("xhpke: " + err.Error())
	}
	// Validate the content against the provided signer
	if len(cert.Signature) != xdsa.SignatureSize {
		return nil, errors.New("xhpke: invalid signature length")
	}
	var sig xdsa.Signature
	copy(sig[:], cert.Signature)

	if err := issuer.Verify(cert.RawTBSCertificate, &sig); err != nil {
		return nil, err
	}
	// Check time validity if requested
	if t, ok := validity.Timestamp(); ok {
		if t.Before(cert.NotBefore) || t.After(cert.NotAfter) {
			return nil, x509.ErrExpiredCertificate
		}
	}
	// Enforce key usage profile (check required bits are set)
	if cert.KeyUsage&stdx509.KeyUsageKeyAgreement == 0 {
		return nil, x509.ErrInvalidKeyUsage
	}
	if cert.IsCA {
		return nil, x509.ErrMustBeLeaf
	}
	// Extract the embedded public key
	spki, err := asn1ext.ParseSubjectPublicKeyInfo(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, errors.New("xhpke: " + err.Error())
	}
	if spki.SubjectPublicKey.BitLength%8 != 0 {
		return nil, errors.New("xhpke: invalid public key bit string")
	}
	if len(spki.SubjectPublicKey.Bytes) != PublicKeySize {
		return nil, errors.New("xhpke: invalid public key length in certificate")
	}
	var blob [PublicKeySize]byte
	copy(blob[:], spki.SubjectPublicKey.Bytes)

	key, err := ParsePublicKey(blob)
	if err != nil {
		return nil, err
	}
	return &x509.Verified[*PublicKey]{
		PublicKey:   key,
		Certificate: cert,
	}, nil
}

// VerifyCertPEM parses and verifies a PEM-encoded X.509 certificate against the
// xDSA issuer's public key.
func VerifyCertPEM(s string, issuer *xdsa.PublicKey, validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	if kind != "CERTIFICATE" {
		return nil, errors.New("xhpke: invalid PEM type: " + kind)
	}
	return VerifyCertDER(blob, issuer, validity)
}

// VerifyCertDERWithIssuer parses and verifies a DER-encoded X.509 certificate
// using a previously verified xDSA issuer certificate. In addition to signature
// and time checks, it enforces CA role, key usage, path length, and DN chaining
// constraints on the issuer.
func VerifyCertDERWithIssuer(der []byte, issuerCert *x509.Verified[*xdsa.PublicKey], validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
	cert, err := VerifyCertDER(der, issuerCert.PublicKey, validity)
	if err != nil {
		return nil, err
	}
	if err := enforceIssuerChaining(cert.Certificate, issuerCert.Certificate); err != nil {
		return nil, err
	}
	return cert, nil
}

// VerifyCertPEMWithIssuer parses and verifies a PEM-encoded X.509 certificate
// using a previously verified xDSA issuer certificate. In addition to signature
// and time checks, it enforces CA role, key usage, path length, and DN chaining
// constraints on the issuer.
func VerifyCertPEMWithIssuer(s string, issuerCert *x509.Verified[*xdsa.PublicKey], validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
	cert, err := VerifyCertPEM(s, issuerCert.PublicKey, validity)
	if err != nil {
		return nil, err
	}
	if err := enforceIssuerChaining(cert.Certificate, issuerCert.Certificate); err != nil {
		return nil, err
	}
	return cert, nil
}

// MustVerifyCertDER is like VerifyCertDER but panics on error.
func MustVerifyCertDER(der []byte, issuer *xdsa.PublicKey, validity x509.ValidityCheck) *x509.Verified[*PublicKey] {
	cert, err := VerifyCertDER(der, issuer, validity)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return cert
}

// MustVerifyCertPEM is like VerifyCertPEM but panics on error.
func MustVerifyCertPEM(s string, issuer *xdsa.PublicKey, validity x509.ValidityCheck) *x509.Verified[*PublicKey] {
	cert, err := VerifyCertPEM(s, issuer, validity)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return cert
}

// enforceIssuerChaining validates that the issuer certificate is authorized to
// sign the child certificate (CA role, key usage, DN chaining).
func enforceIssuerChaining(child *stdx509.Certificate, issuer *stdx509.Certificate) error {
	// Issuer must be a CA
	if !issuer.IsCA {
		return x509.ErrIssuerNotCA
	}
	// Issuer must have keyCertSign|cRLSign set
	if issuer.KeyUsage&(stdx509.KeyUsageCertSign|stdx509.KeyUsageCRLSign) != stdx509.KeyUsageCertSign|stdx509.KeyUsageCRLSign {
		return x509.ErrIssuerKeyUsage
	}
	// Child's issuer DN must match issuer's subject DN
	if child.Issuer.String() != issuer.Subject.String() {
		return x509.ErrIssuerDNMismatch
	}
	return nil
}
