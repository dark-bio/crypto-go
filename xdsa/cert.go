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

// xdsaSigner implements x509ext.Signer through an XDSA secret key.
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

// IssueCertDER generates a DER-encoded X.509 certificate for the subject public
// key, signed by the issuer.
func IssueCertDER(subject *PublicKey, issuer Signer, template *x509.Template) ([]byte, error) {
	return x509ext.New[[PublicKeySize]byte](subject, &xdsaSigner{issuer}, template)
}

// IssueCertPEM generates a PEM-encoded X.509 certificate for the subject public
// key, signed by the issuer.
func IssueCertPEM(subject *PublicKey, issuer Signer, template *x509.Template) (string, error) {
	der, err := IssueCertDER(subject, issuer, template)
	if err != nil {
		return "", err
	}
	return string(pem.Encode("CERTIFICATE", der)), nil
}

// VerifyCertDER parses and verifies a DER-encoded X.509 certificate against the
// issuer's public key, checking signature validity and optionally time validity.
func VerifyCertDER(der []byte, issuer *PublicKey, validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
	// Parse the certificate
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("xdsa: " + err.Error())
	}
	// Validate the content against the provided signer
	if len(cert.Signature) != SignatureSize {
		return nil, errors.New("xdsa: invalid signature length")
	}
	var sig Signature
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
	// Enforce key usage profile based on certificate role (check required bits are set)
	if cert.IsCA {
		if cert.KeyUsage&(stdx509.KeyUsageCertSign|stdx509.KeyUsageCRLSign) != stdx509.KeyUsageCertSign|stdx509.KeyUsageCRLSign {
			return nil, x509.ErrInvalidKeyUsage
		}
	} else {
		if cert.KeyUsage&stdx509.KeyUsageDigitalSignature == 0 {
			return nil, x509.ErrInvalidKeyUsage
		}
	}
	// Extract the embedded public key
	spki, err := asn1ext.ParseSubjectPublicKeyInfo(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, errors.New("xdsa: " + err.Error())
	}
	if spki.SubjectPublicKey.BitLength%8 != 0 {
		return nil, errors.New("xdsa: invalid public key bit string")
	}
	if len(spki.SubjectPublicKey.Bytes) != PublicKeySize {
		return nil, errors.New("xdsa: invalid public key length in certificate")
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
// issuer's public key.
func VerifyCertPEM(s string, issuer *PublicKey, validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	if kind != "CERTIFICATE" {
		return nil, errors.New("xdsa: invalid PEM type: " + kind)
	}
	return VerifyCertDER(blob, issuer, validity)
}

// VerifyCertDERWithIssuer parses and verifies a DER-encoded X.509 certificate
// using a previously verified issuer certificate. In addition to signature and
// time checks, it enforces CA role, key usage, path length, and DN chaining
// constraints on the issuer.
func VerifyCertDERWithIssuer(der []byte, issuerCert *x509.Verified[*PublicKey], validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
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
// using a previously verified issuer certificate. In addition to signature and
// // time checks, it enforces CA role, key usage, path length, and DN chaining
// // constraints on the issuer.
func VerifyCertPEMWithIssuer(s string, issuerCert *x509.Verified[*PublicKey], validity x509.ValidityCheck) (*x509.Verified[*PublicKey], error) {
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
func MustVerifyCertDER(der []byte, issuer *PublicKey, validity x509.ValidityCheck) *x509.Verified[*PublicKey] {
	cert, err := VerifyCertDER(der, issuer, validity)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return cert
}

// MustVerifyCertPEM is like VerifyCertPEM but panics on error.
func MustVerifyCertPEM(s string, issuer *PublicKey, validity x509.ValidityCheck) *x509.Verified[*PublicKey] {
	cert, err := VerifyCertPEM(s, issuer, validity)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return cert
}

// enforceIssuerChaining validates that the issuer certificate is authorized to
// sign the child certificate (CA role, key usage, path length, DN chaining).
func enforceIssuerChaining(child *stdx509.Certificate, issuer *stdx509.Certificate) error {
	// Issuer must be a CA
	if !issuer.IsCA {
		return x509.ErrIssuerNotCA
	}
	// Issuer must have keyCertSign|cRLSign set
	if issuer.KeyUsage&(stdx509.KeyUsageCertSign|stdx509.KeyUsageCRLSign) != stdx509.KeyUsageCertSign|stdx509.KeyUsageCRLSign {
		return x509.ErrIssuerKeyUsage
	}
	// If issuer has pathLen constraint and child is also a CA, check depth
	if issuer.MaxPathLenZero || issuer.MaxPathLen > 0 {
		if child.IsCA && issuer.MaxPathLen == 0 && issuer.MaxPathLenZero {
			return x509.ErrIssuerPathLen
		}
	}
	// Child's issuer DN must match issuer's subject DN
	if child.Issuer.String() != issuer.Subject.String() {
		return x509.ErrIssuerDNMismatch
	}
	return nil
}
