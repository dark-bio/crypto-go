// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509ext provides X.509 certificate creation for xDSA and xHPKE keys.
//
// https://datatracker.ietf.org/doc/html/rfc5280
package x509ext

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"time"
	"unsafe"

	cryptox509 "github.com/dark-bio/crypto-go/x509"
)

// XDSAOrXHPKEPublicKey defines the supported public key sizes. This allows us
// to reuse the same generic certificate creation logic for both xDSA (1984-byte)
// and xHPKE/X-Wing (1216-byte) public keys.
type XDSAOrXHPKEPublicKey interface {
	~[1984]byte | ~[1216]byte
}

var (
	// oidXDSA is the ASN.1 object identifier for MLDSA65-Ed25519-SHA512.
	oidXDSA = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 48}

	// oidXWing is the ASN.1 object identifier for X-Wing.
	oidXWing = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722}
)

// Subject is an interface for types that can be embedded into X.509 certificates
// as the subject's public key.
type Subject[T XDSAOrXHPKEPublicKey] interface {
	// Marshal returns the raw public key bytes to embed in the certificate.
	Marshal() T
}

// Signer is an interface for types that can sign X.509 certificates.
type Signer interface {
	// Sign signs the message and returns the signature.
	Sign(message []byte) (*[3373]byte, error)

	// PublicKey returns the issuer's public key.
	PublicKey() *[1984]byte
}

// tbsCertificate is the ASN.1 structure for the TBS (to-be-signed) certificate.
type tbsCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKeyInfo      subjectPublicKeyInfo
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

// validity is the ASN.1 structure for certificate validity period.
type validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// subjectPublicKeyInfo is the ASN.1 structure for SPKI.
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// certificate is the ASN.1 structure for a complete X.509 certificate.
type certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// New creates an X.509 certificate for a subject, signed by the given signer.
func New[T XDSAOrXHPKEPublicKey](subject Subject[T], signer Signer, template *cryptox509.Template) ([]byte, error) {
	// Validate the template fields
	if err := validateTemplate(template); err != nil {
		return nil, err
	}
	// Generate a random serial number
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		panic("x509: " + err.Error())
	}
	serialBytes[0] &= 0x7F // Ensure positive (MSB = 0)
	serial := new(big.Int).SetBytes(serialBytes)

	// Create the signature algorithm identifier (always xDSA)
	sigAlg := pkix.AlgorithmIdentifier{
		Algorithm: oidXDSA,
	}
	// Build subject and issuer names using pkix.Name
	issuerRDN, err := asn1.Marshal(template.Issuer.ToRDNSequence())
	if err != nil {
		panic("x509: " + err.Error())
	}
	subjectRDN, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		panic("x509: " + err.Error())
	}
	issuerName := asn1.RawValue{FullBytes: issuerRDN}
	subjectName := asn1.RawValue{FullBytes: subjectRDN}

	// Build the subject public key info
	subjectArray := subject.Marshal()
	subjectBytes := unsafe.Slice((*byte)(unsafe.Pointer(&subjectArray)), unsafe.Sizeof(subjectArray))

	var subjectOID asn1.ObjectIdentifier
	switch unsafe.Sizeof(subjectArray) {
	case 1984:
		subjectOID = oidXDSA
	case 1216:
		subjectOID = oidXWing
	}
	spki := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: subjectOID,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     subjectBytes,
			BitLength: len(subjectBytes) * 8,
		},
	}
	// Build extensions for the key identities and constraints
	pk := signer.PublicKey()

	isCA := template.Role.IsCA()
	var pathLen *uint8
	if v, ok := template.Role.PathLen(); ok {
		pathLen = &v
	}
	extensions := []pkix.Extension{
		makeBasicConstraintsExt(isCA, pathLen),
		makeKeyUsageExt(isCA, subjectOID),
		makeSKIExt(subjectBytes),
		makeAKIExt(pk[:]),
	}
	// Track extension OIDs for duplicate checking with custom extensions
	extensionOIDs := map[string]bool{
		"2.5.29.19": true, // basicConstraints
		"2.5.29.15": true, // keyUsage
		"2.5.29.14": true, // subjectKeyIdentifier
		"2.5.29.35": true, // authorityKeyIdentifier
	}
	// Inject custom extensions
	for _, ext := range template.Extensions {
		oid := ext.OID.String()
		if strings.HasPrefix(oid, "2.5.29.") {
			return nil, cryptox509.ErrReservedExtensionOID
		}
		if extensionOIDs[oid] {
			return nil, cryptox509.ErrDuplicateExtensionOID
		}
		extensionOIDs[oid] = true

		extensions = append(extensions, pkix.Extension{
			Id:       ext.OID,
			Critical: ext.Critical,
			Value:    ext.Value,
		})
	}
	// Build the TBS certificate
	tbs := tbsCertificate{
		Version:            2, // v3
		SerialNumber:       serial,
		SignatureAlgorithm: sigAlg,
		Issuer:             issuerName,
		Validity: validity{
			NotBefore: template.NotBefore.UTC(),
			NotAfter:  template.NotAfter.UTC(),
		},
		Subject:       subjectName,
		PublicKeyInfo: spki,
		Extensions:    extensions,
	}
	// Encode and sign the TBS certificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		panic("x509: " + err.Error())
	}
	sig, err := signer.Sign(tbsDER)
	if err != nil {
		return nil, err
	}
	// Create the final certificate
	cert := certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: sigAlg,
		SignatureValue: asn1.BitString{
			Bytes:     sig[:],
			BitLength: len(sig) * 8,
		},
	}
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		panic("x509: " + err.Error())
	}
	return certDER, nil
}

// validateTemplate checks the template fields for obvious errors.
func validateTemplate(t *cryptox509.Template) error {
	if len(t.Subject.Names) == 0 && len(t.Subject.ExtraNames) == 0 && t.Subject.CommonName == "" {
		return cryptox509.ErrEmptySubject
	}
	if len(t.Issuer.Names) == 0 && len(t.Issuer.ExtraNames) == 0 && t.Issuer.CommonName == "" {
		return cryptox509.ErrEmptyIssuer
	}
	if !t.NotBefore.Before(t.NotAfter) {
		return cryptox509.ErrInvalidValidity
	}
	return nil
}

// makeSKIExt creates a SubjectKeyIdentifier extension.
func makeSKIExt(publicKey []byte) pkix.Extension {
	// Create the SHA1 hash of the subject public key
	hash := sha1.Sum(publicKey)

	// Encode as OCTET STRING
	value, _ := asn1.Marshal(hash[:])

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 14}, // id-ce-subjectKeyIdentifier
		Critical: false,
		Value:    value,
	}
}

// makeAKIExt creates an AuthorityKeyIdentifier extension.
func makeAKIExt(publicKey []byte) pkix.Extension {
	// Create the SHA1 hash of the issuer public key
	hash := sha1.Sum(publicKey)

	// AuthorityKeyIdentifier ::= SEQUENCE {
	//   keyIdentifier [0] IMPLICIT KeyIdentifier OPTIONAL
	// }
	// KeyIdentifier ::= OCTET STRING
	keyID := asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   0,
		Bytes: hash[:],
	}
	keyIDBytes, _ := asn1.Marshal(keyID)

	// Wrap in SEQUENCE
	seq := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      keyIDBytes,
	}
	value, _ := asn1.Marshal(seq)

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 35}, // id-ce-authorityKeyIdentifier
		Critical: false,
		Value:    value,
	}
}

// basicConstraints is the ASN.1 structure for BasicConstraints extension.
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// makeBasicConstraintsExt creates a BasicConstraints extension.
//
// For CA certificates, set `is_ca=true`. The `path_len` constrains how many
// intermediate CAs can follow (e.g., 0 means can only sign end-entity certs).
func makeBasicConstraintsExt(isCA bool, pathLen *uint8) pkix.Extension {
	// BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
	bc := basicConstraints{IsCA: isCA, MaxPathLen: -1}
	if pathLen != nil {
		bc.MaxPathLen = int(*pathLen)
	}
	value, _ := asn1.Marshal(bc)

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // id-ce-basicConstraints
		Critical: true,
		Value:    value,
	}
}

// makeKeyUsageExt creates a KeyUsage extension.
//
// For CA certificates, sets keyCertSign and cRLSign.
// For end-entity certificates:
//   - xDSA subjects use digitalSignature
//   - xHPKE subjects use keyAgreement
func makeKeyUsageExt(isCA bool, subjectOID asn1.ObjectIdentifier) pkix.Extension {
	var usage asn1.BitString
	if isCA {
		usage = asn1.BitString{Bytes: []byte{0b0000_0110}, BitLength: 7} // keyCertSign (bit 5) + cRLSign (bit 6)
	} else if subjectOID.Equal(oidXWing) {
		usage = asn1.BitString{Bytes: []byte{0b0000_1000}, BitLength: 5} // keyAgreement (bit 4)
	} else {
		usage = asn1.BitString{Bytes: []byte{0b1000_0000}, BitLength: 1} // digitalSignature (bit 0)
	}

	value, _ := asn1.Marshal(usage)

	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: value}
}
