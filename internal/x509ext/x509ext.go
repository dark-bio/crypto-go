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
	"time"
	"unsafe"

	"github.com/dark-bio/crypto-go/x509"
)

// XDSAOrXHPKEPublicKey defines the supported public key sizes. This allows us
// to reuse
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
func New[T XDSAOrXHPKEPublicKey](subject Subject[T], signer Signer, params *x509.Params) ([]byte, error) {
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
	issuerRDN, err := asn1.Marshal(params.IssuerName.ToRDNSequence())
	if err != nil {
		panic("x509: " + err.Error())
	}
	subjectRDN, err := asn1.Marshal(params.SubjectName.ToRDNSequence())
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
	extensions := []pkix.Extension{
		makeBasicConstraintsExt(params.IsCA, params.PathLen),
		makeKeyUsageExt(params.IsCA),
		makeSKIExt(subjectBytes),
		makeAKIExt(pk[:]),
	}
	// Build the TBS certificate
	tbs := tbsCertificate{
		Version:            2, // v3
		SerialNumber:       serial,
		SignatureAlgorithm: sigAlg,
		Issuer:             issuerName,
		Validity: validity{
			NotBefore: params.NotBefore.UTC(),
			NotAfter:  params.NotAfter.UTC(),
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
// For CA certificates, sets keyCertSign (bit 5) and cRLSign (bit 6).
// For end-entity certificates, sets digitalSignature (bit 0).
func makeKeyUsageExt(isCA bool) pkix.Extension {
	// KeyUsage ::= BIT STRING { Bit 0: digitalSignature, Bit 5: keyCertSign, Bit 6: cRLSign }
	var usage asn1.BitString
	if isCA {
		usage = asn1.BitString{Bytes: []byte{0b0000_0110}, BitLength: 7} // keyCertSign (bit 5) + cRLSign (bit 6), 1 unused bit
	} else {
		usage = asn1.BitString{Bytes: []byte{0b1000_0000}, BitLength: 1} // digitalSignature (bit 0), 7 unused bits
	}
	value, _ := asn1.Marshal(usage)

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // id-ce-keyUsage
		Critical: true,
		Value:    value,
	}
}
