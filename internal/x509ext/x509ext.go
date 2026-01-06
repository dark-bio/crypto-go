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
	"unicode/utf8"
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
	Sign(message []byte) [3373]byte

	// PublicKey returns the issuer's public key.
	PublicKey() [1984]byte
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
func New[T XDSAOrXHPKEPublicKey](subject Subject[T], signer Signer, params *x509.Params) []byte {
	// Validate common names are valid UTF-8
	if !utf8.ValidString(params.SubjectName) {
		panic("x509: subject name is not valid UTF-8")
	}
	if !utf8.ValidString(params.IssuerName) {
		panic("x509: issuer name is not valid UTF-8")
	}

	// Generate a random 128-bit serial number (positive)
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

	// Build subject and issuer names
	issuerName := makeCNName(params.IssuerName)
	subjectName := makeCNName(params.SubjectName)

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

	// Build extensions
	pk := signer.PublicKey()
	extensions := makeExtensions(subjectBytes, pk[:], params.IsCA, params.PathLen)

	// Build the TBS certificate
	tbs := tbsCertificate{
		Version:            2, // v3
		SerialNumber:       serial,
		SignatureAlgorithm: sigAlg,
		Issuer:             issuerName,
		Validity: validity{
			NotBefore: time.Unix(int64(params.NotBefore), 0).UTC(),
			NotAfter:  time.Unix(int64(params.NotAfter), 0).UTC(),
		},
		Subject:       subjectName,
		PublicKeyInfo: spki,
		Extensions:    extensions,
	}

	// Encode TBS certificate
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		panic("x509: " + err.Error())
	}

	// Sign the TBS certificate
	signature := signer.Sign(tbsDER)

	// Build the complete certificate
	cert := certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: sigAlg,
		SignatureValue: asn1.BitString{
			Bytes:     signature[:],
			BitLength: len(signature) * 8,
		},
	}

	// Encode the complete certificate
	certDER, err := asn1.Marshal(cert)
	if err != nil {
		panic("x509: " + err.Error())
	}
	return certDER
}

// makeCNName creates a distinguished name with only a CommonName.
func makeCNName(cn string) asn1.RawValue {
	// OID 2.5.4.3 = CommonName
	cnOID := asn1.ObjectIdentifier{2, 5, 4, 3}

	// AttributeTypeAndValue
	atv := []interface{}{cnOID, cn}
	atvDER, _ := asn1.Marshal(atv)

	// RelativeDistinguishedName (SET OF AttributeTypeAndValue)
	rdn := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      atvDER,
	}
	rdnDER, _ := asn1.Marshal(rdn)

	// Name (SEQUENCE OF RelativeDistinguishedName)
	name := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      rdnDER,
	}
	nameDER, _ := asn1.Marshal(name)

	return asn1.RawValue{FullBytes: nameDER}
}

// makeExtensions builds the certificate extensions.
func makeExtensions(subjectPubKey []byte, issuerPubKey []byte, isCA bool, pathLen *uint8) []pkix.Extension {
	extensions := make([]pkix.Extension, 0, 4)

	// BasicConstraints (critical)
	extensions = append(extensions, makeBasicConstraintsExt(isCA, pathLen))

	// KeyUsage (critical)
	extensions = append(extensions, makeKeyUsageExt(isCA))

	// SubjectKeyIdentifier
	extensions = append(extensions, makeSKIExt(subjectPubKey))

	// AuthorityKeyIdentifier
	extensions = append(extensions, makeAKIExt(issuerPubKey))

	return extensions
}

// makeSKIExt creates a SubjectKeyIdentifier extension.
func makeSKIExt(publicKey []byte) pkix.Extension {
	// SHA1 hash of the public key
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
	// SHA1 hash of the issuer public key
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

// makeBasicConstraintsExt creates a BasicConstraints extension.
func makeBasicConstraintsExt(isCA bool, pathLen *uint8) pkix.Extension {
	var buf []byte
	if isCA {
		buf = append(buf, 0x01, 0x01, 0xFF) // BOOLEAN TRUE
		if pathLen != nil {
			plBytes, _ := asn1.Marshal(int(*pathLen))
			buf = append(buf, plBytes...)
		}
	}

	// Wrap in SEQUENCE
	value := make([]byte, 0, len(buf)+2)
	value = append(value, 0x30, byte(len(buf)))
	value = append(value, buf...)

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // id-ce-basicConstraints
		Critical: true,
		Value:    value,
	}
}

// makeKeyUsageExt creates a KeyUsage extension.
func makeKeyUsageExt(isCA bool) pkix.Extension {
	var usageByte byte
	var unusedBits byte

	if isCA {
		usageByte = 0b0000_0110 // keyCertSign + cRLSign
		unusedBits = 1
	} else {
		usageByte = 0b1000_0000 // digitalSignature
		unusedBits = 7
	}

	value := []byte{0x03, 0x02, unusedBits, usageByte}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // id-ce-keyUsage
		Critical: true,
		Value:    value,
	}
}
