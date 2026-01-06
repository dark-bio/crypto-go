// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 provides X.509 certificate creation for xDSA and xHPKE keys.
//
// https://datatracker.ietf.org/doc/html/rfc5280
package x509

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Params contains parameters for creating an X.509 certificate.
type Params struct {
	// SubjectName is the subject's common name (CN) in the certificate.
	SubjectName string
	// IssuerName is the issuer's common name (CN) in the certificate.
	IssuerName string
	// NotBefore is the certificate validity start time (Unix timestamp).
	NotBefore uint64
	// NotAfter is the certificate validity end time (Unix timestamp).
	NotAfter uint64
	// IsCA indicates whether this certificate is a CA certificate.
	IsCA bool
	// PathLen is the maximum number of intermediate CAs allowed below this one.
	// Only relevant if IsCA is true.
	PathLen *uint8
}

// Subject is an interface for types that can be embedded into X.509 certificates
// as the subject's public key.
type Subject interface {
	// Bytes returns the raw public key bytes to embed in the certificate.
	Bytes() []byte
	// AlgorithmOID returns the OID for the subject's algorithm.
	AlgorithmOID() asn1.ObjectIdentifier
}

// Signer is an interface for types that can sign X.509 certificates.
type Signer interface {
	// Sign signs the message and returns the signature bytes.
	Sign(message []byte) []byte
	// SignatureOID returns the OID for the signature algorithm.
	SignatureOID() asn1.ObjectIdentifier
	// IssuerPublicKeyBytes returns the issuer's public key bytes for AKI extension.
	IssuerPublicKeyBytes() []byte
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
func New(subject Subject, signer Signer, params *Params) []byte {
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

	// Create the signature algorithm identifier
	sigAlg := pkix.AlgorithmIdentifier{
		Algorithm: signer.SignatureOID(),
	}

	// Build subject and issuer names
	issuerName := makeCNName(params.IssuerName)
	subjectName := makeCNName(params.SubjectName)

	// Build the subject public key info
	subjectBytes := subject.Bytes()
	spki := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: subject.AlgorithmOID(),
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     subjectBytes,
			BitLength: len(subjectBytes) * 8,
		},
	}

	// Build extensions
	extensions := makeExtensions(subjectBytes, signer.IssuerPublicKeyBytes(), params.IsCA, params.PathLen)

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
			Bytes:     signature,
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
	value, _ := asn1.Marshal(keyID)

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

// ParsedCertificate holds the extracted certificate fields.
type ParsedCertificate struct {
	TBSRaw    []byte
	Signature []byte
	PublicKey []byte
	NotBefore uint64
	NotAfter  uint64
}

// Parse extracts the relevant fields from a DER-encoded X.509 certificate.
func Parse(der []byte) (*ParsedCertificate, error) {
	input := cryptobyte.String(der)

	var cert cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) {
		return nil, errors.New("x509: failed to parse certificate")
	}
	if !input.Empty() {
		return nil, errors.New("x509: trailing data after certificate")
	}

	var tbsRaw, sigAlg cryptobyte.String
	if !cert.ReadASN1Element(&tbsRaw, cbasn1.SEQUENCE) {
		return nil, errors.New("x509: failed to parse TBS certificate")
	}
	if !cert.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return nil, errors.New("x509: failed to parse signature algorithm")
	}

	var sigVal cryptobyte.String
	if !cert.ReadASN1(&sigVal, cbasn1.BIT_STRING) {
		return nil, errors.New("x509: failed to parse signature value")
	}
	if !cert.Empty() {
		return nil, errors.New("x509: trailing data in certificate")
	}

	// Parse BitString: first byte is unused bits count
	var unusedBits uint8
	if !sigVal.ReadUint8(&unusedBits) || unusedBits != 0 {
		return nil, errors.New("x509: invalid signature bit string")
	}
	signature := []byte(sigVal)

	// Parse the TBS contents (skip the outer SEQUENCE tag/length we already validated)
	var tbsInner cryptobyte.String
	tbsCopy := tbsRaw
	if !tbsCopy.ReadASN1(&tbsInner, cbasn1.SEQUENCE) {
		return nil, errors.New("x509: failed to parse TBS certificate contents")
	}

	pubKey, notBefore, notAfter, err := parseTBSCertificate(tbsInner)
	if err != nil {
		return nil, err
	}

	return &ParsedCertificate{
		TBSRaw:    []byte(tbsRaw),
		Signature: signature,
		PublicKey: pubKey,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, nil
}

// parseTBSCertificate extracts public key and validity from TBS certificate.
func parseTBSCertificate(data cryptobyte.String) ([]byte, uint64, uint64, error) {
	// Check for optional version [0] EXPLICIT INTEGER
	if data.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var version cryptobyte.String
		if !data.ReadASN1(&version, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, 0, 0, errors.New("x509: failed to parse version")
		}
	}

	// Skip serialNumber (INTEGER)
	var serialNumber cryptobyte.String
	if !data.ReadASN1(&serialNumber, cbasn1.INTEGER) {
		return nil, 0, 0, errors.New("x509: failed to parse serial number")
	}

	// Skip signature algorithm (SEQUENCE)
	var sigAlg cryptobyte.String
	if !data.ReadASN1(&sigAlg, cbasn1.SEQUENCE) {
		return nil, 0, 0, errors.New("x509: failed to parse signature algorithm")
	}

	// Skip issuer (SEQUENCE)
	var issuer cryptobyte.String
	if !data.ReadASN1(&issuer, cbasn1.SEQUENCE) {
		return nil, 0, 0, errors.New("x509: failed to parse issuer")
	}

	// Parse validity (SEQUENCE)
	var validitySeq cryptobyte.String
	if !data.ReadASN1(&validitySeq, cbasn1.SEQUENCE) {
		return nil, 0, 0, errors.New("x509: failed to parse validity")
	}
	notBefore, notAfter, err := parseValidity(validitySeq)
	if err != nil {
		return nil, 0, 0, err
	}

	// Skip subject (SEQUENCE)
	var subject cryptobyte.String
	if !data.ReadASN1(&subject, cbasn1.SEQUENCE) {
		return nil, 0, 0, errors.New("x509: failed to parse subject")
	}

	// Parse subjectPublicKeyInfo (SEQUENCE)
	var spki cryptobyte.String
	if !data.ReadASN1(&spki, cbasn1.SEQUENCE) {
		return nil, 0, 0, errors.New("x509: failed to parse SPKI")
	}
	pubKey, err := parseSPKI(spki)
	if err != nil {
		return nil, 0, 0, err
	}

	return pubKey, notBefore, notAfter, nil
}

// parseValidity extracts notBefore and notAfter from Validity structure.
func parseValidity(data cryptobyte.String) (uint64, uint64, error) {
	notBefore, err := parseTime(&data)
	if err != nil {
		return 0, 0, errors.New("x509: failed to parse notBefore")
	}
	notAfter, err := parseTime(&data)
	if err != nil {
		return 0, 0, errors.New("x509: failed to parse notAfter")
	}
	if !data.Empty() {
		return 0, 0, errors.New("x509: trailing data in validity")
	}
	return uint64(notBefore.Unix()), uint64(notAfter.Unix()), nil
}

// parseTime parses a UTCTime or GeneralizedTime from the input.
func parseTime(data *cryptobyte.String) (time.Time, error) {
	var timeBytes cryptobyte.String

	if data.PeekASN1Tag(cbasn1.UTCTime) {
		if !data.ReadASN1(&timeBytes, cbasn1.UTCTime) {
			return time.Time{}, errors.New("x509: failed to read UTCTime")
		}
		return time.Parse("060102150405Z", string(timeBytes))
	}

	if data.PeekASN1Tag(cbasn1.GeneralizedTime) {
		if !data.ReadASN1(&timeBytes, cbasn1.GeneralizedTime) {
			return time.Time{}, errors.New("x509: failed to read GeneralizedTime")
		}
		return time.Parse("20060102150405Z", string(timeBytes))
	}

	return time.Time{}, errors.New("x509: unsupported time format")
}

// parseSPKI extracts the public key bytes from SubjectPublicKeyInfo.
func parseSPKI(data cryptobyte.String) ([]byte, error) {
	// Skip algorithm (SEQUENCE)
	var alg cryptobyte.String
	if !data.ReadASN1(&alg, cbasn1.SEQUENCE) {
		return nil, errors.New("x509: failed to parse SPKI algorithm")
	}

	// Read subjectPublicKey (BIT STRING)
	var pubKeyBits cryptobyte.String
	if !data.ReadASN1(&pubKeyBits, cbasn1.BIT_STRING) {
		return nil, errors.New("x509: failed to parse SPKI public key")
	}
	if !data.Empty() {
		return nil, errors.New("x509: trailing data in SPKI")
	}

	// Parse BitString: first byte is unused bits count
	var unusedBits uint8
	if !pubKeyBits.ReadUint8(&unusedBits) || unusedBits != 0 {
		return nil, errors.New("x509: invalid public key bit string")
	}

	return []byte(pubKeyBits), nil
}
