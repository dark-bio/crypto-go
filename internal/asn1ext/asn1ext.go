// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package asn1ext provides ASN.1 structures for PKCS#8 and SPKI encoding.
package asn1ext

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PKCS8PrivateKey is the ASN.1 structure for PKCS#8 private keys.
type PKCS8PrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// ParsePKCS8PrivateKey parses a DER-encoded PKCS#8 private key using strict
// DER validation via cryptobyte. To keep things deterministic, we also reject
// optional public keys.
func ParsePKCS8PrivateKey(der []byte) (*PKCS8PrivateKey, error) {
	input := cryptobyte.String(der)

	// Parse the outer SEQUENCE and ensure no trailing data
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("asn1ext: invalid PKCS#8 structure")
	}
	// Extract the version field (must be a single-byte integer)
	var versionBytes cryptobyte.String
	if !inner.ReadASN1(&versionBytes, cbasn1.INTEGER) || len(versionBytes) != 1 {
		return nil, errors.New("asn1ext: invalid version")
	}
	version := int(versionBytes[0])
	if version != 0 {
		return nil, errors.New("asn1ext: unsupported PKCS#8 version")
	}
	// Parse the AlgorithmIdentifier SEQUENCE
	var algSeq cryptobyte.String
	if !inner.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
		return nil, errors.New("asn1ext: invalid algorithm identifier")
	}
	// Extract the algorithm OID
	var oid asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("asn1ext: invalid algorithm OID")
	}
	// Read optional parameters (ignore them, but consume if present)
	var params cryptobyte.String
	algSeq.ReadOptionalASN1(&params, nil, cbasn1.Tag(0).ContextSpecific())
	if !algSeq.Empty() {
		// Parameters might be other types, just skip remaining
		algSeq.SkipASN1(0)
	}
	// Extract the raw private key bytes from the OCTET STRING
	var keyBytes cryptobyte.String
	if !inner.ReadASN1(&keyBytes, cbasn1.OCTET_STRING) {
		return nil, errors.New("asn1ext: invalid private key encoding")
	}
	// Reject if there's any trailing data
	if !inner.Empty() {
		return nil, errors.New("asn1ext: trailing data in private key")
	}
	return &PKCS8PrivateKey{
		Version: version,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		PrivateKey: keyBytes,
	}, nil
}

// SubjectPublicKeyInfo is the ASN.1 structure for SPKI public keys.
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// ParseSubjectPublicKeyInfo parses a DER-encoded SPKI public key using strict
// DER validation via cryptobyte.
func ParseSubjectPublicKeyInfo(der []byte) (*SubjectPublicKeyInfo, error) {
	input := cryptobyte.String(der)

	// Parse the outer SEQUENCE and ensure no trailing data
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("asn1ext: invalid SPKI structure")
	}
	// Parse the AlgorithmIdentifier SEQUENCE and extract the OID
	var algSeq cryptobyte.String
	if !inner.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
		return nil, errors.New("asn1ext: invalid algorithm identifier")
	}
	var oid asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&oid) {
		return nil, errors.New("asn1ext: invalid algorithm OID")
	}
	// Parse the BIT STRING containing the public key
	var bitString cryptobyte.String
	if !inner.ReadASN1(&bitString, cbasn1.BIT_STRING) || !inner.Empty() {
		return nil, errors.New("asn1ext: invalid public key encoding")
	}
	if len(bitString) < 1 {
		return nil, errors.New("asn1ext: empty bit string")
	}
	// First byte indicates the number of unused bits in the final octet
	paddingBits := int(bitString[0])
	return &SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     bitString[1:],
			BitLength: (len(bitString)-1)*8 - paddingBits,
		},
	}, nil
}
