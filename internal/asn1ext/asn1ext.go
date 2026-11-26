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

// ErrTrailingData is returned when a structure parses correctly but is
// followed by additional unconsumed bytes.
var ErrTrailingData = errors.New("asn1ext: trailing data")

// ErrInvalidBitString is returned when an SPKI public key has an invalid BIT STRING.
var ErrInvalidBitString = errors.New("asn1ext: invalid public key bit string")

// PKCS8PrivateKey is the ASN.1 structure for PKCS#8 private keys.
type PKCS8PrivateKey struct {
	Version    int                      // PKCS#8 structure version (must be 0)
	Algorithm  pkix.AlgorithmIdentifier // key algorithm and optional parameters
	PrivateKey []byte                   // raw algorithm-specific private key bytes
}

// ParsePKCS8PrivateKey parses a DER-encoded PKCS#8 private key using strict
// DER validation via cryptobyte. Optional public keys are rejected for
// deterministic encoding.
func ParsePKCS8PrivateKey(der []byte) (*PKCS8PrivateKey, error) {
	input := cryptobyte.String(der)

	// Parse the outer SEQUENCE and ensure no trailing data
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) {
		return nil, errors.New("asn1ext: invalid PKCS#8 structure")
	}
	if !input.Empty() {
		return nil, ErrTrailingData
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
	// Retain any remaining algorithm parameters raw for callers to police
	params := asn1.RawValue{FullBytes: []byte(algSeq)}

	// Extract the raw private key bytes from the OCTET STRING
	var keyBytes cryptobyte.String
	if !inner.ReadASN1(&keyBytes, cbasn1.OCTET_STRING) {
		return nil, errors.New("asn1ext: invalid private key encoding")
	}
	// Reject if there's any trailing data
	if !inner.Empty() {
		return nil, ErrTrailingData
	}
	return &PKCS8PrivateKey{
		Version: version,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: params,
		},
		PrivateKey: keyBytes,
	}, nil
}

// SubjectPublicKeyInfo is the ASN.1 structure for SPKI public keys.
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier // key algorithm and optional parameters
	SubjectPublicKey asn1.BitString           // public key BIT STRING
}

// ParseSubjectPublicKeyInfo parses a DER-encoded SPKI public key using strict
// DER validation via cryptobyte.
func ParseSubjectPublicKeyInfo(der []byte) (*SubjectPublicKeyInfo, error) {
	input := cryptobyte.String(der)

	// Parse the outer SEQUENCE and ensure no trailing data
	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) {
		return nil, errors.New("asn1ext: invalid SPKI structure")
	}
	if !input.Empty() {
		return nil, ErrTrailingData
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
	// Retain any remaining algorithm parameters raw for callers to police
	params := asn1.RawValue{FullBytes: []byte(algSeq)}

	// Parse the BIT STRING containing the public key
	var bitString asn1.BitString
	if !inner.ReadASN1BitString(&bitString) {
		return nil, ErrInvalidBitString
	}
	if !inner.Empty() {
		return nil, ErrTrailingData
	}
	return &SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: params,
		},
		SubjectPublicKey: bitString,
	}, nil
}
