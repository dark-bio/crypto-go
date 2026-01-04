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
)

// PKCS8PrivateKey is the ASN.1 structure for PKCS#8 private keys.
type PKCS8PrivateKey struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// SubjectPublicKeyInfo is the ASN.1 structure for SPKI public keys.
type SubjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}
