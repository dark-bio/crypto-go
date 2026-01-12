// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mldsa provides ML-DSA-65 digital signatures.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-dilithium-certificates
package mldsa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/pem"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// SecretKeySize is the size of the secret key seed in bytes.
	SecretKeySize = 32

	// PublicKeySize is the size of the public key in bytes.
	PublicKeySize = 1952

	// SignatureSize is the size of a signature in bytes.
	SignatureSize = 3309
)

// OID is the ASN.1 object identifier for ML-DSA-65.
var OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

// SecretKey contains an ML-DSA-65 private key for creating digital signatures.
type SecretKey struct {
	key  *mldsa65.PrivateKey
	seed [mldsa65.SeedSize]byte
}

// GenerateKey creates a new, random private key.
func GenerateKey() *SecretKey {
	var seed [SecretKeySize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("mldsa: " + err.Error())
	}
	return ParseSecretKey(seed)
}

// ParseSecretKey creates a private key from a 32-byte seed.
func ParseSecretKey(seed [SecretKeySize]byte) *SecretKey {
	_, key := mldsa65.NewKeyFromSeed(&seed)
	return &SecretKey{
		key:  key,
		seed: seed,
	}
}

// ParseSecretKeyDER parses a DER buffer into a private key.
func ParseSecretKeyDER(der []byte) (*SecretKey, error) {
	// Parse the DER encoded container
	info, err := asn1ext.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	if info.Version != 0 {
		return nil, errors.New("mldsa: unsupported version")
	}
	// Ensure the algorithm OID matches ML_DSA_65 (OID: 2.16.840.1.101.3.4.3.18)
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("mldsa: not an ML-DSA-65 private key")
	}
	// Wrap the private key in a SEQUENCE containing:
	//   - OCTET STRING (32 bytes): seed
	//   - OCTET STRING (4032 bytes): expanded key
	input := cryptobyte.String(info.PrivateKey)

	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("mldsa: invalid private key structure")
	}
	var seedBytes cryptobyte.String
	if !inner.ReadASN1(&seedBytes, cbasn1.OCTET_STRING) {
		return nil, errors.New("mldsa: invalid seed encoding")
	}
	if len(seedBytes) != SecretKeySize {
		return nil, errors.New("mldsa: seed must be 32 bytes")
	}
	var expandedBytes cryptobyte.String
	if !inner.ReadASN1(&expandedBytes, cbasn1.OCTET_STRING) || !inner.Empty() {
		return nil, errors.New("mldsa: invalid expanded key encoding")
	}
	if len(expandedBytes) != 4032 {
		return nil, errors.New("mldsa: expanded key must be 4032 bytes")
	}
	// Generate key from seed and validate it matches the expanded key in DER
	var seed [SecretKeySize]byte
	copy(seed[:], seedBytes)

	_, key := mldsa65.NewKeyFromSeed(&seed)
	expanded, _ := key.MarshalBinary()
	for i := range expanded {
		if expanded[i] != expandedBytes[i] {
			return nil, errors.New("mldsa: expanded key does not match seed")
		}
	}
	return &SecretKey{
		key:  key,
		seed: seed,
	}, nil
}

// MustParseSecretKeyDER parses a DER buffer into a private key.
// It panics if the parsing fails.
func MustParseSecretKeyDER(der []byte) *SecretKey {
	key, err := ParseSecretKeyDER(der)
	if err != nil {
		panic("mldsa: " + err.Error())
	}
	return key
}

// ParseSecretKeyPEM parses a PEM string into a private key.
func ParseSecretKeyPEM(s string) (*SecretKey, error) {
	kind, blob, err := pem.Decode([]byte(s))
	// Crack open the PEM to get to the private key info
	if err != nil {
		return nil, err
	}
	if kind != "PRIVATE KEY" {
		return nil, errors.New("mldsa: invalid PEM type: " + kind)
	}
	// Parse the DER content
	return ParseSecretKeyDER(blob)
}

// MustParseSecretKeyPEM parses a PEM string into a private key.
// It panics if the parsing fails.
func MustParseSecretKeyPEM(s string) *SecretKey {
	key, err := ParseSecretKeyPEM(s)
	if err != nil {
		panic("mldsa: " + err.Error())
	}
	return key
}

// Marshal returns the 32-byte seed of the private key.
func (k *SecretKey) Marshal() [SecretKeySize]byte {
	return k.seed
}

// MarshalDER serializes a private key into a DER buffer.
func (k *SecretKey) MarshalDER() []byte {
	expanded, _ := k.key.MarshalBinary()

	inner := struct {
		Seed     []byte
		Expanded []byte
	}{
		Seed:     k.seed[:],
		Expanded: expanded,
	}
	innerBytes, err := asn1.Marshal(inner)
	if err != nil {
		panic(err) // cannot fail
	}
	info := asn1ext.PKCS8PrivateKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: OID,
		},
		PrivateKey: innerBytes,
	}
	der, err := asn1.Marshal(info)
	if err != nil {
		panic(err) // cannot fail
	}
	return der
}

// MarshalPEM serializes a private key into a PEM string.
func (k *SecretKey) MarshalPEM() string {
	return string(pem.Encode("PRIVATE KEY", k.MarshalDER()))
}

// PublicKey retrieves the public counterpart of the secret key.
func (k *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{
		key: k.key.Public().(*mldsa65.PublicKey),
	}
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *SecretKey) Fingerprint() [32]byte {
	return k.PublicKey().Fingerprint()
}

// Sign creates a digital signature of the message with an optional context string.
func (k *SecretKey) Sign(message []byte, ctx []byte) *Signature {
	var sig [SignatureSize]byte
	mldsa65.SignTo(k.key, message, ctx, false, sig[:])
	return &Signature{inner: sig}
}

// PublicKey contains an ML-DSA-65 public key for verifying digital signatures.
type PublicKey struct {
	key *mldsa65.PublicKey
}

// ParsePublicKey converts a 1952-byte array into a public key.
func ParsePublicKey(b [PublicKeySize]byte) *PublicKey {
	key := new(mldsa65.PublicKey)
	if err := key.UnmarshalBinary(b[:]); err != nil {
		panic(err) // cannot fail for valid length
	}
	return &PublicKey{
		key: key,
	}
}

// ParsePublicKeyDER parses a DER buffer into a public key.
func ParsePublicKeyDER(der []byte) (*PublicKey, error) {
	info, err := asn1ext.ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return nil, err
	}
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("mldsa: not an ML-DSA-65 public key")
	}
	keyBytes := info.SubjectPublicKey.Bytes
	if len(keyBytes) != PublicKeySize {
		return nil, errors.New("mldsa: public key must be 1952 bytes")
	}
	if info.SubjectPublicKey.BitLength != PublicKeySize*8 {
		return nil, errors.New("mldsa: public key BIT STRING must be byte-aligned")
	}
	var b [PublicKeySize]byte
	copy(b[:], keyBytes)
	return &PublicKey{key: ParsePublicKey(b).key}, nil
}

// MustParsePublicKeyDER parses a DER buffer into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyDER(der []byte) *PublicKey {
	key, err := ParsePublicKeyDER(der)
	if err != nil {
		panic("mldsa: " + err.Error())
	}
	return key
}

// ParsePublicKeyPEM parses a PEM string into a public key.
func ParsePublicKeyPEM(s string) (*PublicKey, error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	if kind != "PUBLIC KEY" {
		return nil, errors.New("mldsa: invalid PEM type: " + kind)
	}
	return ParsePublicKeyDER(blob)
}

// MustParsePublicKeyPEM parses a PEM string into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyPEM(s string) *PublicKey {
	key, err := ParsePublicKeyPEM(s)
	if err != nil {
		panic("mldsa: " + err.Error())
	}
	return key
}

// Marshal converts a public key into a 1952-byte array.
func (k *PublicKey) Marshal() [PublicKeySize]byte {
	var out [PublicKeySize]byte
	bytes, _ := k.key.MarshalBinary()
	copy(out[:], bytes)
	return out
}

// MarshalDER serializes a public key into a DER buffer.
func (k *PublicKey) MarshalDER() []byte {
	pubBytes := k.Marshal()

	info := asn1ext.SubjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: OID,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     pubBytes[:],
			BitLength: len(pubBytes) * 8,
		},
	}
	der, _ := asn1.Marshal(info)
	return der
}

// MarshalPEM serializes a public key into a PEM string.
func (k *PublicKey) MarshalPEM() string {
	return string(pem.Encode("PUBLIC KEY", k.MarshalDER()))
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *PublicKey) Fingerprint() [32]byte {
	raw := k.Marshal()
	return sha256.Sum256(raw[:])
}

// Verify verifies a digital signature with an optional context string.
func (k *PublicKey) Verify(message []byte, ctx []byte, sig *Signature) error {
	if !mldsa65.Verify(k.key, message, ctx, sig.inner[:]) {
		return errors.New("mldsa: signature verification failed")
	}
	return nil
}

// Signature contains an ML-DSA-65 signature.
type Signature struct {
	inner [SignatureSize]byte
}

// ParseSignature converts a 3309-byte array into a signature.
func ParseSignature(b [SignatureSize]byte) *Signature {
	return &Signature{inner: b}
}

// Marshal converts a signature into a 3309-byte array.
func (s *Signature) Marshal() [SignatureSize]byte {
	return s.inner
}
