// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xdsa provides composite ML-DSA-65 + Ed25519 digital signatures.
//
// https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs
package xdsa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"filippo.io/edwards25519"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/dark-bio/crypto-go/internal/asn1ext"
)

const (
	// SignaturePrefix is the byte encoding of "CompositeAlgorithmSignatures2025"
	// per the IETF composite signature spec.
	SignaturePrefix = "CompositeAlgorithmSignatures2025"

	// SignatureDomain is the signature label for ML-DSA-65-Ed25519-SHA512.
	SignatureDomain = "COMPSIG-MLDSA65-Ed25519-SHA512"

	// SecretKeySize is the size of the secret key in bytes.
	// Format: ML-DSA seed (32 bytes) || Ed25519 seed (32 bytes)
	SecretKeySize = 64

	// PublicKeySize is the size of the public key in bytes.
	// Format: ML-DSA (1952 bytes) || Ed25519 (32 bytes)
	PublicKeySize = 1984

	// SignatureSize is the size of a composite signature in bytes.
	// Format: ML-DSA (3309 bytes) || Ed25519 (64 bytes)
	SignatureSize = 3373
)

// OID is the ASN.1 object identifier for MLDSA65-Ed25519-SHA512.
var OID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 48}

// SecretKey contains a composite ML-DSA-65 + Ed25519 private key for creating
// quantum-resistant digital signatures.
type SecretKey struct {
	mlKey  *mldsa65.PrivateKey
	mlSeed [mldsa65.SeedSize]byte
	edKey  ed25519.PrivateKey
}

// GenerateKey creates a new, random private key.
func GenerateKey() *SecretKey {
	var seed [SecretKeySize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("xdsa: " + err.Error())
	}
	return ParseSecretKey(seed)
}

// ParseSecretKey creates a private key from a 64-byte seed.
func ParseSecretKey(seed [SecretKeySize]byte) *SecretKey {
	var mlSeed [mldsa65.SeedSize]byte
	copy(mlSeed[:], seed[:32])

	_, mlKey := mldsa65.NewKeyFromSeed(&mlSeed)
	edKey := ed25519.NewKeyFromSeed(seed[32:])

	return &SecretKey{
		mlKey:  mlKey,
		mlSeed: mlSeed,
		edKey:  edKey,
	}
}

// ParseSecretKeyDER parses a DER buffer into a private key..
func ParseSecretKeyDER(der []byte) (*SecretKey, error) {
	// Parse the DER encoded container
	var info asn1ext.PKCS8PrivateKey
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, err
	}
	if info.Version != 0 {
		return nil, errors.New("xdsa: unsupported version")
	}
	// Ensure the algorithm OID matches MLDSA65-Ed25519-SHA512 (1.3.6.1.5.5.7.6.48)
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("xdsa: not a composite ML-DSA-65-Ed25519-SHA512 private key")
	}
	// Private key is ML-DSA seed (32) || Ed25519 seed (32) = 64 bytes
	if len(info.PrivateKey) != 64 {
		return nil, errors.New("xdsa: composite private key must be 64 bytes")
	}
	// Go's ASN1 parser permits unused trailing bytes (inside or outside). We
	// don't want to allow that, so just round trip the format and see if it's
	// matching or not.
	recoded, err := asn1.Marshal(info)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(recoded, der) {
		return nil, errors.New("xdsa: non-canonical DER encoding")
	}
	// Everything seems fine, instantiate the key
	var seed [SecretKeySize]byte
	copy(seed[:], info.PrivateKey)
	return ParseSecretKey(seed), nil
}

// MustParseSecretKeyDER parses a DER buffer into a private key.
// It panics if the parsing fails.
func MustParseSecretKeyDER(der []byte) *SecretKey {
	key, err := ParseSecretKeyDER(der)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key
}

// ParseSecretKeyPEM parses a PEM string into a private key.
func ParseSecretKeyPEM(s string) (*SecretKey, error) {
	// Crack open the PEM to get to the private key info
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("xdsa: invalid PEM")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, errors.New("xdsa: invalid PEM type: " + block.Type)
	}
	// Parse the DER content
	return ParseSecretKeyDER(block.Bytes)
}

// MustParseSecretKeyPEM parses a PEM string into a private key.
// It panics if the parsing fails.
func MustParseSecretKeyPEM(s string) *SecretKey {
	key, err := ParseSecretKeyPEM(s)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key
}

// Marshal converts a secret key into a 64-byte array.
func (k *SecretKey) Marshal() [SecretKeySize]byte {
	var out [SecretKeySize]byte
	copy(out[:32], k.mlSeed[:])
	copy(out[32:], k.edKey.Seed())
	return out
}

// MarshalDER serializes a private key into a DER buffer.
func (k *SecretKey) MarshalDER() []byte {
	// The private key is ML-DSA seed (32) || Ed25519 seed (32) = 64 bytes
	seed := k.Marshal()

	// Create the MLDSA65-Ed25519-SHA512 algorithm identifier; parameters
	// MUST be absent
	info := asn1ext.PKCS8PrivateKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: OID,
		},
		PrivateKey: seed[:],
	}
	der, err := asn1.Marshal(info)
	if err != nil {
		panic(err) // cannot fail
	}
	return der
}

// MarshalPEM serializes a private key into a PEM string.
func (k *SecretKey) MarshalPEM() string {
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: k.MarshalDER(),
	}
	return string(pem.EncodeToMemory(block))
}

// PublicKey retrieves the public counterpart of the secret key.
func (k *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{
		mlKey: k.mlKey.Public().(*mldsa65.PublicKey),
		edKey: k.edKey.Public().(ed25519.PublicKey),
	}
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *SecretKey) Fingerprint() [32]byte {
	return k.PublicKey().Fingerprint()
}

// Sign creates a digital signature of the message.
func (k *SecretKey) Sign(message []byte) [SignatureSize]byte {
	// Construct M' = Prefix || Label || len(ctx) || ctx || PH(M)
	// where ctx is empty and PH is SHA512
	prehash := sha512.Sum512(message)

	mPrime := make([]byte, 0, len(SignaturePrefix)+len(SignatureDomain)+1+64)
	mPrime = append(mPrime, SignaturePrefix...)
	mPrime = append(mPrime, SignatureDomain...)
	mPrime = append(mPrime, 0) // len(ctx) = 0
	mPrime = append(mPrime, prehash[:]...)

	// Sign M' with both algorithms, as ML-DSA-65 (3309 bytes) || Ed25519 (64 bytes)
	var sig [SignatureSize]byte

	mldsa65.SignTo(k.mlKey, mPrime, []byte(SignatureDomain), false, sig[:3309])
	edSig := ed25519.Sign(k.edKey, mPrime)
	copy(sig[3309:], edSig)

	return sig
}

// PublicKey is an ML-DSA-65 public key paired with an Ed25519 public key for
// verifying quantum resistant digital signatures.
type PublicKey struct {
	mlKey *mldsa65.PublicKey
	edKey ed25519.PublicKey
}

// ParsePublicKey converts a 1984-byte array into a public key.
func ParsePublicKey(b [PublicKeySize]byte) (*PublicKey, error) {
	var mlBytes [mldsa65.PublicKeySize]byte
	copy(mlBytes[:], b[:1952])

	// Parse the ML-DSA key, this cannot fail
	mlKey := new(mldsa65.PublicKey)
	if err := mlKey.UnmarshalBinary(mlBytes[:]); err != nil {
		panic(err) // cannot fail
	}
	// Parse Ed25519, this can fail with an invalid curve point
	if _, err := new(edwards25519.Point).SetBytes(b[1952:]); err != nil {
		return nil, errors.New("xdsa: invalid Ed25519 public key")
	}
	edKey := ed25519.PublicKey(b[1952:])

	return &PublicKey{
		mlKey: mlKey,
		edKey: edKey,
	}, nil
}

// MustParsePublicKey converts a 1984-byte array into a public key.
// It panics if the parsing fails.
func MustParsePublicKey(b [PublicKeySize]byte) *PublicKey {
	key, err := ParsePublicKey(b)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key
}

// ParsePublicKeyDER parses a DER buffer into a public key.
func ParsePublicKeyDER(der []byte) (*PublicKey, error) {
	// Parse the DER encoded container
	var info asn1ext.SubjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, err
	}
	// Ensure the algorithm OID matches MLDSA65-Ed25519-SHA512 (1.3.6.1.5.5.7.6.48)
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("xdsa: not a composite ML-DSA-65-Ed25519-SHA512 public key")
	}
	// Public key is ML-DSA-65 (1952 bytes) || Ed25519 (32 bytes) = 1984 bytes
	keyBytes := info.SubjectPublicKey.Bytes
	if len(keyBytes) != PublicKeySize {
		return nil, errors.New("xdsa: composite public key must be 1984 bytes")
	}
	// Go's ASN1 parser permits unused trailing bytes (inside or outside). We
	// don't want to allow that, so just round trip the format and see if it's
	// matching or not.
	recoded, err := asn1.Marshal(info)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(recoded, der) {
		return nil, errors.New("xdsa: non-canonical DER encoding")
	}
	// Everything seems fine, instantiate the key
	var b [PublicKeySize]byte
	copy(b[:], keyBytes)
	return ParsePublicKey(b)
}

// MustParsePublicKeyDER parses a DER buffer into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyDER(der []byte) *PublicKey {
	key, err := ParsePublicKeyDER(der)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key
}

// ParsePublicKeyPEM parses a PEM string into a public key.
func ParsePublicKeyPEM(s string) (*PublicKey, error) {
	// Crack open the PEM to get to the public key info
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("xdsa: invalid PEM")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, errors.New("xdsa: invalid PEM type: " + block.Type)
	}
	// Parse the DER content
	return ParsePublicKeyDER(block.Bytes)
}

// MustParsePublicKeyPEM parses a PEM string into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyPEM(s string) *PublicKey {
	key, err := ParsePublicKeyPEM(s)
	if err != nil {
		panic("xdsa: " + err.Error())
	}
	return key
}

// Marshal converts a public key into a 1984-byte array.
func (k *PublicKey) Marshal() [PublicKeySize]byte {
	var out [PublicKeySize]byte

	mlBytes, _ := k.mlKey.MarshalBinary()
	copy(out[:1952], mlBytes)
	copy(out[1952:], k.edKey)

	return out
}

// MarshalDER serializes a public key into a DER buffer.
func (k *PublicKey) MarshalDER() []byte {
	// The public key info is the BITSTRING of the two keys concatenated
	pubBytes := k.Marshal()

	// Create the MLDSA65-Ed25519-SHA512 algorithm identifier; parameters
	// MUST be absent
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
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: k.MarshalDER(),
	}
	return string(pem.EncodeToMemory(block))
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *PublicKey) Fingerprint() [32]byte {
	raw := k.Marshal()
	return sha256.Sum256(raw[:])
}

// Verify verifies a digital signature.
func (k *PublicKey) Verify(message []byte, sig [SignatureSize]byte) error {
	// Construct M' = Prefix || Label || len(ctx) || ctx || PH(M)
	// where ctx is empty and PH is SHA512
	prehash := sha512.Sum512(message)

	mPrime := make([]byte, 0, len(SignaturePrefix)+len(SignatureDomain)+1+64)
	mPrime = append(mPrime, SignaturePrefix...)
	mPrime = append(mPrime, SignatureDomain...)
	mPrime = append(mPrime, 0) // len(ctx) = 0
	mPrime = append(mPrime, prehash[:]...)

	// Split and verify both signatures
	if !mldsa65.Verify(k.mlKey, mPrime, []byte(SignatureDomain), sig[:3309]) {
		return errors.New("xdsa: ML-DSA signature verification failed")
	}
	if !ed25519.Verify(k.edKey, mPrime, sig[3309:]) {
		return errors.New("xdsa: Ed25519 signature verification failed")
	}
	return nil
}
