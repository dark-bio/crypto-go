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
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"

	"github.com/dark-bio/crypto-go/eddsa"
	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/internal/base64ext"
	"github.com/dark-bio/crypto-go/mldsa"
	"github.com/dark-bio/crypto-go/pem"
)

const (
	// signaturePrefix is the byte encoding of "CompositeAlgorithmSignatures2025"
	// per the IETF composite signature spec.
	signaturePrefix = "CompositeAlgorithmSignatures2025"

	// signatureDomain is the signature label for ML-DSA-65-Ed25519-SHA512.
	signatureDomain = "COMPSIG-MLDSA65-Ed25519-SHA512"

	// SecretKeySize is the size of the secret key in bytes.
	// Format: ML-DSA seed (32 bytes) || Ed25519 seed (32 bytes)
	SecretKeySize = 64

	// PublicKeySize is the size of the public key in bytes.
	// Format: ML-DSA (1952 bytes) || Ed25519 (32 bytes)
	PublicKeySize = 1984

	// SignatureSize is the size of a composite signature in bytes.
	// Format: ML-DSA (3309 bytes) || Ed25519 (64 bytes)
	SignatureSize = 3373

	// FingerprintSize is the size of a fingerprint in bytes.
	FingerprintSize = 32
)

// OID is the ASN.1 object identifier for MLDSA65-Ed25519-SHA512.
var OID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 48}

// SecretKey contains a composite ML-DSA-65 + Ed25519 private key for creating
// quantum-resistant digital signatures.
type SecretKey struct {
	mlKey *mldsa.SecretKey
	edKey *eddsa.SecretKey
}

// GenerateKey creates a new, random private key.
func GenerateKey() *SecretKey {
	var seed [SecretKeySize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("xdsa: " + err.Error())
	}
	return ParseSecretKey(seed)
}

// ComposeSecretKey creates a secret key from its constituent ML-DSA-65 and
// Ed25519 secret keys.
func ComposeSecretKey(mlKey *mldsa.SecretKey, edKey *eddsa.SecretKey) *SecretKey {
	return &SecretKey{mlKey: mlKey, edKey: edKey}
}

// Split decomposes a secret key into its constituent ML-DSA-65 and Ed25519
// secret keys.
func (k *SecretKey) Split() (*mldsa.SecretKey, *eddsa.SecretKey) {
	return k.mlKey, k.edKey
}

// ParseSecretKey creates a private key from a 64-byte seed.
func ParseSecretKey(seed [SecretKeySize]byte) *SecretKey {
	var mlSeed [mldsa.SecretKeySize]byte
	var edSeed [eddsa.SecretKeySize]byte

	copy(mlSeed[:], seed[:32])
	copy(edSeed[:], seed[32:])

	return &SecretKey{
		mlKey: mldsa.ParseSecretKey(mlSeed),
		edKey: eddsa.ParseSecretKey(edSeed),
	}
}

// ParseSecretKeyDER parses a DER buffer into a private key.
func ParseSecretKeyDER(der []byte) (*SecretKey, error) {
	info, err := asn1ext.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	if info.Version != 0 {
		return nil, errors.New("xdsa: unsupported version")
	}
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("xdsa: not a composite ML-DSA-65-Ed25519-SHA512 private key")
	}
	if len(info.PrivateKey) != 64 {
		return nil, errors.New("xdsa: composite private key must be 64 bytes")
	}
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
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	if kind != "PRIVATE KEY" {
		return nil, errors.New("xdsa: invalid PEM type: " + kind)
	}
	return ParseSecretKeyDER(blob)
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

	mlSeed := k.mlKey.Marshal()
	edSeed := k.edKey.Marshal()

	copy(out[:32], mlSeed[:])
	copy(out[32:], edSeed[:])
	return out
}

// MarshalDER serializes a private key into a DER buffer.
func (k *SecretKey) MarshalDER() []byte {
	seed := k.Marshal()

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
	return string(pem.Encode("PRIVATE KEY", k.MarshalDER()))
}

// PublicKey retrieves the public counterpart of the secret key.
func (k *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{
		mlKey: k.mlKey.PublicKey(),
		edKey: k.edKey.PublicKey(),
	}
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *SecretKey) Fingerprint() Fingerprint {
	return k.PublicKey().Fingerprint()
}

// Sign creates a digital signature of the message. This call will never return
// an error, the type is there for composability.
func (k *SecretKey) Sign(message []byte) (*Signature, error) {
	// Compute the M' that will be signed by the two keys
	mPrime := cmldsaMessagePrime(message)

	// Sign M' with both algorithms
	mlSig, err := k.mlKey.Sign(mPrime, []byte(signatureDomain))
	if err != nil {
		panic(err) // Signing with keys never fails
	}
	edSig, err := k.edKey.Sign(mPrime)
	if err != nil {
		panic(err) // Signing with keys never fails
	}
	// Concatenate: ML-DSA-65 (3309 bytes) || Ed25519 (64 bytes)
	var sig Signature
	copy(sig[:3309], mlSig[:])
	copy(sig[3309:], edSig[:])
	return &sig, nil
}

// SplitSign implements the xDSA signature algorithm, operating on split signers
// instead of a composite secret key. This method is needed as currently there is
// no hardware HSM that supports ML-DSA; but even when that arrives, composite
// ML-DSA will probably not be shipped maybe ever. This method allows the user to
// create the two signatures and combine them, *without* having to leak out the
// internal signature scheme.
func SplitSign(mlKey mldsa.Signer, edKey eddsa.Signer, message []byte) (*Signature, error) {
	// Compute the M' that will be signed by the two keys
	mPrime := cmldsaMessagePrime(message)

	// Sign M' with both algorithms
	mlSig, err := mlKey.Sign(mPrime, []byte(signatureDomain))
	if err != nil {
		return nil, err
	}
	edSig, err := edKey.Sign(mPrime)
	if err != nil {
		return nil, err
	}
	// Concatenate: ML-DSA-65 (3309 bytes) || Ed25519 (64 bytes)
	var sig Signature
	copy(sig[:3309], mlSig[:])
	copy(sig[3309:], edSig[:])
	return &sig, nil
}

// PublicKey is an ML-DSA-65 public key paired with an Ed25519 public key for
// verifying quantum resistant digital signatures.
type PublicKey struct {
	mlKey *mldsa.PublicKey
	edKey *eddsa.PublicKey
}

// ComposePublicKey creates a public key from its constituent ML-DSA-65 and
// Ed25519 public keys.
func ComposePublicKey(mlKey *mldsa.PublicKey, edKey *eddsa.PublicKey) *PublicKey {
	return &PublicKey{mlKey: mlKey, edKey: edKey}
}

// Split decomposes a public key into its constituent ML-DSA-65 and Ed25519
// public keys.
func (k *PublicKey) Split() (*mldsa.PublicKey, *eddsa.PublicKey) {
	return k.mlKey, k.edKey
}

// ParsePublicKey converts a 1984-byte array into a public key.
func ParsePublicKey(b [PublicKeySize]byte) (*PublicKey, error) {
	var mlBytes [mldsa.PublicKeySize]byte
	var edBytes [eddsa.PublicKeySize]byte

	copy(mlBytes[:], b[:1952])
	copy(edBytes[:], b[1952:])

	edKey, err := eddsa.ParsePublicKey(edBytes)
	if err != nil {
		return nil, errors.New("xdsa: invalid Ed25519 public key")
	}
	return &PublicKey{
		mlKey: mldsa.ParsePublicKey(mlBytes),
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
	info, err := asn1ext.ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return nil, err
	}
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("xdsa: not a composite ML-DSA-65-Ed25519-SHA512 public key")
	}
	keyBytes := info.SubjectPublicKey.Bytes
	if len(keyBytes) != PublicKeySize {
		return nil, errors.New("xdsa: composite public key must be 1984 bytes")
	}
	if info.SubjectPublicKey.BitLength != PublicKeySize*8 {
		return nil, errors.New("xdsa: public key BIT STRING must be byte-aligned")
	}
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
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	if kind != "PUBLIC KEY" {
		return nil, errors.New("xdsa: invalid PEM type: " + kind)
	}
	return ParsePublicKeyDER(blob)
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

	mlBytes := k.mlKey.Marshal()
	edBytes := k.edKey.Marshal()

	copy(out[:1952], mlBytes[:])
	copy(out[1952:], edBytes[:])

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

func (k *PublicKey) MarshalText() ([]byte, error) {
	raw := k.Marshal()
	return []byte(base64.StdEncoding.EncodeToString(raw[:])), nil
}

func (k *PublicKey) UnmarshalText(text []byte) error {
	raw, err := base64ext.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(raw) != PublicKeySize {
		return errors.New("xdsa: invalid public key length")
	}
	var b [PublicKeySize]byte
	copy(b[:], raw)
	key, err := ParsePublicKey(b)
	if err != nil {
		return err
	}
	*k = *key
	return nil
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *PublicKey) Fingerprint() Fingerprint {
	raw := k.Marshal()
	return Fingerprint(sha256.Sum256(raw[:]))
}

// Verify verifies a digital signature.
func (k *PublicKey) Verify(message []byte, sig *Signature) error {
	// Compute the M' that needed to be signed by the two keys
	mPrime := cmldsaMessagePrime(message)

	// Split signatures
	mlSig, edSig := sig.Split()

	// Verify both signatures
	if err := k.mlKey.Verify(mPrime, []byte(signatureDomain), mlSig); err != nil {
		return errors.New("xdsa: ML-DSA signature verification failed")
	}
	if err := k.edKey.Verify(mPrime, edSig); err != nil {
		return errors.New("xdsa: Ed25519 signature verification failed")
	}
	return nil
}

// Signature contains a composite ML-DSA-65 + Ed25519 signature.
type Signature [SignatureSize]byte

// ComposeSignature creates a signature from its constituent ML-DSA-65 and
// Ed25519 signatures.
func ComposeSignature(mlSig *mldsa.Signature, edSig *eddsa.Signature) *Signature {
	var sig Signature
	copy(sig[:mldsa.SignatureSize], mlSig[:])
	copy(sig[mldsa.SignatureSize:], edSig[:])
	return &sig
}

// Split decomposes a signature into its constituent ML-DSA-65 and Ed25519
// signatures.
func (s *Signature) Split() (*mldsa.Signature, *eddsa.Signature) {
	var mlSig mldsa.Signature
	var edSig eddsa.Signature
	copy(mlSig[:], s[:3309])
	copy(edSig[:], s[3309:])
	return &mlSig, &edSig
}

// MarshalText implements encoding.TextMarshaler.
func (s *Signature) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(s[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *Signature) UnmarshalText(text []byte) error {
	raw, err := base64ext.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(raw) != SignatureSize {
		return errors.New("xdsa: invalid signature length")
	}
	copy(s[:], raw)
	return nil
}

// Fingerprint is a 256-bit unique identifier for a composite xDSA key.
type Fingerprint [FingerprintSize]byte

// MarshalText implements encoding.TextMarshaler.
func (f *Fingerprint) MarshalText() ([]byte, error) {
	return []byte(base64.StdEncoding.EncodeToString(f[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (f *Fingerprint) UnmarshalText(text []byte) error {
	raw, err := base64ext.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(raw) != FingerprintSize {
		return errors.New("xdsa: invalid fingerprint length")
	}
	copy(f[:], raw)
	return nil
}

// Signer is an interface that allows creating xDSA signatures without a specific
// backend. It's used for remote or hardware signers.
type Signer interface {
	// Sign signs the message and returns the signature.
	Sign(message []byte) (*Signature, error)

	// PublicKey returns the signer's public key.
	PublicKey() *PublicKey
}

// cmldsaMessagePrime derives the composite message M' from a raw message
// according to the IETF composite signature spec:
//
//	M' = Prefix || Label || len(ctx) || ctx || PH(M)
//	  where ctx is empty and PH is SHA512.
//
// Use this when signing separately with individual ML-DSA and Ed25519 keys
// before composing the signatures.
func cmldsaMessagePrime(message []byte) []byte {
	prehash := sha512.Sum512(message)

	mPrime := make([]byte, 0, len(signaturePrefix)+len(signatureDomain)+1+64)
	mPrime = append(mPrime, signaturePrefix...)
	mPrime = append(mPrime, signatureDomain...)
	mPrime = append(mPrime, 0) // len(ctx) = 0
	mPrime = append(mPrime, prehash[:]...)
	return mPrime
}
