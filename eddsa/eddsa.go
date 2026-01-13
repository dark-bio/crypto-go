// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package eddsa provides Ed25519 digital signatures.
//
// https://datatracker.ietf.org/doc/html/rfc8032
package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"

	"filippo.io/edwards25519"
	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/pem"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

const (
	// SecretKeySize is the size of the secret key seed in bytes.
	SecretKeySize = 32

	// PublicKeySize is the size of the public key in bytes.
	PublicKeySize = 32

	// SignatureSize is the size of a signature in bytes.
	SignatureSize = 64
)

// OID is the ASN.1 object identifier for Ed25519.
var OID = asn1.ObjectIdentifier{1, 3, 101, 112}

// SecretKey contains an Ed25519 private key usable for signing.
type SecretKey struct {
	key ed25519.PrivateKey
}

// GenerateKey creates a new, random private key.
func GenerateKey() *SecretKey {
	var seed [SecretKeySize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic("eddsa: " + err.Error())
	}
	return ParseSecretKey(seed)
}

// ParseSecretKey creates a private key from a 32-byte seed.
func ParseSecretKey(seed [SecretKeySize]byte) *SecretKey {
	return &SecretKey{
		key: ed25519.NewKeyFromSeed(seed[:]),
	}
}

// ParseSecretKeyDER parses a DER buffer into a private key.
func ParseSecretKeyDER(der []byte) (*SecretKey, error) {
	pkcs8, err := asn1ext.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	if !pkcs8.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("eddsa: not an Ed25519 private key")
	}
	input := cryptobyte.String(pkcs8.PrivateKey)
	var seed cryptobyte.String
	if !input.ReadASN1(&seed, cbasn1.OCTET_STRING) || !input.Empty() {
		return nil, errors.New("eddsa: invalid Ed25519 seed encoding")
	}
	if len(seed) != SecretKeySize {
		return nil, errors.New("eddsa: invalid Ed25519 seed length")
	}
	return &SecretKey{key: ed25519.NewKeyFromSeed(seed)}, nil
}

// MustParseSecretKeyDER parses a DER buffer into a private key.
// It panics if the parsing fails.
func MustParseSecretKeyDER(der []byte) *SecretKey {
	key, err := ParseSecretKeyDER(der)
	if err != nil {
		panic("eddsa: " + err.Error())
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
		return nil, errors.New("eddsa: invalid PEM type: " + kind)
	}
	return ParseSecretKeyDER(blob)
}

// MustParseSecretKeyPEM parses a PEM string into a private key.
// It panics if the parsing fails.
func MustParseSecretKeyPEM(s string) *SecretKey {
	key, err := ParseSecretKeyPEM(s)
	if err != nil {
		panic("eddsa: " + err.Error())
	}
	return key
}

// Marshal converts a secret key into a 32-byte seed array.
func (k *SecretKey) Marshal() [SecretKeySize]byte {
	var out [SecretKeySize]byte
	copy(out[:], k.key.Seed())
	return out
}

// MarshalDER serializes a private key into a DER buffer.
func (k *SecretKey) MarshalDER() []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		panic(err) // cannot fail for valid key
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
		key: k.key.Public().(ed25519.PublicKey),
	}
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *SecretKey) Fingerprint() [32]byte {
	return k.PublicKey().Fingerprint()
}

// Sign creates a digital signature of the message.
func (k *SecretKey) Sign(message []byte) *Signature {
	sig := ed25519.Sign(k.key, message)
	var out [SignatureSize]byte
	copy(out[:], sig)
	return &Signature{inner: out}
}

// PublicKey contains an Ed25519 public key usable for verification.
type PublicKey struct {
	key ed25519.PublicKey
}

// ParsePublicKey converts a 32-byte array into a public key.
func ParsePublicKey(b [PublicKeySize]byte) (*PublicKey, error) {
	if _, err := new(edwards25519.Point).SetBytes(b[:]); err != nil {
		return nil, errors.New("eddsa: invalid Ed25519 public key")
	}
	return &PublicKey{
		key: b[:],
	}, nil
}

// MustParsePublicKey converts a 32-byte array into a public key.
// It panics if the parsing fails.
func MustParsePublicKey(b [PublicKeySize]byte) *PublicKey {
	key, err := ParsePublicKey(b)
	if err != nil {
		panic("eddsa: " + err.Error())
	}
	return key
}

// ParsePublicKeyDER parses a DER buffer into a public key.
func ParsePublicKeyDER(der []byte) (*PublicKey, error) {
	spki, err := asn1ext.ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return nil, err
	}
	if !spki.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("eddsa: not an Ed25519 public key")
	}
	if spki.SubjectPublicKey.BitLength != PublicKeySize*8 {
		return nil, errors.New("eddsa: invalid Ed25519 public key length")
	}
	if _, err := new(edwards25519.Point).SetBytes(spki.SubjectPublicKey.Bytes); err != nil {
		return nil, errors.New("eddsa: invalid Ed25519 public key")
	}
	return &PublicKey{key: spki.SubjectPublicKey.Bytes}, nil
}

// MustParsePublicKeyDER parses a DER buffer into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyDER(der []byte) *PublicKey {
	key, err := ParsePublicKeyDER(der)
	if err != nil {
		panic("eddsa: " + err.Error())
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
		return nil, errors.New("eddsa: invalid PEM type: " + kind)
	}
	return ParsePublicKeyDER(blob)
}

// MustParsePublicKeyPEM parses a PEM string into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyPEM(s string) *PublicKey {
	key, err := ParsePublicKeyPEM(s)
	if err != nil {
		panic("eddsa: " + err.Error())
	}
	return key
}

// Marshal converts a public key into a 32-byte array.
func (k *PublicKey) Marshal() [PublicKeySize]byte {
	var out [PublicKeySize]byte
	copy(out[:], k.key)
	return out
}

// MarshalDER serializes a public key into a DER buffer.
func (k *PublicKey) MarshalDER() []byte {
	der, err := x509.MarshalPKIXPublicKey(k.key)
	if err != nil {
		panic(err) // cannot fail for valid key
	}
	return der
}

// MarshalPEM serializes a public key into a PEM string.
func (k *PublicKey) MarshalPEM() string {
	return string(pem.Encode("PUBLIC KEY", k.MarshalDER()))
}

// MarshalText implements encoding.TextMarshaler.
func (k *PublicKey) MarshalText() ([]byte, error) {
	raw := k.Marshal()
	return []byte(base64.StdEncoding.EncodeToString(raw[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *PublicKey) UnmarshalText(text []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(raw) != PublicKeySize {
		return errors.New("eddsa: invalid public key length")
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
func (k *PublicKey) Fingerprint() [32]byte {
	raw := k.Marshal()
	return sha256.Sum256(raw[:])
}

// Verify verifies a digital signature.
func (k *PublicKey) Verify(message []byte, sig *Signature) error {
	if !ed25519.Verify(k.key, message, sig.inner[:]) {
		return errors.New("eddsa: signature verification failed")
	}
	return nil
}

// Signature contains an Ed25519 signature.
type Signature struct {
	inner [SignatureSize]byte
}

// ParseSignature converts a 64-byte array into a signature.
func ParseSignature(b [SignatureSize]byte) *Signature {
	return &Signature{inner: b}
}

// Marshal converts a signature into a 64-byte array.
func (s *Signature) Marshal() [SignatureSize]byte {
	return s.inner
}
