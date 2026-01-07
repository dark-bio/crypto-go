// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rsa provides RSA-2048-SHA256 signing and verification.
//
// https://datatracker.ietf.org/doc/html/rfc8017
package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"

	"github.com/dark-bio/crypto-go/pem"
)

const (
	// SecretKeySize is the size of the raw secret key in bytes.
	// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes)
	SecretKeySize = 520

	// PublicKeySize is the size of the raw public key in bytes.
	// Format: n (256 bytes) || e (8 bytes)
	PublicKeySize = 264

	// SignatureSize is the size of an RSA-2048 signature.
	SignatureSize = 256
)

// SecretKey contains a 2048-bit RSA private key usable for signing, with SHA256
// as the underlying hash algorithm.
type SecretKey struct {
	inner *rsa.PrivateKey
}

// GenerateKey creates a new, random private key.
func GenerateKey() *SecretKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("rsa: " + err.Error())
	}
	return &SecretKey{inner: key}
}

// ParseSecretKey parses a 520-byte array into a private key.
//
// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
// all in big-endian.
func ParseSecretKey(b [SecretKeySize]byte) (*SecretKey, error) {
	p := new(big.Int).SetBytes(b[0:128])
	q := new(big.Int).SetBytes(b[128:256])
	d := new(big.Int).SetBytes(b[256:512])
	e := new(big.Int).SetBytes(b[512:520])

	n := new(big.Int).Mul(p, q)

	// The modulus must be exactly 2048 bits
	if n.BitLen() != 2048 {
		return nil, errors.New("rsa: modulus must be 2048 bits")
	}
	// Whilst the RSA algorithm permits different exponents, every modern
	// system only ever uses 65537 and most also enforce this. Might as
	// well do the same.
	if e.Cmp(big.NewInt(65537)) != 0 {
		return nil, errors.New("rsa: exponent must be 65537")
	}
	// Construct the actual private key
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	key.Precompute()

	return &SecretKey{inner: key}, nil
}

// ParseSecretKeyDER parses a PKCS#8 DER-encoded private key.
func ParseSecretKeyDER(der []byte) (*SecretKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("rsa: not an RSA private key")
	}
	// The modulus must be exactly 2048 bits
	if rsaKey.N.BitLen() != 2048 {
		return nil, errors.New("rsa: modulus must be 2048 bits")
	}
	// The modulus must be odd (product of two odd primes)
	if rsaKey.N.Bit(0) == 0 {
		return nil, errors.New("rsa: modulus must be odd")
	}
	// Whilst the RSA algorithm permits different exponents, every modern
	// system only ever uses 65537 and most also enforce this. Might as
	// well do the same.
	if rsaKey.E != 65537 {
		return nil, errors.New("rsa: exponent must be 65537")
	}
	// Go's ASN1 parser permits unused trailing bytes, which may end up with a
	// weird interplay with the optional RSA CRT parameters (junk ignored). We
	// don't want to allow that, so just round trip the format and see if it's
	// matching or not.
	recoded, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(recoded, der) {
		return nil, errors.New("rsa: non-canonical DER encoding")
	}
	return &SecretKey{inner: rsaKey}, nil
}

// MustParseSecretKeyDER parses a PKCS#8 DER-encoded private key.
// It panics if the parsing fails.
func MustParseSecretKeyDER(der []byte) *SecretKey {
	key, err := ParseSecretKeyDER(der)
	if err != nil {
		panic("rsa: " + err.Error())
	}
	return key
}

// ParseSecretKeyPEM parses a PEM-encoded private key.
func ParseSecretKeyPEM(s string) (*SecretKey, error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	if kind != "PRIVATE KEY" {
		return nil, errors.New("rsa: invalid PEM type: " + kind)
	}
	return ParseSecretKeyDER(blob)
}

// MustParseSecretKeyPEM parses a PEM-encoded private key.
// It panics if the parsing fails.
func MustParseSecretKeyPEM(s string) *SecretKey {
	key, err := ParseSecretKeyPEM(s)
	if err != nil {
		panic("rsa: " + err.Error())
	}
	return key
}

// Marshal serializes the private key into a 520-byte array.
//
// Format: p (128 bytes) || q (128 bytes) || d (256 bytes) || e (8 bytes),
// all in big-endian.
func (k *SecretKey) Marshal() [SecretKeySize]byte {
	var out [SecretKeySize]byte

	pBytes := k.inner.Primes[0].Bytes()
	copy(out[128-len(pBytes):128], pBytes)

	qBytes := k.inner.Primes[1].Bytes()
	copy(out[256-len(qBytes):256], qBytes)

	dBytes := k.inner.D.Bytes()
	copy(out[512-len(dBytes):512], dBytes)

	eBytes := big.NewInt(int64(k.inner.E)).Bytes()
	copy(out[520-len(eBytes):520], eBytes)

	return out
}

// MarshalDER serializes the private key to PKCS#8 DER format.
func (k *SecretKey) MarshalDER() []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k.inner)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	return der
}

// MarshalPEM serializes the private key to PEM format.
func (k *SecretKey) MarshalPEM() string {
	return string(pem.Encode("PRIVATE KEY", k.MarshalDER()))
}

// PublicKey returns the public counterpart of the secret key.
func (k *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{inner: &k.inner.PublicKey}
}

// Fingerprint returns a 256-bit unique identifier for this key. For RSA, that
// is the SHA256 hash of the raw (le modulus || le exponent) public key.
func (k *SecretKey) Fingerprint() [32]byte {
	return k.PublicKey().Fingerprint()
}

// Sign creates a digital signature of the message using PKCS#1 v1.5.
func (k *SecretKey) Sign(message []byte) [SignatureSize]byte {
	hash := sha256.Sum256(message)
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.inner, crypto.SHA256, hash[:])
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	var out [SignatureSize]byte
	copy(out[:], sig)
	return out
}

// PublicKey contains a 2048-bit RSA public key usable for verification, with
// SHA256 as the underlying hash algorithm.
type PublicKey struct {
	inner *rsa.PublicKey
}

// ParsePublicKey parses a 264-byte array into a public key.
//
// Format: n (256 bytes) || e (8 bytes), all in big-endian.
func ParsePublicKey(b [PublicKeySize]byte) (*PublicKey, error) {
	n := new(big.Int).SetBytes(b[0:256])
	e := new(big.Int).SetBytes(b[256:264])

	// Validate that modulus and exponent are valid
	if n.Sign() <= 0 {
		return nil, errors.New("rsa: invalid modulus")
	}
	// The modulus must be exactly 2048 bits
	if n.BitLen() != 2048 {
		return nil, errors.New("rsa: modulus must be 2048 bits")
	}
	// The modulus must be odd (product of two odd primes)
	if n.Bit(0) == 0 {
		return nil, errors.New("rsa: modulus must be odd")
	}
	// Whilst the RSA algorithm permits different exponents, every modern
	// system only ever uses 65537 and most also enforce this. Might as
	// well do the same.
	if e.Cmp(big.NewInt(65537)) != 0 {
		return nil, errors.New("rsa: exponent must be 65537")
	}
	return &PublicKey{
		inner: &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		},
	}, nil
}

// ParsePublicKeyDER parses a PKIX DER-encoded public key.
func ParsePublicKeyDER(der []byte) (*PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("rsa: not an RSA public key")
	}
	// The modulus must be exactly 2048 bits
	if rsaKey.N.BitLen() != 2048 {
		return nil, errors.New("rsa: modulus must be 2048 bits")
	}
	// The modulus must be odd (product of two odd primes)
	if rsaKey.N.Bit(0) == 0 {
		return nil, errors.New("rsa: modulus must be odd")
	}
	// Whilst the RSA algorithm permits different exponents, every modern
	// system only ever uses 65537 and most also enforce this. Might as
	// well do the same.
	if rsaKey.E != 65537 {
		return nil, errors.New("rsa: exponent must be 65537")
	}
	return &PublicKey{inner: rsaKey}, nil
}

// MustParsePublicKeyDER parses a PKIX DER-encoded public key.
// It panics if the parsing fails.
func MustParsePublicKeyDER(der []byte) *PublicKey {
	key, err := ParsePublicKeyDER(der)
	if err != nil {
		panic("rsa: " + err.Error())
	}
	return key
}

// ParsePublicKeyPEM parses a PEM-encoded public key.
func ParsePublicKeyPEM(s string) (*PublicKey, error) {
	kind, blob, err := pem.Decode([]byte(s))
	if err != nil {
		return nil, err
	}
	if kind != "PUBLIC KEY" {
		return nil, errors.New("rsa: invalid PEM type: " + kind)
	}
	return ParsePublicKeyDER(blob)
}

// MustParsePublicKeyPEM parses a PEM-encoded public key.
// It panics if the parsing fails.
func MustParsePublicKeyPEM(s string) *PublicKey {
	key, err := ParsePublicKeyPEM(s)
	if err != nil {
		panic("rsa: " + err.Error())
	}
	return key
}

// Marshal serializes the public key into a 264-byte array.
//
// Format: n (256 bytes) || e (8 bytes), all in big-endian.
func (k *PublicKey) Marshal() [PublicKeySize]byte {
	var out [PublicKeySize]byte

	nBytes := k.inner.N.Bytes()
	copy(out[256-len(nBytes):256], nBytes)

	eBytes := big.NewInt(int64(k.inner.E)).Bytes()
	copy(out[264-len(eBytes):264], eBytes)

	return out
}

// MarshalDER serializes the public key to PKIX DER format.
func (k *PublicKey) MarshalDER() []byte {
	der, _ := x509.MarshalPKIXPublicKey(k.inner)
	return der
}

// MarshalPEM serializes the public key to PEM format.
func (k *PublicKey) MarshalPEM() string {
	return string(pem.Encode("PUBLIC KEY", k.MarshalDER()))
}

// Fingerprint returns a 256-bit unique identifier for this key. For RSA, that
// is the SHA256 hash of the raw (le modulus || le exponent) public key.
func (k *PublicKey) Fingerprint() [32]byte {
	modLE := reverseBytes(k.inner.N.Bytes())
	for len(modLE) < 256 {
		modLE = append(modLE, 0)
	}
	expLE := reverseBytes(big.NewInt(int64(k.inner.E)).Bytes())
	for len(expLE) < 8 {
		expLE = append(expLE, 0)
	}
	return sha256.Sum256(append(modLE, expLE...))
}

// Verify verifies a digital signature.
func (k *PublicKey) Verify(message []byte, signature [SignatureSize]byte) error {
	hash := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(k.inner, crypto.SHA256, hash[:], signature[:])
}

// VerifyHash verifies a digital signature on an already hashed message.
func (k *PublicKey) VerifyHash(hash []byte, signature [SignatureSize]byte) error {
	return rsa.VerifyPKCS1v15(k.inner, crypto.SHA256, hash, signature[:])
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
