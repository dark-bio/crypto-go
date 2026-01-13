// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package xhpke provides X-Wing HPKE encryption.
//
// https://datatracker.ietf.org/doc/html/rfc9180
// https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem
package xhpke

import (
	"crypto/hpke"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"

	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/pem"
)

const (
	// InfoPrefix is the prefix for the info string used in HPKE operations,
	// binding the keys to the Dark Bio application context.
	InfoPrefix = "dark-bio-v1:"

	// SecretKeySize is the size of the secret key seed in bytes.
	SecretKeySize = 32

	// PublicKeySize is the size of the public key in bytes.
	PublicKeySize = 1216

	// EncapKeySize is the size of the encapsulated key in bytes.
	EncapKeySize = 1120
)

// OID is the ASN.1 object identifier for X-Wing.
var OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722}

// SecretKey contains an X-Wing private key for decrypting HPKE messages.
type SecretKey struct {
	inner hpke.PrivateKey
	seed  [SecretKeySize]byte
}

// GenerateKey creates a new, random private key.
func GenerateKey() *SecretKey {
	inner, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		panic(err) // cannot fail
	}
	keyBytes, err := inner.Bytes()
	if err != nil {
		panic(err) // cannot fail
	}
	var seed [SecretKeySize]byte
	copy(seed[:], keyBytes)
	return &SecretKey{
		inner: inner,
		seed:  seed,
	}
}

// ParseSecretKey converts a 32-byte seed into a private key.
func ParseSecretKey(seed [SecretKeySize]byte) *SecretKey {
	inner, err := hpke.MLKEM768X25519().NewPrivateKey(seed[:])
	if err != nil {
		panic(err) // cannot fail
	}
	return &SecretKey{
		inner: inner,
		seed:  seed,
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
		return nil, errors.New("xhpke: unsupported version")
	}
	// Ensure the algorithm OID matches X-Wing and extract the actual private key
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("xhpke: not an X-Wing private key")
	}
	if len(info.PrivateKey) != SecretKeySize {
		return nil, errors.New("xhpke: private key must be 32 bytes")
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
		panic("xhpke: " + err.Error())
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
		return nil, errors.New("xhpke: invalid PEM type: " + kind)
	}
	return ParseSecretKeyDER(blob)
}

// MustParseSecretKeyPEM parses a PEM string into a private key.
// It panics if the parsing fails.
func MustParseSecretKeyPEM(s string) *SecretKey {
	key, err := ParseSecretKeyPEM(s)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return key
}

// Marshal converts a secret key into a 32-byte seed.
func (k *SecretKey) Marshal() [SecretKeySize]byte {
	return k.seed
}

// MarshalDER serializes a private key into a DER buffer.
func (k *SecretKey) MarshalDER() []byte {
	// Create the X-Wing algorithm identifier; parameters MUST be absent
	// Per RFC, privateKey contains the raw 32-byte seed directly
	info := asn1ext.PKCS8PrivateKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: OID,
		},
		PrivateKey: k.seed[:],
	}
	der, err := asn1.Marshal(info)
	if err != nil {
		panic(err)
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
		inner: k.inner.PublicKey(),
	}
}

// Fingerprint returns a 256-bit unique identifier for this key.
func (k *SecretKey) Fingerprint() [32]byte {
	return k.PublicKey().Fingerprint()
}

// Open consumes a standalone cryptographic construct encrypted to this secret
// key. The method will deconstruct the given encapsulated key and ciphertext
// and will also verify the authenticity of the (unencrypted) message-to-auth
// (not included in the ciphertext).
//
// Note: X-Wing uses Base mode (no sender authentication). The sender's identity
// cannot be verified from the ciphertext alone.
func (k *SecretKey) Open(sessionKey *[EncapKeySize]byte, msgToOpen, msgToAuth, domain []byte) ([]byte, error) {
	info := append([]byte(InfoPrefix), domain...)

	// Create a receiver session using Base mode (X-Wing doesn't support Auth mode)
	recipient, err := hpke.NewRecipient(
		sessionKey[:],
		k.inner,
		hpke.HKDFSHA256(),
		hpke.ChaCha20Poly1305(),
		info,
	)
	if err != nil {
		return nil, err
	}
	// Verify the construct and decrypt the message if everything checks out
	return recipient.Open(msgToAuth, msgToOpen)
}

// PublicKey contains an X-Wing public key for encrypting HPKE messages.
type PublicKey struct {
	inner hpke.PublicKey
}

// ParsePublicKey converts a 1216-byte array into a public key.
func ParsePublicKey(b [PublicKeySize]byte) (*PublicKey, error) {
	inner, err := hpke.MLKEM768X25519().NewPublicKey(b[:])
	if err != nil {
		return nil, err
	}
	return &PublicKey{inner: inner}, nil
}

// MustParsePublicKey converts a 1216-byte array into a public key.
// It panics if the parsing fails.
func MustParsePublicKey(b [PublicKeySize]byte) *PublicKey {
	key, err := ParsePublicKey(b)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return key
}

// ParsePublicKeyDER parses a DER buffer into a public key.
func ParsePublicKeyDER(der []byte) (*PublicKey, error) {
	// Parse the DER encoded container
	info, err := asn1ext.ParseSubjectPublicKeyInfo(der)
	if err != nil {
		return nil, err
	}
	// Ensure the algorithm OID matches X-Wing and extract the actual public key
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, errors.New("xhpke: not an X-Wing public key")
	}
	keyBytes := info.SubjectPublicKey.Bytes
	if len(keyBytes) != PublicKeySize {
		return nil, errors.New("xhpke: public key must be 1216 bytes")
	}
	if info.SubjectPublicKey.BitLength != PublicKeySize*8 {
		return nil, errors.New("xhpke: public key BIT STRING must be byte-aligned")
	}
	// Public key extracted, return the wrapper
	var b [PublicKeySize]byte
	copy(b[:], keyBytes)
	return ParsePublicKey(b)
}

// MustParsePublicKeyDER parses a DER buffer into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyDER(der []byte) *PublicKey {
	key, err := ParsePublicKeyDER(der)
	if err != nil {
		panic("xhpke: " + err.Error())
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
		return nil, errors.New("xhpke: invalid PEM type: " + kind)
	}
	return ParsePublicKeyDER(blob)
}

// MustParsePublicKeyPEM parses a PEM string into a public key.
// It panics if the parsing fails.
func MustParsePublicKeyPEM(s string) *PublicKey {
	key, err := ParsePublicKeyPEM(s)
	if err != nil {
		panic("xhpke: " + err.Error())
	}
	return key
}

// Marshal converts a public key into a 1216-byte array.
func (k *PublicKey) Marshal() [PublicKeySize]byte {
	var out [PublicKeySize]byte
	copy(out[:], k.inner.Bytes())
	return out
}

// MarshalDER serializes a public key into a DER buffer.
func (k *PublicKey) MarshalDER() []byte {
	// The subject public key is simply the BITSTRING of the pubkey
	pubBytes := k.Marshal()

	// Create the X-Wing algorithm identifier; parameters MUST be absent
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

// MarshalText encodes the public key as base64 text.
func (k *PublicKey) MarshalText() ([]byte, error) {
	raw := k.Marshal()
	return []byte(base64.StdEncoding.EncodeToString(raw[:])), nil
}

// UnmarshalText decodes a base64-encoded public key.
func (k *PublicKey) UnmarshalText(text []byte) error {
	raw, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(raw) != PublicKeySize {
		return errors.New("xhpke: invalid public key length")
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

// Seal creates a standalone cryptographic construct encrypted to this public
// key. The construct will contain the given message-to-seal (encrypted) and
// also an authenticity proof for the (unencrypted) message-to-auth (message
// not included).
//
// The method returns the encapsulated session key and the ciphertext separately.
// To open it on the other side needs transmitting both components along with
// `msgToAuth`.
//
// Note: X-Wing uses Base mode (no sender authentication). The recipient cannot
// verify the sender's identity from the ciphertext alone.
func (k *PublicKey) Seal(msgToSeal, msgToAuth, domain []byte) ([EncapKeySize]byte, []byte, error) {
	info := append([]byte(InfoPrefix), domain...)

	// Create a sender session using Base mode (X-Wing doesn't support Auth mode)
	encapKey, sender, err := hpke.NewSender(
		k.inner,
		hpke.HKDFSHA256(),
		hpke.ChaCha20Poly1305(),
		info,
	)
	if err != nil {
		return [EncapKeySize]byte{}, nil, err
	}
	// Encrypt the messages and seal all the crypto details into a nice box
	enc, err := sender.Seal(msgToAuth, msgToSeal)
	if err != nil {
		return [EncapKeySize]byte{}, nil, err
	}
	var sessionKey [EncapKeySize]byte
	copy(sessionKey[:], encapKey)
	return sessionKey, enc, nil
}
