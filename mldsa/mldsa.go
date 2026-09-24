// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mldsa provides ML-DSA-65 digital signatures.
//
// https://datatracker.ietf.org/doc/html/rfc9881
//
// ML-DSA-65 on its own, the post-quantum half of the composite scheme in the
// xdsa package. Signing takes a context string that verification must repeat.
// Contexts may contain 0 to 255 bytes.
package mldsa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/internal/asn1ext"
	"github.com/dark-bio/crypto-go/internal/base64ext"
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

	// FingerprintSize is the size of a fingerprint in bytes.
	FingerprintSize = 32
)

// OID is the ASN.1 object identifier for ML-DSA-65.
var OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

var (
	// ErrUnexpectedPemTag is returned by ParseSecretKeyPEM and ParsePublicKeyPEM
	// when the PEM block type is not "PRIVATE KEY" or "PUBLIC KEY" respectively.
	// The wrapping error carries the type found.
	ErrUnexpectedPemTag = errors.New("mldsa: invalid PEM tag")

	// ErrUnexpectedAlgorithm is returned by the DER parsers, and through them by
	// the PEM parsers, when the key names an algorithm other than ML-DSA-65.
	ErrUnexpectedAlgorithm = errors.New("mldsa: not an ML-DSA-65 key")

	// ErrMalformedKey is returned by the DER and PEM parsers when a key encoding
	// cannot be parsed or its contents are unusable. Causes include wrong seed
	// or key sizes, an expanded key that does not match its seed, unexpected
	// algorithm parameters or an unsupported PKCS#8 version. The byte
	// constructors cannot fail, and the wrapping error names the problem.
	ErrMalformedKey = errors.New("mldsa: malformed key")

	// ErrTrailingData is returned by the DER parsers, and through them by the
	// PEM parsers, when bytes follow the key structure or its last field.
	ErrTrailingData = errors.New("mldsa: trailing data in key encoding")

	// ErrInvalidSignature is returned by PublicKey.Verify when the signature
	// does not verify under the key for the message and context, or it is not
	// a well formed ML-DSA-65 signature at all.
	ErrInvalidSignature = errors.New("mldsa: signature verification failed")
)

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
		if errors.Is(err, asn1ext.ErrTrailingData) {
			return nil, ErrTrailingData
		}
		return nil, fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	if info.Version != 0 {
		return nil, fmt.Errorf("%w: unsupported PKCS#8 version", ErrMalformedKey)
	}
	// Ensure the algorithm OID matches ML_DSA_65 (OID: 2.16.840.1.101.3.4.3.18)
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, ErrUnexpectedAlgorithm
	}
	// Ensure no algorithm parameters are present, none are allowed
	if len(info.Algorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: unexpected algorithm parameters", ErrMalformedKey)
	}
	// Wrap the private key in a SEQUENCE containing:
	//   - OCTET STRING (32 bytes): seed
	//   - OCTET STRING (4032 bytes): expanded key
	input := cryptobyte.String(info.PrivateKey)

	var inner cryptobyte.String
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("%w: invalid private key structure", ErrMalformedKey)
	}
	var seedBytes cryptobyte.String
	if !inner.ReadASN1(&seedBytes, cbasn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: invalid seed encoding", ErrMalformedKey)
	}
	if len(seedBytes) != SecretKeySize {
		return nil, fmt.Errorf("%w: seed must be 32 bytes", ErrMalformedKey)
	}
	var expandedBytes cryptobyte.String
	if !inner.ReadASN1(&expandedBytes, cbasn1.OCTET_STRING) || !inner.Empty() {
		return nil, fmt.Errorf("%w: invalid expanded key encoding", ErrMalformedKey)
	}
	if len(expandedBytes) != 4032 {
		return nil, fmt.Errorf("%w: expanded key must be 4032 bytes", ErrMalformedKey)
	}
	// Generate key from seed and validate it matches the expanded key in DER
	var seed [SecretKeySize]byte
	copy(seed[:], seedBytes)

	_, key := mldsa65.NewKeyFromSeed(&seed)
	expanded, _ := key.MarshalBinary()
	for i := range expanded {
		if expanded[i] != expandedBytes[i] {
			return nil, fmt.Errorf("%w: expanded key does not match seed", ErrMalformedKey)
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
		return nil, fmt.Errorf("%w %s", ErrUnexpectedPemTag, kind)
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
func (k *SecretKey) Fingerprint() Fingerprint {
	return k.PublicKey().Fingerprint()
}

// Sign creates a digital signature of the message with an optional context
// string. Pass an empty slice for no context. Verification must use the same
// bytes, and the context must not exceed 255 bytes.
func (k *SecretKey) Sign(message []byte, ctx []byte) (*Signature, error) {
	var sig Signature
	mldsa65.SignTo(k.key, message, ctx, false, sig[:])
	return &sig, nil
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
		if errors.Is(err, asn1ext.ErrTrailingData) {
			return nil, ErrTrailingData
		}
		return nil, fmt.Errorf("%w: %v", ErrMalformedKey, err)
	}
	if !info.Algorithm.Algorithm.Equal(OID) {
		return nil, ErrUnexpectedAlgorithm
	}
	// Ensure no algorithm parameters are present, none are allowed
	if len(info.Algorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("%w: unexpected algorithm parameters", ErrMalformedKey)
	}
	keyBytes := info.SubjectPublicKey.Bytes
	if len(keyBytes) != PublicKeySize {
		return nil, fmt.Errorf("%w: public key must be 1952 bytes", ErrMalformedKey)
	}
	if info.SubjectPublicKey.BitLength != PublicKeySize*8 {
		return nil, fmt.Errorf("%w: public key BIT STRING must be byte-aligned", ErrMalformedKey)
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
		return nil, fmt.Errorf("%w %s", ErrUnexpectedPemTag, kind)
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

// MarshalText implements encoding.TextMarshaler.
func (k *PublicKey) MarshalText() ([]byte, error) {
	raw := k.Marshal()
	return []byte(base64.StdEncoding.EncodeToString(raw[:])), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *PublicKey) UnmarshalText(text []byte) error {
	raw, err := base64ext.DecodeString(string(text))
	if err != nil {
		return err
	}
	if len(raw) != PublicKeySize {
		return errors.New("mldsa: invalid public key length")
	}
	var b [PublicKeySize]byte
	copy(b[:], raw)
	*k = *ParsePublicKey(b)
	return nil
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
func (k *PublicKey) Fingerprint() Fingerprint {
	raw := k.Marshal()
	return Fingerprint(sha256.Sum256(raw[:]))
}

// MarshalCBOR implements cbor.Marshaler.
func (k *PublicKey) MarshalCBOR(enc *cbor.Encoder) error {
	b := k.Marshal()
	enc.EncodeBytes(b[:])
	return nil
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (k *PublicKey) UnmarshalCBOR(dec *cbor.Decoder) error {
	b, err := dec.DecodeBytesFixed(PublicKeySize)
	if err != nil {
		return err
	}
	*k = *ParsePublicKey([PublicKeySize]byte(b))
	return nil
}

// Verify verifies a digital signature with an optional context string. The
// context must match the one used for signing. A context longer than 255 bytes
// is rejected with ErrInvalidSignature.
func (k *PublicKey) Verify(message []byte, ctx []byte, sig *Signature) error {
	if !mldsa65.Verify(k.key, message, ctx, sig[:]) {
		return ErrInvalidSignature
	}
	return nil
}

// Signature contains an ML-DSA-65 signature.
type Signature [SignatureSize]byte

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
		return errors.New("mldsa: invalid signature length")
	}
	copy(s[:], raw)
	return nil
}

// Fingerprint is a 256-bit unique identifier for an ML-DSA-65 key.
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
		return errors.New("mldsa: invalid fingerprint length")
	}
	copy(f[:], raw)
	return nil
}

// Signer is an interface to allow integrating ML-DSA signatures more tightly
// into other constructs without tying it to an in-memory private key.
type Signer interface {
	// Sign signs the message and returns the signature.
	Sign(message []byte, ctx []byte) (*Signature, error)
}
