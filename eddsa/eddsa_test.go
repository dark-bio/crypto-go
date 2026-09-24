// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eddsa

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dark-bio/crypto-go/internal/jsonext"
	"github.com/dark-bio/crypto-go/pem"
)

// Test vectors from RFC 8410 Sections 10.1 and 10.3
// https://datatracker.ietf.org/doc/html/rfc8410
var ietfVectors = struct {
	SecretKeySeed  string // 32-byte seed hex
	SecretKeyPEM   string // PKCS#8 v1 PEM
	SecretKeyV2PEM string // PKCS#8 v2 PEM with attribute and embedded public key
	PublicKeyPEM   string // SPKI PEM
}{
	SecretKeySeed: "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842",
	SecretKeyPEM: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----`,
	SecretKeyV2PEM: `-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----`,
	PublicKeyPEM: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PUBLIC KEY-----`,
}

// Tests operations with IETF test vectors: the private key must parse into
// the published raw seed, re-encode into the published PEM and DER, and
// derive the RFC's matching public key.
func TestIETFVectors(t *testing.T) {
	// Round trip the secret key pem and verify the expected seed
	key, err := ParseSecretKeyPEM(ietfVectors.SecretKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}
	keyBytes := key.Marshal()
	if hex.EncodeToString(keyBytes[:]) != ietfVectors.SecretKeySeed {
		t.Fatalf("seed mismatch: have %x, want %s", keyBytes, ietfVectors.SecretKeySeed)
	}
	if strings.TrimSpace(key.MarshalPEM()) != strings.TrimSpace(ietfVectors.SecretKeyPEM) {
		t.Fatal("private key PEM re-encoding mismatch")
	}
	// Round trip the secret key der
	_, der, err := pem.Decode([]byte(ietfVectors.SecretKeyPEM))
	if err != nil {
		t.Fatalf("failed to decode PEM: %v", err)
	}
	if !bytes.Equal(key.MarshalDER(), der) {
		t.Fatal("private key DER re-encoding mismatch")
	}
	// Verify the expected public key
	if strings.TrimSpace(key.PublicKey().MarshalPEM()) != strings.TrimSpace(ietfVectors.PublicKeyPEM) {
		t.Fatal("derived public key PEM mismatch")
	}
	// Round trip the public key pem
	pub, err := ParsePublicKeyPEM(ietfVectors.PublicKeyPEM)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	if strings.TrimSpace(pub.MarshalPEM()) != strings.TrimSpace(ietfVectors.PublicKeyPEM) {
		t.Fatal("public key PEM re-encoding mismatch")
	}
	// Round trip the public key der
	_, der, err = pem.Decode([]byte(ietfVectors.PublicKeyPEM))
	if err != nil {
		t.Fatalf("failed to decode PEM: %v", err)
	}
	if !bytes.Equal(pub.MarshalDER(), der) {
		t.Fatal("public key DER re-encoding mismatch")
	}
}

// Tests that the RFC 8410 v2 private key vector carrying an attribute and an
// embedded public key is rejected: only v1 keys without embedded public data
// are supported.
func TestIETFV2Rejected(t *testing.T) {
	if _, err := ParseSecretKeyPEM(ietfVectors.SecretKeyV2PEM); err == nil {
		t.Fatal("expected v2 private key with attributes to be rejected")
	}
}

// Tests signing and verifying messages. Note, this test is not meant to test
// cryptography, it is mostly an API sanity check to verify that everything
// seems to work.
func TestSignVerify(t *testing.T) {
	secret := GenerateKey()
	public := secret.PublicKey()

	message := []byte("message to authenticate")
	signature, _ := secret.Sign(message)

	if err := public.Verify(message, signature); err != nil {
		t.Fatalf("failed to verify message: %v", err)
	}
	// Verify wrong message fails
	if err := public.Verify([]byte("wrong message"), signature); err == nil {
		t.Fatal("expected verification to fail for wrong message")
	}
}

// Tests that a public key whose algorithm identifier carries parameters is
// rejected.
func TestPublicKeyDERRejectsParams(t *testing.T) {
	// Rebuild a valid public key with injected NULL algorithm parameters
	der := GenerateKey().PublicKey().MarshalDER()

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		t.Fatalf("failed to parse valid public key: %v", err)
	}
	spki.Algorithm.Parameters = asn1.RawValue{Tag: asn1.TagNull}
	badDER, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatalf("failed to marshal tampered public key: %v", err)
	}
	if _, err := ParsePublicKeyDER(badDER); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("params-carrying key not rejected: %v", err)
	}
}

// Tests that a private key whose algorithm identifier carries parameters is
// rejected.
func TestSecretKeyDERRejectsParams(t *testing.T) {
	// Rebuild a valid private key with NULL algorithm parameters spliced in
	der := GenerateKey().MarshalDER()
	long := der[1] == 0x82
	algidPos := 5
	if long {
		algidPos = 7
	}
	algidLen := int(der[algidPos+1])
	oidPos := algidPos + 2
	oidLen := 2 + int(der[oidPos+1])
	afterOID := oidPos + oidLen

	bad := make([]byte, 0, len(der)+2)
	bad = append(bad, der[:afterOID]...)
	bad = append(bad, 0x05, 0x00)
	bad = append(bad, der[afterOID:]...)
	bad[algidPos+1] = byte(algidLen + 2)
	if long {
		grown := (int(der[2])<<8 | int(der[3])) + 2
		bad[2] = byte(grown >> 8)
		bad[3] = byte(grown & 0xff)
	} else {
		bad[1] = byte(int(der[1]) + 2)
	}

	if _, err := ParseSecretKeyDER(bad); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("params-carrying private key not rejected: %v", err)
	}
}

// Tests that the text-encoded types marshal to the same JSON strings by value
// and by pointer, round-trip through them, and reject null unless the target
// is a pointer.
func TestJSON(t *testing.T) {
	secret := GenerateKey()
	signature, err := secret.Sign([]byte("message"))
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	fingerprint := secret.PublicKey().Fingerprint()

	blob, err := json.Marshal(struct {
		Key *PublicKey
		Sig *Signature
		Fp  *Fingerprint
	}{secret.PublicKey(), signature, &fingerprint})
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	byValue, err := json.Marshal(struct {
		Key PublicKey
		Sig Signature
		Fp  Fingerprint
	}{*secret.PublicKey(), *signature, fingerprint})
	if err != nil {
		t.Fatalf("failed to marshal by value: %v", err)
	}
	if string(byValue) != string(blob) {
		t.Fatalf("marshal by value = %s, want %s", byValue, blob)
	}
	var back struct {
		Key PublicKey
		Sig Signature
		Fp  Fingerprint
	}
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if back.Key.Marshal() != secret.PublicKey().Marshal() || back.Sig != *signature || back.Fp != fingerprint {
		t.Fatalf("round trip mismatch")
	}
	tests := []struct {
		name   string
		target any
	}{
		{name: "public key", target: new(PublicKey)},
		{name: "signature", target: new(Signature)},
		{name: "fingerprint", target: new(Fingerprint)},
	}
	for _, tt := range tests {
		if err := json.Unmarshal([]byte("null"), tt.target); !errors.Is(err, jsonext.ErrNull) {
			t.Error(tt.name)
		}
	}
	var key *PublicKey
	if err := json.Unmarshal([]byte("null"), &key); err != nil || key != nil {
		t.Fatalf("null into a pointer = %v, %v, want nil, nil", key, err)
	}
}
