// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cose

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// fixtureCorpus holds shared fixtures pinning the COSE wire format.
type fixtureCorpus struct {
	// XdsaSeed is the hex encoded signing key seed.
	XdsaSeed string `json:"xdsa_seed"`
	// XhpkeSeed is the hex encoded encryption key seed.
	XhpkeSeed string `json:"xhpke_seed"`
	// Domain is the hex encoded application domain.
	Domain string `json:"domain"`
	// Payload is the hex encoded payload, signed as a CBOR byte string.
	Payload string `json:"payload"`
	// Aad is the hex encoded authenticated data, bound as a CBOR byte string.
	Aad string `json:"aad"`
	// Timestamp is the signature's Unix timestamp in seconds.
	Timestamp int64 `json:"timestamp"`
	// Sign1 is the hex encoded signed envelope.
	Sign1 string `json:"sign1"`
	// Encrypt0 is the hex encoded encrypted envelope.
	Encrypt0 string `json:"encrypt0"`
	// Padding records the sender's policy for padded fixtures.
	Padding struct {
		// Type names the padding policy.
		Type string `json:"type"`
		// Floor is the first bucket size in bytes.
		Floor int `json:"floor"`
		// Step is the divisor for bucket growth.
		Step int `json:"step"`
	} `json:"padding"`
	// PlaintextLength is the padded plaintext size in bytes.
	PlaintextLength int `json:"plaintext_length"`
}

// fixtures loads a named COSE fixture corpus.
func fixtures(t *testing.T, name string) *fixtureCorpus {
	t.Helper()

	blob, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("failed to read fixtures: %v", err)
	}
	corpus := new(fixtureCorpus)
	if err := json.Unmarshal(blob, corpus); err != nil {
		t.Fatalf("failed to parse fixtures: %v", err)
	}
	return corpus
}

// mustHex decodes a hex encoded fixture field.
func mustHex(t *testing.T, field string) []byte {
	t.Helper()

	blob, err := hex.DecodeString(field)
	if err != nil {
		t.Fatalf("failed to decode fixture field: %v", err)
	}
	return blob
}

// Tests that the v0.16 fixture corpus still validates, since that was in the
// first public release of the Ark, so we can't change the format anymore.
func TestV016Fixtures(t *testing.T) {
	fx := fixtures(t, "v0.16.json")

	var xdsaSeed [xdsa.SecretKeySize]byte
	copy(xdsaSeed[:], mustHex(t, fx.XdsaSeed))
	var xhpkeSeed [xhpke.SecretKeySize]byte
	copy(xhpkeSeed[:], mustHex(t, fx.XhpkeSeed))

	signer := xdsa.ParseSecretKey(xdsaSeed)
	recipient := xhpke.ParseSecretKey(xhpkeSeed)

	domain := mustHex(t, fx.Domain)
	payload := mustHex(t, fx.Payload)
	aad := mustHex(t, fx.Aad)
	sign1 := mustHex(t, fx.Sign1)
	encrypt0 := mustHex(t, fx.Encrypt0)

	// Verify the committed signature and check the embedded payload
	got, err := VerifyAt[[]byte](sign1, aad, signer.PublicKey(), domain, nil, 0)
	if err != nil {
		t.Fatalf("failed to verify fixture signature: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fixture signature payload mismatch")
	}
	// Wrong domains and tampered structures must fail
	if _, err := VerifyAt[[]byte](sign1, aad, signer.PublicKey(), []byte("wrong"), nil, 0); err == nil {
		t.Fatal("fixture signature verified with wrong domain")
	}
	tampered := bytes.Clone(sign1)
	tampered[len(tampered)-1] ^= 1
	if _, err := VerifyAt[[]byte](tampered, aad, signer.PublicKey(), domain, nil, 0); err == nil {
		t.Fatal("tampered fixture signature verified")
	}
	// Open the committed encrypted message and check the payload
	got, err = OpenAt[[]byte](encrypt0, aad, recipient, signer.PublicKey(), domain, nil, 0)
	if err != nil {
		t.Fatalf("failed to open fixture message: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fixture message payload mismatch")
	}
	tampered = bytes.Clone(encrypt0)
	tampered[len(tampered)-1] ^= 1
	if _, err := OpenAt[[]byte](tampered, aad, recipient, signer.PublicKey(), domain, nil, 0); err == nil {
		t.Fatal("tampered fixture message opened")
	}
}

// TestPaddedFixture opens the shared Rust fixture and checks its wire bytes,
// signature timestamp and payload.
func TestPaddedFixture(t *testing.T) {
	// This envelope was sealed once by crypto-rs with invented fixture data
	fx := fixtures(t, "padded.json")
	signer := xdsa.ParseSecretKey([xdsa.SecretKeySize]byte(mustHex(t, fx.XdsaSeed)))
	recipient := xhpke.ParseSecretKey([xhpke.SecretKeySize]byte(mustHex(t, fx.XhpkeSeed)))
	domain := mustHex(t, fx.Domain)
	aad := mustHex(t, fx.Aad)
	sign1 := mustHex(t, fx.Sign1)
	envelope := mustHex(t, fx.Encrypt0)

	// Pin the plaintext layout independently of the padding implementation
	if fx.Padding.Type != "buckets" || fx.Padding.Floor != 8192 || fx.Padding.Step != 20 {
		t.Fatalf("padding policy: %+v", fx.Padding)
	}
	if fx.PlaintextLength != 8192 {
		t.Fatalf("plaintext length: %d", fx.PlaintextLength)
	}
	plaintext := openPlaintext(t, envelope, aad, recipient, domain)
	if len(plaintext) != 8192 {
		t.Fatalf("plaintext length: %d", len(plaintext))
	}
	if !bytes.Equal(plaintext[:3470], sign1) {
		t.Fatal("fixture signature prefix mismatch")
	}
	if !bytes.Equal(plaintext[3470:], make([]byte, 4722)) {
		t.Fatal("fixture padding mismatch")
	}
	decrypted, err := Decrypt(envelope, aad, recipient, domain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, sign1) {
		t.Fatal("decrypted signature mismatch")
	}

	// Verify the fixed timestamp and read the signed payload
	if fx.Timestamp != 1700000000 {
		t.Fatalf("timestamp: %d", fx.Timestamp)
	}
	payload, err := OpenAt[[]byte](envelope, aad, recipient, signer.PublicKey(), domain, uptr(0), 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("padded cose fixture payload")) {
		t.Fatalf("payload: %q", payload)
	}
	if !bytes.Equal(payload, mustHex(t, fx.Payload)) {
		t.Fatal("fixture payload mismatch")
	}
}
