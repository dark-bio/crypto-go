// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cwt

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dark-bio/crypto-go/cwt/claims"
	"github.com/dark-bio/crypto-go/xdsa"
)

// noExpCert is the fixture token type without an expiration claim.
type noExpCert struct {
	claims.Subject
	claims.NotBefore
	claims.Confirm[*xdsa.PublicKey]
}

// fixtureCorpus is the v0.16 fixture corpus pinning the CWT wire format.
type fixtureCorpus struct {
	// XdsaSeed is the hex-encoded signing key seed.
	XdsaSeed string `json:"xdsa_seed"`
	// Domain is the hex-encoded application domain.
	Domain string `json:"domain"`
	// Now is the Unix reference timestamp in seconds.
	Now uint64 `json:"now"`
	// Valid is the hex-encoded valid token fixture.
	Valid string `json:"valid"`
	// Expired is the hex-encoded expired token fixture.
	Expired string `json:"expired"`
	// Premature is the hex-encoded not-yet-valid token fixture.
	Premature string `json:"premature"`
}

// fixtures loads the v0.16 fixture corpus.
func fixtures(t *testing.T) *fixtureCorpus {
	t.Helper()

	blob, err := os.ReadFile(filepath.Join("testdata", "v0.16.json"))
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

// TestV016Fixtures checks that the committed v0.16 CWT fixtures still verify
// and enforce their temporal bounds, pinning wire compatibility across releases.
func TestV016Fixtures(t *testing.T) {
	fx := fixtures(t)

	var xdsaSeed [xdsa.SecretKeySize]byte
	copy(xdsaSeed[:], mustHex(t, fx.XdsaSeed))
	signer := xdsa.ParseSecretKey(xdsaSeed)

	domain := mustHex(t, fx.Domain)
	now := fx.Now

	// Verify the committed valid token and check the decoded claims
	valid := mustHex(t, fx.Valid)
	got, err := Verify[simpleCert](valid, signer.PublicKey(), domain, &now)
	if err != nil {
		t.Fatalf("failed to verify fixture token: %v", err)
	}
	if got.Sub != "fixture" {
		t.Fatalf("fixture subject mismatch: have %s, want fixture", got.Sub)
	}
	if got.Exp != 4102444800 {
		t.Fatalf("fixture expiration mismatch: have %d, want 4102444800", got.Exp)
	}
	if got.Nbf != 1500000000 {
		t.Fatalf("fixture not-before mismatch: have %d, want 1500000000", got.Nbf)
	}
	if got.Confirm.Key().Marshal() != signer.PublicKey().Marshal() {
		t.Fatal("fixture confirm key mismatch")
	}
	// The expired and premature tokens must keep failing temporally
	expired := mustHex(t, fx.Expired)
	if _, err := Verify[simpleCert](expired, signer.PublicKey(), domain, &now); !errors.Is(err, ErrAlreadyExpired) {
		t.Fatalf("expired fixture token: have %v, want ErrAlreadyExpired", err)
	}
	premature := mustHex(t, fx.Premature)
	if _, err := Verify[noExpCert](premature, signer.PublicKey(), domain, &now); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("premature fixture token: have %v, want ErrNotYetValid", err)
	}
	// A tampered token must fail the signature check
	tampered := append([]byte{}, valid...)
	tampered[len(tampered)-1] ^= 1
	if _, err := Verify[simpleCert](tampered, signer.PublicKey(), domain, &now); err == nil {
		t.Fatal("tampered fixture token verified")
	}
}
