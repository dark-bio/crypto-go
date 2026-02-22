// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cwt

import (
	"errors"
	"testing"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/cose"
	"github.com/dark-bio/crypto-go/cwt/claims"
	"github.com/dark-bio/crypto-go/cwt/claims/eat"
	"github.com/dark-bio/crypto-go/xdsa"
)

// simpleCert is the minimal token type used by most tests.
type simpleCert struct {
	claims.Subject
	claims.Expiration
	claims.NotBefore
	claims.Confirm[*xdsa.PublicKey]
}

// deviceCert is a composite token type with EAT claims.
type deviceCert struct {
	claims.Subject
	claims.Expiration
	claims.NotBefore
	claims.Confirm[*xdsa.PublicKey]
	eat.UEID
}

func ptr(v uint64) *uint64 { return &v }

// TestIssueVerify tests the happy path: issue a token and verify it.
func TestIssueVerify(t *testing.T) {
	issuer := xdsa.GenerateKey()
	device := xdsa.GenerateKey()

	cert := &deviceCert{
		Subject:    claims.Subject{Sub: "device-abc"},
		Expiration: claims.Expiration{Exp: 2000000},
		NotBefore:  claims.NotBefore{Nbf: 1000000},
		Confirm:    claims.NewConfirm(device.PublicKey()),
		UEID:       eat.UEID{UEID: []byte("SN-999")},
	}
	token, err := Issue(cert, issuer, []byte("test-domain"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := Verify[deviceCert](token, issuer.PublicKey(), []byte("test-domain"), ptr(1500000))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Sub != "device-abc" {
		t.Fatalf("subject: got %q, want %q", got.Sub, "device-abc")
	}
	if got.Exp != 2000000 {
		t.Fatalf("exp: got %d, want 2000000", got.Exp)
	}
	if got.Key().Marshal() != device.PublicKey().Marshal() {
		t.Fatalf("confirm key mismatch")
	}
	if string(got.UEID.UEID) != "SN-999" {
		t.Fatalf("ueid: got %q, want %q", got.UEID.UEID, "SN-999")
	}
}

// TestVerifySkipTime tests that now=nil skips temporal validation.
func TestVerifySkipTime(t *testing.T) {
	issuer := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:   claims.Subject{Sub: "test"},
		NotBefore: claims.NotBefore{Nbf: 1000000},
		Confirm:   claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// now=nil should skip time checks entirely
	got, err := Verify[simpleCert](token, issuer.PublicKey(), []byte("test"), nil)
	if err != nil {
		t.Fatalf("verify with nil time should succeed: %v", err)
	}
	if got.Sub != "test" {
		t.Fatalf("subject: got %q, want %q", got.Sub, "test")
	}
}

// TestVerifyNotYetValid tests rejection when now < nbf.
func TestVerifyNotYetValid(t *testing.T) {
	issuer := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:   claims.Subject{Sub: "test"},
		NotBefore: claims.NotBefore{Nbf: 1000000},
		Confirm:   claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = Verify[simpleCert](token, issuer.PublicKey(), []byte("test"), ptr(500000))
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
}

// TestVerifyExpired tests rejection when now > exp.
func TestVerifyExpired(t *testing.T) {
	issuer := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:    claims.Subject{Sub: "test"},
		Expiration: claims.Expiration{Exp: 2000000},
		NotBefore:  claims.NotBefore{Nbf: 1000000},
		Confirm:    claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = Verify[simpleCert](token, issuer.PublicKey(), []byte("test"), ptr(3000000))
	if !errors.Is(err, ErrAlreadyExpired) {
		t.Fatalf("expected ErrAlreadyExpired, got %v", err)
	}
}

// TestVerifyMissingNbf tests rejection when nbf is absent and time check is on.
func TestVerifyMissingNbf(t *testing.T) {
	issuer := xdsa.GenerateKey()

	// Token type without NotBefore
	type noNbf struct {
		claims.Subject
		claims.Confirm[*xdsa.PublicKey]
	}
	cert := &noNbf{
		Subject: claims.Subject{Sub: "test"},
		Confirm: claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = Verify[noNbf](token, issuer.PublicKey(), []byte("test"), ptr(1000000))
	if !errors.Is(err, ErrMissingNbf) {
		t.Fatalf("expected ErrMissingNbf, got %v", err)
	}
}

// TestVerifyWrongKey tests rejection with wrong verifier key.
func TestVerifyWrongKey(t *testing.T) {
	issuer := xdsa.GenerateKey()
	wrong := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:   claims.Subject{Sub: "test"},
		NotBefore: claims.NotBefore{Nbf: 1000000},
		Confirm:   claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = Verify[simpleCert](token, wrong.PublicKey(), []byte("test"), ptr(1500000))
	if err == nil {
		t.Fatalf("expected error with wrong key, got nil")
	}
}

// TestSigner tests fingerprint extraction from a token.
func TestSigner(t *testing.T) {
	issuer := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:   claims.Subject{Sub: "test"},
		NotBefore: claims.NotBefore{Nbf: 1000000},
		Confirm:   claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	fp, err := Signer(token)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if fp != issuer.PublicKey().Fingerprint() {
		t.Fatalf("fingerprint mismatch: got %x, want %x", fp, issuer.PublicKey().Fingerprint())
	}
}

// TestPeek tests unauthenticated claims extraction.
func TestPeek(t *testing.T) {
	issuer := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:   claims.Subject{Sub: "peek-test"},
		NotBefore: claims.NotBefore{Nbf: 1000000},
		Confirm:   claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := Peek[simpleCert](token)
	if err != nil {
		t.Fatalf("peek: %v", err)
	}
	if got.Sub != "peek-test" {
		t.Fatalf("subject: got %q, want %q", got.Sub, "peek-test")
	}
}

// TestVerifyWrongDomain tests rejection when the verification domain differs.
func TestVerifyWrongDomain(t *testing.T) {
	issuer := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:   claims.Subject{Sub: "test"},
		NotBefore: claims.NotBefore{Nbf: 1000000},
		Confirm:   claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("domain-a"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	_, err = Verify[simpleCert](token, issuer.PublicKey(), []byte("domain-b"), ptr(1500000))
	if err == nil {
		t.Fatalf("expected error with wrong domain, got nil")
	}
}

// TestVerifyBoundaryExact tests that now == nbf passes and now == exp fails per RFC 8392.
func TestVerifyBoundaryExact(t *testing.T) {
	issuer := xdsa.GenerateKey()

	cert := &simpleCert{
		Subject:    claims.Subject{Sub: "test"},
		Expiration: claims.Expiration{Exp: 2000000},
		NotBefore:  claims.NotBefore{Nbf: 1000000},
		Confirm:    claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// now == nbf should pass
	if _, err := Verify[simpleCert](token, issuer.PublicKey(), []byte("test"), ptr(1000000)); err != nil {
		t.Fatalf("now == nbf should pass: %v", err)
	}
	// now == exp should fail (exp is "on or after which the token MUST NOT be accepted")
	if _, err := Verify[simpleCert](token, issuer.PublicKey(), []byte("test"), ptr(2000000)); !errors.Is(err, ErrAlreadyExpired) {
		t.Fatalf("now == exp should fail with ErrAlreadyExpired, got %v", err)
	}
}

// TestVerifyNoExpiration tests that a token without exp passes time validation.
func TestVerifyNoExpiration(t *testing.T) {
	issuer := xdsa.GenerateKey()

	type noExp struct {
		claims.Subject
		claims.NotBefore
		claims.Confirm[*xdsa.PublicKey]
	}
	cert := &noExp{
		Subject:   claims.Subject{Sub: "test"},
		NotBefore: claims.NotBefore{Nbf: 1000000},
		Confirm:   claims.NewConfirm(xdsa.GenerateKey().PublicKey()),
	}
	token, err := Issue(cert, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Should pass even far in the future since there's no exp
	if _, err := Verify[noExp](token, issuer.PublicKey(), []byte("test"), ptr(99999999)); err != nil {
		t.Fatalf("no exp should pass: %v", err)
	}
}

// TestVerifyDuplicateNbf tests that duplicate temporal claim keys are rejected.
func TestVerifyDuplicateNbf(t *testing.T) {
	issuer := xdsa.GenerateKey()

	// Manually construct a CBOR map with duplicate nbf (key 5)
	enc := cbor.NewEncoder()
	enc.EncodeMapHeader(3)
	enc.EncodeInt(2)
	if err := enc.EncodeText("test"); err != nil {
		t.Fatalf("encode text: %v", err)
	}
	enc.EncodeInt(5)
	enc.EncodeUint(1000000)
	enc.EncodeInt(5) // duplicate nbf
	enc.EncodeUint(2000000)

	// Sign the raw payload via COSE (bypassing CWT's encoder)
	token, err := cose.Sign(cbor.Raw(enc.Bytes()), cbor.Null{}, issuer, []byte("test"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Verify should fail with ErrDuplicateKey before claims decoding
	_, err = Verify[simpleCert](token, issuer.PublicKey(), []byte("test"), ptr(1500000))
	if !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("expected ErrDuplicateKey, got %v", err)
	}
}
