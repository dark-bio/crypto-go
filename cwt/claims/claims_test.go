// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package claims

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// TestConfirmXDSA verifies round-trip encoding of a Confirm[*xdsa.PublicKey].
func TestConfirmXDSA(t *testing.T) {
	key := xdsa.GenerateKey().PublicKey()

	type token struct {
		Confirm[*xdsa.PublicKey]
	}
	orig := token{Confirm: NewConfirm(key)}

	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Key().Marshal() != key.Marshal() {
		t.Fatalf("xdsa key mismatch after round-trip")
	}
}

// TestConfirmXHPKE verifies round-trip encoding of a Confirm[*xhpke.PublicKey].
func TestConfirmXHPKE(t *testing.T) {
	key := xhpke.GenerateKey().PublicKey()

	type token struct {
		Confirm[*xhpke.PublicKey]
	}
	orig := token{Confirm: NewConfirm(key)}

	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Key().Marshal() != key.Marshal() {
		t.Fatalf("xhpke key mismatch after round-trip")
	}
}

// TestCompositeClaims verifies a struct embedding multiple claim types.
func TestCompositeClaims(t *testing.T) {
	key := xdsa.GenerateKey().PublicKey()

	type deviceCert struct {
		Subject
		Expiration
		NotBefore
		Confirm[*xdsa.PublicKey]
		UEID []byte `cbor:"256,key"`
	}
	orig := deviceCert{
		Subject:    Subject{Sub: "device-abc-123"},
		Expiration: Expiration{Exp: 1000000},
		NotBefore:  NotBefore{Nbf: 100},
		Confirm:    NewConfirm(key),
		UEID:       []byte("SN-12345"),
	}
	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got deviceCert
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Sub != orig.Sub {
		t.Fatalf("subject: got %q, want %q", got.Sub, orig.Sub)
	}
	if got.Exp != orig.Exp {
		t.Fatalf("exp: got %d, want %d", got.Exp, orig.Exp)
	}
	if got.Nbf != orig.Nbf {
		t.Fatalf("nbf: got %d, want %d", got.Nbf, orig.Nbf)
	}
	if got.Key().Marshal() != key.Marshal() {
		t.Fatalf("confirm key mismatch")
	}
	if !bytes.Equal(got.UEID, orig.UEID) {
		t.Fatalf("ueid: got %x, want %x", got.UEID, orig.UEID)
	}
}

// TestConfirmWrongKeyType tests that decoding a cnf with mismatched kty fails.
func TestConfirmWrongKeyType(t *testing.T) {
	key := xdsa.GenerateKey().PublicKey()

	type xdsaToken struct {
		Confirm[*xdsa.PublicKey]
	}
	type xhpkeToken struct {
		Confirm[*xhpke.PublicKey]
	}
	orig := xdsaToken{Confirm: NewConfirm(key)}
	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got xhpkeToken
	err = cbor.Unmarshal(data, &got)
	if !errors.Is(err, ErrInvalidKeyType) {
		t.Fatalf("expected ErrInvalidKeyType, got %v", err)
	}
}
