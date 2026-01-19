// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cose

import (
	"fmt"
	"testing"
	"time"

	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

type testPayload struct {
	_   struct{} `cbor:"_,array"`
	Num uint64
	Str string
}

type testAAD struct {
	_   struct{} `cbor:"_,array"`
	Str string
}

// Tests various combinations of signing and verifying ops.
func TestSignVerify(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		msgToSign         testPayload
		msgToAuth         testAAD
		verifierMsgToAuth testAAD
		domain            []byte
		verifierDomain    []byte
		timestamp         *int64
		maxDrift          *uint64
		wrongKey          bool
		wantOK            bool
	}{
		// Valid signature with aad
		{
			msgToSign:         testPayload{Num: 1, Str: "foo"},
			msgToAuth:         testAAD{Str: "bar"},
			verifierMsgToAuth: testAAD{Str: "bar"},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            true,
		},
		// Valid signature, empty aad
		{
			msgToSign:         testPayload{Num: 2, Str: "foobar"},
			msgToAuth:         testAAD{Str: ""},
			verifierMsgToAuth: testAAD{Str: ""},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            true,
		},
		// Valid signature with explicit timestamp, no drift check
		{
			msgToSign:         testPayload{Num: 3, Str: "foo"},
			msgToAuth:         testAAD{Str: "bar"},
			verifierMsgToAuth: testAAD{Str: "bar"},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         ptr(now),
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            true,
		},
		// Valid signature within drift tolerance
		{
			msgToSign:         testPayload{Num: 4, Str: "foo"},
			msgToAuth:         testAAD{Str: "bar"},
			verifierMsgToAuth: testAAD{Str: "bar"},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         ptr(now - 30),
			maxDrift:          uptr(60),
			wrongKey:          false,
			wantOK:            true,
		},
		// Wrong domain
		{
			msgToSign:         testPayload{Num: 5, Str: "foo"},
			msgToAuth:         testAAD{Str: "bar"},
			verifierMsgToAuth: testAAD{Str: "bar"},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz2"),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            false,
		},
		// Wrong aad
		{
			msgToSign:         testPayload{Num: 6, Str: "foo!"},
			msgToAuth:         testAAD{Str: "bar"},
			verifierMsgToAuth: testAAD{Str: "baz"},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            false,
		},
		// Wrong key
		{
			msgToSign:         testPayload{Num: 7, Str: "foo!"},
			msgToAuth:         testAAD{Str: ""},
			verifierMsgToAuth: testAAD{Str: ""},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          true,
			wantOK:            false,
		},
		// Timestamp too far in the past
		{
			msgToSign:         testPayload{Num: 8, Str: "foo"},
			msgToAuth:         testAAD{Str: "bar"},
			verifierMsgToAuth: testAAD{Str: "bar"},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         ptr(now - 120),
			maxDrift:          uptr(60),
			wrongKey:          false,
			wantOK:            false,
		},
		// Timestamp too far in the future
		{
			msgToSign:         testPayload{Num: 9, Str: "foo"},
			msgToAuth:         testAAD{Str: "bar"},
			verifierMsgToAuth: testAAD{Str: "bar"},
			domain:            []byte("baz"),
			verifierDomain:    []byte("baz"),
			timestamp:         ptr(now + 120),
			maxDrift:          uptr(60),
			wrongKey:          false,
			wantOK:            false,
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			alice := xdsa.GenerateKey()
			bobby := xdsa.GenerateKey()

			var signed []byte
			var err error
			if tt.timestamp != nil {
				signed, err = SignAt(&tt.msgToSign, &tt.msgToAuth, alice, tt.domain, *tt.timestamp)
			} else {
				signed, err = Sign(&tt.msgToSign, &tt.msgToAuth, alice, tt.domain)
			}
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			verifier := alice.PublicKey()
			if tt.wrongKey {
				verifier = bobby.PublicKey()
			}

			recovered, err := Verify[testPayload](signed, &tt.verifierMsgToAuth, verifier, tt.verifierDomain, tt.maxDrift)

			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected success, have error: %v", err)
				}
				if recovered.Num != tt.msgToSign.Num || recovered.Str != tt.msgToSign.Str {
					t.Fatalf("payload mismatch: have %+v, want %+v", recovered, tt.msgToSign)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, have success")
				}
			}
		})
	}
}

// Tests various combinations of sealing and opening ops.
func TestSealOpen(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		msgToSeal       testPayload
		msgToAuth       testAAD
		openerMsgToAuth testAAD
		domain          []byte
		openerDomain    []byte
		timestamp       *int64
		maxDrift        *uint64
		wrongSigner     bool
		wantOK          bool
	}{
		// Valid seal/open with aad
		{
			msgToSeal:       testPayload{Num: 1, Str: "foo"},
			msgToAuth:       testAAD{Str: "bar"},
			openerMsgToAuth: testAAD{Str: "bar"},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          true,
		},
		// Valid seal/open, empty aad
		{
			msgToSeal:       testPayload{Num: 2, Str: "foo"},
			msgToAuth:       testAAD{Str: ""},
			openerMsgToAuth: testAAD{Str: ""},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          true,
		},
		// Valid seal/open, no drift check
		{
			msgToSeal:       testPayload{Num: 3, Str: "foo"},
			msgToAuth:       testAAD{Str: "bar"},
			openerMsgToAuth: testAAD{Str: "bar"},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       ptr(now),
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          true,
		},
		// Valid seal/open, valid drift
		{
			msgToSeal:       testPayload{Num: 4, Str: "foo"},
			msgToAuth:       testAAD{Str: "bar"},
			openerMsgToAuth: testAAD{Str: "bar"},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       ptr(now - 30),
			maxDrift:        uptr(60),
			wrongSigner:     false,
			wantOK:          true,
		},
		// Wrong domain
		{
			msgToSeal:       testPayload{Num: 5, Str: "foo"},
			msgToAuth:       testAAD{Str: ""},
			openerMsgToAuth: testAAD{Str: ""},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz2"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          false,
		},
		// Wrong aad
		{
			msgToSeal:       testPayload{Num: 6, Str: "foo"},
			msgToAuth:       testAAD{Str: "bar"},
			openerMsgToAuth: testAAD{Str: "bar2"},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          false,
		},
		// Wrong signer
		{
			msgToSeal:       testPayload{Num: 7, Str: "foo"},
			msgToAuth:       testAAD{Str: ""},
			openerMsgToAuth: testAAD{Str: ""},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     true,
			wantOK:          false,
		},
		// Timestamp too far in the past
		{
			msgToSeal:       testPayload{Num: 8, Str: "foo"},
			msgToAuth:       testAAD{Str: "bar"},
			openerMsgToAuth: testAAD{Str: "bar"},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       ptr(now - 120),
			maxDrift:        uptr(60),
			wrongSigner:     false,
			wantOK:          false,
		},
		// Timestamp too far in the future
		{
			msgToSeal:       testPayload{Num: 9, Str: "foo"},
			msgToAuth:       testAAD{Str: "bar"},
			openerMsgToAuth: testAAD{Str: "bar"},
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       ptr(now + 120),
			maxDrift:        uptr(60),
			wrongSigner:     false,
			wantOK:          false,
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			alice := xdsa.GenerateKey()
			bobby := xdsa.GenerateKey()
			carol := xhpke.GenerateKey()

			var sealed []byte
			var err error
			if tt.timestamp != nil {
				sealed, err = SealAt(&tt.msgToSeal, &tt.msgToAuth, alice, carol.PublicKey(), tt.domain, *tt.timestamp)
			} else {
				sealed, err = Seal(&tt.msgToSeal, &tt.msgToAuth, alice, carol.PublicKey(), tt.domain)
			}
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}

			verifier := alice.PublicKey()
			if tt.wrongSigner {
				verifier = bobby.PublicKey()
			}

			recovered, err := Open[testPayload](sealed, &tt.openerMsgToAuth, carol, verifier, tt.openerDomain, tt.maxDrift)

			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected success, have error: %v", err)
				}
				if recovered.Num != tt.msgToSeal.Num || recovered.Str != tt.msgToSeal.Str {
					t.Fatalf("payload mismatch: have %+v, want %+v", recovered, tt.msgToSeal)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, have success")
				}
			}
		})
	}
}

// Tests detached signing and verification.
func TestSignVerifyDetached(t *testing.T) {
	alice := xdsa.GenerateKey()
	bobby := xdsa.GenerateKey()

	msg := testAAD{Str: "hello detached"}

	signed, err := SignDetached(&msg, alice, []byte("domain"))
	if err != nil {
		t.Fatalf("SignDetached failed: %v", err)
	}
	// Verify with correct key succeeds
	if err := VerifyDetached(signed, &msg, alice.PublicKey(), []byte("domain"), nil); err != nil {
		t.Fatalf("VerifyDetached failed: %v", err)
	}
	// Verify with wrong key fails
	if err := VerifyDetached(signed, &msg, bobby.PublicKey(), []byte("domain"), nil); err == nil {
		t.Fatal("VerifyDetached should have failed with wrong key")
	}
	// Verify with wrong message fails
	if err := VerifyDetached(signed, &testAAD{Str: "wrong"}, alice.PublicKey(), []byte("domain"), nil); err == nil {
		t.Fatal("VerifyDetached should have failed with wrong message")
	}
}

func ptr(v int64) *int64    { return &v }
func uptr(v uint64) *uint64 { return &v }
