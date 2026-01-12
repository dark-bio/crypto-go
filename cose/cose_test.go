// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cose

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// Tests various combinations of signing and verifying ops.
func TestSignVerify(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		msgToSign         []byte
		msgToAuth         []byte
		verifierMsgToAuth []byte
		timestamp         *int64
		maxDrift          *uint64
		wrongKey          bool
		wantOK            bool
	}{
		// Valid signature with aad
		{
			msgToSign:         []byte("foo"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("bar"),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            true,
		},
		// Valid signature, empty aad
		{
			msgToSign:         []byte("foobar"),
			msgToAuth:         []byte(""),
			verifierMsgToAuth: []byte(""),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            true,
		},
		// Valid signature with explicit timestamp, no drift check
		{
			msgToSign:         []byte("foo"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("bar"),
			timestamp:         ptr(now),
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            true,
		},
		// Valid signature within drift tolerance
		{
			msgToSign:         []byte("foo"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("bar"),
			timestamp:         ptr(now - 30),
			maxDrift:          uptr(60),
			wrongKey:          false,
			wantOK:            true,
		},
		// Wrong aad
		{
			msgToSign:         []byte("foo!"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("baz"),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          false,
			wantOK:            false,
		},
		// Wrong key
		{
			msgToSign:         []byte("foo!"),
			msgToAuth:         []byte(""),
			verifierMsgToAuth: []byte(""),
			timestamp:         nil,
			maxDrift:          nil,
			wrongKey:          true,
			wantOK:            false,
		},
		// Timestamp too far in the past
		{
			msgToSign:         []byte("foo"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("bar"),
			timestamp:         ptr(now - 120),
			maxDrift:          uptr(60),
			wrongKey:          false,
			wantOK:            false,
		},
		// Timestamp too far in the future
		{
			msgToSign:         []byte("foo"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("bar"),
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
			if tt.timestamp != nil {
				signed = SignAt(tt.msgToSign, tt.msgToAuth, alice, *tt.timestamp)
			} else {
				signed = Sign(tt.msgToSign, tt.msgToAuth, alice)
			}

			verifier := alice.PublicKey()
			if tt.wrongKey {
				verifier = bobby.PublicKey()
			}

			recovered, err := Verify(signed, tt.verifierMsgToAuth, verifier, tt.maxDrift)

			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected success, have error: %v", err)
				}
				if !bytes.Equal(recovered, tt.msgToSign) {
					t.Fatalf("payload mismatch: have %q, want %q", recovered, tt.msgToSign)
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
		msgToSeal       []byte
		msgToAuth       []byte
		openerMsgToAuth []byte
		domain          []byte
		openerDomain    []byte
		timestamp       *int64
		maxDrift        *uint64
		wrongSigner     bool
		wantOK          bool
	}{
		// Valid seal/open with aad
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar"),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          true,
		},
		// Valid seal/open, empty aad
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte(""),
			openerMsgToAuth: []byte(""),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          true,
		},
		// Valid seal/open, no drift check
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar"),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       ptr(now),
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          true,
		},
		// Valid seal/open, valid drift
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar"),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       ptr(now - 30),
			maxDrift:        uptr(60),
			wrongSigner:     false,
			wantOK:          true,
		},
		// Wrong domain
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte(""),
			openerMsgToAuth: []byte(""),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz2"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          false,
		},
		// Wrong aad
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar2"),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     false,
			wantOK:          false,
		},
		// Wrong signer
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte(""),
			openerMsgToAuth: []byte(""),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       nil,
			maxDrift:        nil,
			wrongSigner:     true,
			wantOK:          false,
		},
		// Timestamp too far in the past
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar"),
			domain:          []byte("baz"),
			openerDomain:    []byte("baz"),
			timestamp:       ptr(now - 120),
			maxDrift:        uptr(60),
			wrongSigner:     false,
			wantOK:          false,
		},
		// Timestamp too far in the future
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar"),
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
				sealed, err = SealAt(tt.msgToSeal, tt.msgToAuth, alice, carol.PublicKey(), tt.domain, *tt.timestamp)
			} else {
				sealed, err = Seal(tt.msgToSeal, tt.msgToAuth, alice, carol.PublicKey(), tt.domain)
			}
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}

			verifier := alice.PublicKey()
			if tt.wrongSigner {
				verifier = bobby.PublicKey()
			}

			recovered, err := Open(sealed, tt.openerMsgToAuth, carol, verifier, tt.openerDomain, tt.maxDrift)

			if tt.wantOK {
				if err != nil {
					t.Fatalf("expected success, have error: %v", err)
				}
				if !bytes.Equal(recovered, tt.msgToSeal) {
					t.Fatalf("payload mismatch: have %q, want %q", recovered, tt.msgToSeal)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, have success")
				}
			}
		})
	}
}

type testPayload struct {
	_   struct{} `cbor:"_,array"`
	Num uint64
	Str string
}

type testAAD struct {
	_   struct{} `cbor:"_,array"`
	Str string
}

// Tests CBOR encoding/decoding for sign/verify.
func TestSignVerifyCBOR(t *testing.T) {
	alice := xdsa.GenerateKey()

	msg := testPayload{Num: 42, Str: "foo"}
	auth := testAAD{Str: "bar"}

	signed, err := SignCBOR(&msg, &auth, alice)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	recovered, err := VerifyCBOR[testPayload](signed, &auth, alice.PublicKey(), nil)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if recovered.Num != msg.Num || recovered.Str != msg.Str {
		t.Fatalf("payload mismatch: have %+v, want %+v", recovered, msg)
	}
}

// Tests CBOR encoding/decoding for seal/open.
func TestSealOpenCBOR(t *testing.T) {
	alice := xdsa.GenerateKey()
	carol := xhpke.GenerateKey()

	msg := testPayload{Num: 123, Str: "foo"}
	auth := testAAD{Str: "bar"}

	sealed, err := SealCBOR(&msg, &auth, alice, carol.PublicKey(), []byte("baz"))
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}
	recovered, err := OpenCBOR[testPayload](sealed, &auth, carol, alice.PublicKey(), []byte("baz"), nil)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if recovered.Num != msg.Num || recovered.Str != msg.Str {
		t.Fatalf("payload mismatch: have %+v, want %+v", recovered, msg)
	}
}

func ptr(v int64) *int64    { return &v }
func uptr(v uint64) *uint64 { return &v }
