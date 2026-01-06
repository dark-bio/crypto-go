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

	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// Tests various combinations of signing and verifying ops.
func TestSignVerify(t *testing.T) {
	tests := []struct {
		msgToSign         []byte
		msgToAuth         []byte
		verifierMsgToAuth []byte
		wrongKey          bool
		wantOK            bool
	}{
		// Valid signature with aad
		{
			msgToSign:         []byte("foo"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("bar"),
			wrongKey:          false,
			wantOK:            true,
		},
		// Valid signature, empty aad
		{
			msgToSign:         []byte("foobar"),
			msgToAuth:         []byte(""),
			verifierMsgToAuth: []byte(""),
			wrongKey:          false,
			wantOK:            true,
		},
		// Wrong aad
		{
			msgToSign:         []byte("foo!"),
			msgToAuth:         []byte("bar"),
			verifierMsgToAuth: []byte("baz"),
			wrongKey:          false,
			wantOK:            false,
		},
		// Wrong key
		{
			msgToSign:         []byte("foo!"),
			msgToAuth:         []byte(""),
			verifierMsgToAuth: []byte(""),
			wrongKey:          true,
			wantOK:            false,
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			alice := xdsa.GenerateKey()
			bobby := xdsa.GenerateKey()

			signed := Sign(tt.msgToSign, tt.msgToAuth, alice)

			verifier := alice.PublicKey()
			if tt.wrongKey {
				verifier = bobby.PublicKey()
			}

			recovered, err := Verify(signed, tt.verifierMsgToAuth, verifier)

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
	tests := []struct {
		msgToSeal       []byte
		msgToAuth       []byte
		openerMsgToAuth []byte
		domain          string
		openerDomain    string
		wrongSigner     bool
		wantOK          bool
	}{
		// Valid seal/open with aad
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar"),
			domain:          "baz",
			openerDomain:    "baz",
			wrongSigner:     false,
			wantOK:          true,
		},
		// Valid seal/open, empty aad
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte(""),
			openerMsgToAuth: []byte(""),
			domain:          "baz",
			openerDomain:    "baz",
			wrongSigner:     false,
			wantOK:          true,
		},
		// Wrong domain
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte(""),
			openerMsgToAuth: []byte(""),
			domain:          "baz",
			openerDomain:    "baz2",
			wrongSigner:     false,
			wantOK:          false,
		},
		// Wrong aad
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte("bar"),
			openerMsgToAuth: []byte("bar2"),
			domain:          "baz",
			openerDomain:    "baz",
			wrongSigner:     false,
			wantOK:          false,
		},
		// Wrong signer
		{
			msgToSeal:       []byte("foo"),
			msgToAuth:       []byte(""),
			openerMsgToAuth: []byte(""),
			domain:          "baz",
			openerDomain:    "baz",
			wrongSigner:     true,
			wantOK:          false,
		},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			alice := xdsa.GenerateKey()
			bobby := xdsa.GenerateKey()
			carol := xhpke.GenerateKey()

			sealed, err := Seal(tt.msgToSeal, tt.msgToAuth, alice, carol.PublicKey(), tt.domain)
			if err != nil {
				t.Fatalf("Seal failed: %v", err)
			}

			verifier := alice.PublicKey()
			if tt.wrongSigner {
				verifier = bobby.PublicKey()
			}

			recovered, err := Open(sealed, tt.openerMsgToAuth, carol, verifier, tt.openerDomain)

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
