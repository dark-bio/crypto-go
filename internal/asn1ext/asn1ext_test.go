// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asn1ext

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
)

// TestSubjectPublicKeyBitString checks DER padding in the SPKI public key.
func TestSubjectPublicKeyBitString(t *testing.T) {
	for _, tt := range []struct {
		name string
		body []byte
		bits int
		err  error
	}{
		{"aligned", []byte{0, 0xff}, 8, nil},
		{"padded", []byte{7, 0x80}, 1, nil},
		{"empty", []byte{0}, 0, nil},
		{"missing padding count", nil, 0, ErrInvalidBitString},
		{"excess padding", []byte{8, 0}, 0, ErrInvalidBitString},
		{"padding without data", []byte{1}, 0, ErrInvalidBitString},
		{"nonzero unused bits", []byte{3, 0xfc}, 0, ErrInvalidBitString},
	} {
		// Encode the BIT STRING body verbatim to exercise malformed padding
		der, err := asn1.Marshal(struct {
			Algorithm pkix.AlgorithmIdentifier
			Key       asn1.RawValue
		}{
			pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}},
			asn1.RawValue{Tag: asn1.TagBitString, Bytes: tt.body},
		})
		if err != nil {
			t.Fatal(err)
		}
		info, err := ParseSubjectPublicKeyInfo(der)
		if !errors.Is(err, tt.err) {
			t.Errorf("%s: got %v, want %v", tt.name, err, tt.err)
		} else if err == nil && (info.SubjectPublicKey.BitLength != tt.bits || !bytes.Equal(info.SubjectPublicKey.Bytes, tt.body[1:])) {
			t.Errorf("%s: got %+v", tt.name, info.SubjectPublicKey)
		}
	}
}
