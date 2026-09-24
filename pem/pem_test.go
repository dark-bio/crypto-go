// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pem

import (
	"bytes"
	"errors"
	"testing"
)

// Tests that a body without any base64 text is rejected, whether it has no
// lines or only blank ones.
func TestDecodeEmptyPayload(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "no body", input: "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"},
		{name: "blank line", input: "-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----\n"},
		{name: "blank crlf line", input: "-----BEGIN PUBLIC KEY-----\r\n\r\n-----END PUBLIC KEY-----\r\n"},
		{name: "two blank lines", input: "-----BEGIN PUBLIC KEY-----\n\n\n-----END PUBLIC KEY-----\n"},
	}
	for _, tt := range tests {
		if _, _, err := Decode([]byte(tt.input)); !errors.Is(err, ErrMalformedBody) {
			t.Error(tt.name)
		}
	}
}

// Tests that encoding an empty payload panics, since Decode rejects it.
func TestEncodeEmptyPayload(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	Encode("PUBLIC KEY", nil)
}

// Tests that payloads around the 64-character line length survive encoding
// and decoding unchanged.
func TestRoundTrip(t *testing.T) {
	for _, size := range []int{1, 47, 48, 49, 96, 97} {
		payload := bytes.Repeat([]byte{0xa5}, size)
		kind, decoded, err := Decode(Encode("PUBLIC KEY", payload))
		if err != nil || kind != "PUBLIC KEY" || !bytes.Equal(decoded, payload) {
			t.Error(size)
		}
	}
}
