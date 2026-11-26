// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pem

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestBlankBodyLines checks blank lines in every position with both line endings.
func TestBlankBodyLines(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		for _, lines := range [][]string{{"", "YW", "Jj"}, {"YW", "", "Jj"}, {"YW", "Jj", ""}} {
			body := strings.Join(lines, newline)
			input := "-----BEGIN TEST-----" + newline + body + newline + "-----END TEST-----"
			if _, _, err := Decode([]byte(input)); !errors.Is(err, ErrMalformedBody) {
				t.Errorf("%q: got %v, want %v", input, err, ErrMalformedBody)
			}
		}
	}
}

// TestBodyLineEndings checks every base64 line against the header's line ending.
func TestBodyLineEndings(t *testing.T) {
	for _, tt := range []struct {
		header, body string
		err          error
	}{
		{"\n", "YW\nJj\n", nil},
		{"\r\n", "YW\r\nJj\r\n", nil},
		{"\n", "YW\r\nJj\n", ErrMalformedPayload},
		{"\r\n", "YW\nJj\r\n", ErrMalformedPayload},
		{"\n", "YWJj\r\n", ErrMalformedPayload},
		{"\r\n", "YWJj\n", ErrMalformedBody},
		{"\r\n", "YW\rJj\r\n", ErrMalformedPayload},
		{"\n", "YW\rJj\n", ErrMalformedPayload},
		{"\n", "YWJj\r", ErrMalformedBody},
		{"\n", "YWJj\n!!!!\n", ErrMalformedPayload},
		{"\n", "YWJj", ErrMalformedBody},
	} {
		input := "-----BEGIN TEST-----" + tt.header + tt.body + "-----END TEST-----"
		_, blob, err := Decode([]byte(input))
		if !errors.Is(err, tt.err) || err == nil && string(blob) != "abc" {
			t.Errorf("%q: got %q, %v", input, blob, err)
		}
	}
}

// TestBlockLabels checks that Encode and Decode enforce the same label grammar.
func TestBlockLabels(t *testing.T) {
	for _, tt := range []struct {
		kind string
		err  error
	}{
		{"A", nil}, {"PUBLIC KEY", nil}, {"!A #~", nil},
		{"", ErrEmptyBlockType}, {" A", ErrMalformedBlockType}, {"A ", ErrMalformedBlockType},
		{"A  B", ErrMalformedBlockType}, {"A-B", ErrMalformedBlockType}, {"A\rB", ErrMalformedBlockType},
		{"A\tB", ErrMalformedBlockType}, {"A\x00B", ErrMalformedBlockType}, {"\x7f", ErrMalformedBlockType},
		{"é", ErrMalformedBlockType}, {"\xff", ErrMalformedBlockType},
	} {
		t.Run(fmt.Sprintf("%q", tt.kind), func(t *testing.T) {
			input := fmt.Sprintf("-----BEGIN %[1]s-----\nYQ==\n-----END %[1]s-----\n", tt.kind)
			kind, blob, err := Decode([]byte(input))
			if !errors.Is(err, tt.err) {
				t.Fatalf("Decode: got %v, want %v", err, tt.err)
			}
			if tt.err != nil {
				defer func() {
					if got := recover(); got != "pem: invalid block type" {
						t.Errorf("Encode panic: got %v, want pem: invalid block type", got)
					}
				}()
				Encode(tt.kind, []byte("a"))
				return
			}
			if kind != tt.kind || string(blob) != "a" || string(Encode(tt.kind, blob)) != input {
				t.Fatal("label did not round-trip")
			}
		})
	}
}

// TestDecodeEmptyPayload checks that a body without base64 text is rejected,
// whether it has no lines or only blank ones.
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

// TestEncodeEmptyPayload checks that encoding an empty payload panics.
func TestEncodeEmptyPayload(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("no panic")
		}
	}()
	Encode("PUBLIC KEY", nil)
}

// TestRoundTrip checks that payloads around the 64-character line boundary
// survive encoding and decoding unchanged.
func TestRoundTrip(t *testing.T) {
	for _, size := range []int{1, 47, 48, 49, 96, 97} {
		payload := bytes.Repeat([]byte{0xa5}, size)
		kind, decoded, err := Decode(Encode("PUBLIC KEY", payload))
		if err != nil || kind != "PUBLIC KEY" || !bytes.Equal(decoded, payload) {
			t.Error(size)
		}
	}
}
