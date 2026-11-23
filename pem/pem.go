// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pem provides strict PEM encoding and decoding.
//
// One block per input, no leading whitespace, and strict base64. Decode
// documents the rules at the block boundaries and for line endings. Only an
// optional final line ending may follow the footer.
package pem

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	pemHeader = []byte("-----BEGIN ")
	pemFooter = []byte("-----END ")
	pemEnding = []byte("-----")
)

var (
	// ErrMissingHeader is returned when the input does not start with
	// "-----BEGIN ". Leading whitespace counts as missing.
	ErrMissingHeader = errors.New("pem: missing PEM header")

	// ErrMalformedHeader is returned when the first line is not a complete
	// "-----BEGIN TYPE-----" header. The wrapping error says what is missing.
	ErrMalformedHeader = errors.New("pem: malformed PEM header")

	// ErrEmptyBlockType is returned when the header names no block type.
	ErrEmptyBlockType = errors.New("pem: empty PEM block type")

	// ErrMalformedBlockType is returned for invalid label characters or spacing.
	ErrMalformedBlockType = errors.New("pem: malformed PEM block type")

	// ErrMissingFooter is returned when no "-----END TYPE-----" footer matches
	// the header's block type.
	ErrMissingFooter = errors.New("pem: missing PEM footer")

	// ErrTrailingData is returned when bytes follow the footer other than a
	// single line ending matching the header.
	ErrTrailingData = errors.New("pem: trailing data after PEM block")

	// ErrMalformedBody is returned when the body between header and footer is
	// empty, contains a blank line, or does not end in a line ending. The
	// wrapping error says which.
	ErrMalformedBody = errors.New("pem: malformed PEM body")

	// ErrMalformedPayload is returned when the body is not strict base64, or a
	// line ends differently from the header. The wrapping error names the
	// reason.
	ErrMalformedPayload = errors.New("pem: malformed base64 payload")
)

// validLabel reports whether kind contains printable ASCII words without
// hyphens, separated by single spaces.
func validLabel(kind string) bool {
	for word := range strings.SplitSeq(kind, " ") {
		if word == "" {
			return false
		}
		for i := range len(word) {
			if b := word[i]; b < 0x21 || b > 0x7e || b == '-' {
				return false
			}
		}
	}
	return true
}

// Decode decodes a single PEM block with strict validation.
//
// Rules:
//   - Header must start at byte 0 (no leading whitespace)
//   - Label uses printable ASCII other than hyphens, with single spaces between words
//   - Footer must end the data (only optional line ending after)
//   - Line endings must be consistent (\n or \r\n throughout)
//   - Base64 lines are non-empty and contain only base64 characters
//   - Strict base64 decoding (no padding errors, etc.)
//   - Payload must not be empty
//   - No trailing data after the PEM block
func Decode(data []byte) (kind string, blob []byte, err error) {
	// Must start with header immediately (no leading whitespace)
	if !bytes.HasPrefix(data, pemHeader) {
		return "", nil, ErrMissingHeader
	}
	// Find the end of header line (first \n)
	headerEnd := bytes.Index(data, []byte("\n"))
	if headerEnd < 0 {
		return "", nil, fmt.Errorf("%w: incomplete header line", ErrMalformedHeader)
	}
	// Detect line ending style from first line
	var lineEnding []byte
	if headerEnd > 0 && data[headerEnd-1] == '\r' {
		lineEnding = []byte("\r\n")
	} else {
		lineEnding = []byte("\n")
	}
	// Extract header (without line ending)
	header := data[:headerEnd]
	if len(lineEnding) == 2 {
		header = header[:len(header)-1]
	}
	// Parse the block type from the header
	if !bytes.HasPrefix(header, pemHeader) || !bytes.HasSuffix(header, pemEnding) {
		return "", nil, fmt.Errorf("%w: unterminated block type", ErrMalformedHeader)
	}
	blockType := string(header[len(pemHeader) : len(header)-len(pemEnding)])
	if len(blockType) == 0 {
		return "", nil, ErrEmptyBlockType
	}
	if !validLabel(blockType) {
		return "", nil, ErrMalformedBlockType
	}
	// Build expected footer
	footer := append(append(append([]byte(nil), pemFooter...), blockType...), pemEnding...)

	// Find the footer
	footerIdx := bytes.Index(data[headerEnd+1:], footer)
	if footerIdx < 0 {
		return "", nil, ErrMissingFooter
	}
	footerStart := headerEnd + 1 + footerIdx
	footerEnd := footerStart + len(footer)

	// Validate what comes after footer: nothing or same line ending
	rest := data[footerEnd:]
	if len(rest) > 0 {
		if !bytes.Equal(rest, lineEnding) {
			return "", nil, ErrTrailingData
		}
	}
	// Extract body (between header and footer)
	body := data[headerEnd+1 : footerStart]

	if len(body) == 0 {
		return "", nil, fmt.Errorf("%w: empty body", ErrMalformedBody)
	}
	if !bytes.HasSuffix(body, lineEnding) {
		return "", nil, fmt.Errorf("%w: missing newline before footer", ErrMalformedBody)
	}
	// Check each line before passing the body to the newline-tolerant base64 decoder
	for line := range bytes.SplitSeq(body[:len(body)-len(lineEnding)], lineEnding) {
		if bytes.ContainsAny(line, "\r\n") {
			return "", nil, fmt.Errorf("%w: stray line endings", ErrMalformedPayload)
		}
		if len(line) == 0 {
			return "", nil, fmt.Errorf("%w: blank line", ErrMalformedBody)
		}
	}
	decoded, err := base64.StdEncoding.Strict().AppendDecode(nil, body)
	if err != nil {
		clear(decoded)
		return "", nil, fmt.Errorf("%w: %v", ErrMalformedPayload, err)
	}
	return blockType, decoded, nil
}

// Encode encodes data as a PEM block with the given type.
// Lines are 64 characters, using \n line endings. It panics if blob is empty
// or kind is an invalid block label.
func Encode(kind string, blob []byte) []byte {
	if len(blob) == 0 {
		panic("pem: empty payload")
	}
	if !validLabel(kind) {
		panic("pem: invalid block type")
	}
	b64 := base64.StdEncoding.EncodeToString(blob)

	var buf bytes.Buffer
	buf.Write(pemHeader)
	buf.WriteString(kind)
	buf.Write(pemEnding)
	buf.WriteByte('\n')

	for len(b64) > 0 {
		line := b64
		if len(line) > 64 {
			line = b64[:64]
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
		b64 = b64[len(line):]
	}

	buf.Write(pemFooter)
	buf.WriteString(kind)
	buf.Write(pemEnding)
	buf.WriteByte('\n')

	return buf.Bytes()
}
