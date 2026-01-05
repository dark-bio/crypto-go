// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package pem provides strict PEM encoding and decoding.
package pem

import (
	"bytes"
	"encoding/base64"
	"errors"
)

var (
	pemHeader = []byte("-----BEGIN ")
	pemFooter = []byte("-----END ")
	pemEnding = []byte("-----")
)

// Decode decodes a single PEM block with strict validation.
//
// Rules:
//   - Header must start at byte 0 (no leading whitespace)
//   - Footer must end the data (only optional line ending after)
//   - Line endings must be consistent (\n or \r\n throughout)
//   - Base64 lines contain only base64 characters
//   - Strict base64 decoding (no padding errors, etc.)
//   - No trailing data after the PEM block
func Decode(data []byte) (kind string, blob []byte, err error) {
	// Must start with header immediately (no leading whitespace)
	if !bytes.HasPrefix(data, pemHeader) {
		return "", nil, errors.New("pemext: missing PEM header")
	}
	// Find the end of header line (first \n)
	headerEnd := bytes.Index(data, []byte("\n"))
	if headerEnd < 0 {
		return "", nil, errors.New("pemext: incomplete PEM header")
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
		return "", nil, errors.New("pemext: malformed PEM header")
	}
	blockType := string(header[len(pemHeader) : len(header)-len(pemEnding)])
	if len(blockType) == 0 {
		return "", nil, errors.New("pemext: empty PEM block type")
	}
	// Build expected footer
	footer := append(append(append([]byte(nil), pemFooter...), blockType...), pemEnding...)

	// Find the footer
	footerIdx := bytes.Index(data[headerEnd+1:], footer)
	if footerIdx < 0 {
		return "", nil, errors.New("pemext: missing PEM footer")
	}
	footerStart := headerEnd + 1 + footerIdx
	footerEnd := footerStart + len(footer)

	// Validate what comes after footer: nothing or same line ending
	rest := data[footerEnd:]
	if len(rest) > 0 {
		if !bytes.Equal(rest, lineEnding) {
			return "", nil, errors.New("pemext: trailing data after PEM block")
		}
	}
	// Extract body (between header and footer)
	body := data[headerEnd+1 : footerStart]

	// Body must end with the line ending (the line before footer)
	if len(body) == 0 {
		return "", nil, errors.New("pemext: empty PEM body")
	}
	if !bytes.HasSuffix(body, lineEnding) {
		return "", nil, errors.New("pemext: body must end with newline before footer")
	}
	body = body[:len(body)-len(lineEnding)]

	// Strip line endings and decode
	b64 := bytes.ReplaceAll(body, lineEnding, nil)

	decoded, err := base64.StdEncoding.Strict().DecodeString(string(b64))
	if err != nil {
		return "", nil, errors.New("pemext: invalid base64 encoding")
	}
	return blockType, decoded, nil
}

// Encode encodes data as a PEM block with the given type.
// Lines are 64 characters, using \n line endings.
func Encode(kind string, blob []byte) []byte {
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
