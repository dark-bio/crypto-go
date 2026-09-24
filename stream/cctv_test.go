// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stream_test

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dark-bio/crypto-go/hkdf"
	"github.com/dark-bio/crypto-go/stream"
)

// Tests the STREAM implementation against the C2SP CCTV age testkit vectors,
// vendored at commit 1e3d2860d46e94e777e1b17c7a6f2436387e3ecc: success
// vectors must decrypt fully to the expected payload hash and re-encrypt
// byte for byte; failure vectors must error with only the expected prefix
// released.
//
// https://github.com/C2SP/CCTV/tree/main/age
func TestCCTVVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "cctv", "stream_*"))
	if err != nil {
		t.Fatalf("failed to glob vectors: %v", err)
	}
	if len(files) != 28 {
		t.Fatalf("unexpected vector count: have %d, want 28", len(files))
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read vector: %v", err)
			}
			// Split the vector into its textual header and the age file body
			head, body, ok := bytes.Cut(raw, []byte("\n\n"))
			if !ok {
				t.Fatal("malformed vector: no header separator")
			}
			hdr := make(map[string]string)
			for _, line := range strings.Split(string(head), "\n") {
				key, val, ok := strings.Cut(line, ": ")
				if !ok {
					t.Fatalf("malformed header line: %q", line)
				}
				hdr[key] = val
			}
			// Decompress the body if needed and slice off the header and MAC
			if hdr["compressed"] == "zlib" {
				zr, err := zlib.NewReader(bytes.NewReader(body))
				if err != nil {
					t.Fatalf("failed to open zlib body: %v", err)
				}
				if body, err = io.ReadAll(zr); err != nil {
					t.Fatalf("failed to decompress body: %v", err)
				}
			}
			mac := bytes.Index(body, []byte("\n--- "))
			if mac < 0 {
				t.Fatal("malformed vector: no header MAC")
			}
			nl := bytes.IndexByte(body[mac+1:], '\n')
			if nl < 0 {
				t.Fatal("malformed vector: unterminated MAC line")
			}
			paysec := body[mac+1+nl+1:]

			// A payload too short for the nonce must never be a success vector
			if len(paysec) < 16 {
				if hdr["expect"] == "success" {
					t.Fatal("success vector without a payload nonce")
				}
				return
			}
			// Derive the payload key and decrypt, collecting released plaintext
			fileKey, err := hex.DecodeString(hdr["file key"])
			if err != nil {
				t.Fatalf("failed to decode file key: %v", err)
			}
			key := stream.PayloadKey(hkdf.Key(fileKey, paysec[:16], []byte("payload"), stream.PayloadKeySize))
			ciphertext := paysec[16:]

			var released bytes.Buffer
			_, rerr := io.Copy(&released, stream.Decrypt(key, bytes.NewReader(ciphertext)))

			// Whatever was handed out must match the expected payload hash
			if hash, ok := hdr["payload"]; ok {
				sum := sha256.Sum256(released.Bytes())
				if hex.EncodeToString(sum[:]) != hash {
					t.Fatalf("released payload hash mismatch: have %x, want %s", sum, hash)
				}
			}
			if hdr["expect"] == "success" {
				// Decryption must succeed and re-encrypting the recovered
				// plaintext must reproduce the ciphertext byte for byte
				if rerr != nil {
					t.Fatalf("failed to decrypt: %v", rerr)
				}
				var reencrypted bytes.Buffer
				writer := stream.Encrypt(key, &reencrypted)
				if _, err := writer.Write(released.Bytes()); err != nil {
					t.Fatalf("failed to re-encrypt: %v", err)
				}
				if err := writer.Close(); err != nil {
					t.Fatalf("failed to finalize re-encryption: %v", err)
				}
				if !bytes.Equal(reencrypted.Bytes(), ciphertext) {
					t.Fatal("re-encrypted payload mismatch")
				}
				// Random access must recover the same plaintext
				reader, err := stream.DecryptAt(key, bytes.NewReader(ciphertext), int64(len(ciphertext)))
				if err != nil {
					t.Fatalf("failed to open for random access: %v", err)
				}
				plaintext, err := io.ReadAll(io.NewSectionReader(reader, 0, reader.Size()))
				if err != nil {
					t.Fatalf("failed to read with random access: %v", err)
				}
				if !bytes.Equal(plaintext, released.Bytes()) {
					t.Fatal("random access plaintext mismatch")
				}
			} else {
				if rerr == nil {
					t.Fatal("decryption succeeded, want failure")
				}
				// Random access must refuse the stream on opening or on reading
				if reader, err := stream.DecryptAt(key, bytes.NewReader(ciphertext), int64(len(ciphertext))); err == nil {
					if _, err := io.ReadAll(io.NewSectionReader(reader, 0, reader.Size())); err == nil {
						t.Fatal("random access succeeded, want failure")
					}
				}
			}
		})
	}
}
