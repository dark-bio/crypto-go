// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package stream provides streaming authenticated encryption based on age's
// STREAM construction.
//
// Plaintext is split into 64 KiB chunks, each sealed with ChaCha20-Poly1305
// under a nonce that counts up and marks the final chunk, so truncation and
// reordering are detected. A Writer must be closed for the last chunk to be
// written out.
package stream

import (
	"io"

	inner "github.com/dark-bio/crypto-go/stream/internal"
)

// PayloadKeySize is the size of the payload key in bytes.
const PayloadKeySize = 32

// PayloadKey is the symmetric key encrypting or decrypting a stream.
//
// The key must never be repeated across multiple streams. Derive it with HKDF
// from both a random file key and a random nonce.
type PayloadKey [PayloadKeySize]byte

// Writer encrypts the plaintext written to it into the underlying writer.
type Writer struct {
	stream *inner.EncryptWriter
}

// Encrypt wraps STREAM encryption under the given key around a writer.
func Encrypt(key PayloadKey, dst io.Writer) *Writer {
	w, err := inner.NewEncryptWriter(key[:], dst)
	if err != nil {
		panic(err) // cannot fail for a 32-byte key
	}
	return &Writer{stream: w}
}

// Write encrypts p into the stream.
func (w *Writer) Write(p []byte) (int, error) {
	return w.stream.Write(p)
}

// Close encrypts and writes the final chunk, completing the stream. It does
// not close the underlying writer.
func (w *Writer) Close() error {
	return w.stream.Close()
}

// Reader decrypts the stream read from the underlying reader.
type Reader struct {
	stream *inner.DecryptReader
}

// Decrypt wraps STREAM decryption under the given key around a reader.
func Decrypt(key PayloadKey, src io.Reader) *Reader {
	r, err := inner.NewDecryptReader(key[:], src)
	if err != nil {
		panic(err) // cannot fail for a 32-byte key
	}
	return &Reader{stream: r}
}

// Read decrypts the next plaintext into p. It returns an error if the stream
// was tampered with, is truncated, or continues past its end.
func (r *Reader) Read(p []byte) (int, error) {
	return r.stream.Read(p)
}

// ReaderAt decrypts arbitrary plaintext ranges of a stream held in random
// access storage.
type ReaderAt struct {
	stream *inner.DecryptReaderAt
	size   int64
}

// DecryptAt wraps STREAM decryption under the given key around random access
// storage holding size bytes of ciphertext. It returns an error if size is
// invalid, or if the stream is truncated or does not match the key.
func DecryptAt(key PayloadKey, src io.ReaderAt, size int64) (*ReaderAt, error) {
	r, err := inner.NewDecryptReaderAt(key[:], src, size)
	if err != nil {
		return nil, err
	}
	plain, err := inner.PlaintextSize(size)
	if err != nil {
		return nil, err
	}
	return &ReaderAt{stream: r, size: plain}, nil
}

// ReadAt decrypts len(p) bytes of plaintext starting at offset off, following
// the io.ReaderAt contract. It returns an error if a chunk it reads was
// tampered with.
func (r *ReaderAt) ReadAt(p []byte, off int64) (int, error) {
	return r.stream.ReadAt(p, off)
}

// Size returns the length of the plaintext in bytes.
func (r *ReaderAt) Size() int64 {
	return r.size
}
