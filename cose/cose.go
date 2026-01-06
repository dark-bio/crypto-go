// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cose provides COSE wrappers for xDSA and xHPKE.
//
// https://datatracker.ietf.org/doc/html/rfc8152
// https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke
package cose

import (
	"errors"
	"fmt"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// Algorithm identifiers for COSE operations
const (
	// AlgorithmXDSA is the private COSE algorithm identifier for composite
	// ML-DSA-65 + Ed25519 signatures.
	AlgorithmXDSA = -70000

	// AlgorithmXHPKE is the private COSE algorithm identifier for X-Wing
	// (ML-KEM-768 + X25519) HPKE.
	AlgorithmXHPKE = -70001
)

// Error types for COSE operations
var (
	ErrUnexpectedAlgorithm = errors.New("cose: unexpected algorithm")
	ErrInvalidEncapKeySize = errors.New("cose: invalid encapsulated key size")
	ErrSignatureInvalid    = errors.New("cose: signature verification failed")
	ErrDecryptionFailed    = errors.New("cose: decryption failed")
)

// ProtectedHeader contains the algorithm identifier.
type ProtectedHeader struct {
	Algorithm int64 `cbor:"1,key"`
}

// EmptyHeader is an empty unprotected header map (for COSE_Sign1).
type EmptyHeader struct{}

// EncapKeyHeader contains the encapsulated key (for COSE_Encrypt0).
type EncapKeyHeader struct {
	EncapKey []byte `cbor:"-4,key"`
}

// CoseSign1 is the COSE_Sign1 structure per RFC 9052 Section 4.2.
//
//	COSE_Sign1 = [
//	    protected:   bstr,
//	    unprotected: header_map,
//	    payload:     bstr,
//	    signature:   bstr
//	]
type CoseSign1 struct {
	_           struct{} `cbor:"_,array"`
	Protected   []byte
	Unprotected EmptyHeader
	Payload     []byte
	Signature   [xdsa.SignatureSize]byte
}

// CoseEncrypt0 is the COSE_Encrypt0 structure per RFC 9052 Section 5.2.
//
//	COSE_Encrypt0 = [
//	    protected:   bstr,
//	    unprotected: header_map,
//	    ciphertext:  bstr
//	]
type CoseEncrypt0 struct {
	_           struct{} `cbor:"_,array"`
	Protected   []byte
	Unprotected EncapKeyHeader
	Ciphertext  []byte
}

// SigStructure is the Sig_structure for computing signatures per RFC 9052 Section 4.4.
//
//	Sig_structure = [
//	    context:        "Signature1",
//	    body_protected: bstr,
//	    external_aad:   bstr,
//	    payload:        bstr
//	]
type SigStructure struct {
	_           struct{} `cbor:"_,array"`
	Context     string
	Protected   []byte
	ExternalAAD []byte
	Payload     []byte
}

// EncStructure is the Enc_structure for computing AAD per RFC 9052 Section 5.3.
//
//	Enc_structure = [
//	    context:      "Encrypt0",
//	    protected:    bstr,
//	    external_aad: bstr
//	]
type EncStructure struct {
	_           struct{} `cbor:"_,array"`
	Context     string
	Protected   []byte
	ExternalAAD []byte
}

// Sign creates a COSE_Sign1 digital signature of the msgToEmbed.
//
//   - msgToEmbed: The message to sign (embedded in COSE_Sign1)
//   - msgToAuth: Additional authenticated data (not embedded, but signed)
//   - signer: The xDSA secret key to sign with
//
// Returns the serialized COSE_Sign1 structure.
func Sign(msgToEmbed, msgToAuth []byte, signer *xdsa.SecretKey) []byte {
	// Build protected header
	protected, err := cbor.Marshal(&ProtectedHeader{Algorithm: AlgorithmXDSA})
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	// Build and sign Sig_structure
	sigStructure := SigStructure{
		Context:     "Signature1",
		Protected:   protected,
		ExternalAAD: msgToAuth,
		Payload:     msgToEmbed,
	}
	toBeSigned, err := cbor.Marshal(&sigStructure)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	signature := signer.Sign(toBeSigned)

	// Build and encode COSE_Sign1
	sign1 := CoseSign1{
		Protected:   protected,
		Unprotected: EmptyHeader{},
		Payload:     msgToEmbed,
		Signature:   signature,
	}
	result, err := cbor.Marshal(&sign1)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	return result
}

// Verify validates a COSE_Sign1 digital signature and returns the payload.
//
//   - msgToCheck: The serialized COSE_Sign1 structure
//   - msgToAuth: The same additional authenticated data used during signing
//   - verifier: The xDSA public key to verify against
//
// Returns the embedded payload if verification succeeds.
func Verify(msgToCheck, msgToAuth []byte, verifier *xdsa.PublicKey) ([]byte, error) {
	// Parse COSE_Sign1
	var sign1 CoseSign1
	if err := cbor.Unmarshal(msgToCheck, &sign1); err != nil {
		return nil, err
	}
	// Verify the protected header
	if err := verifyProtectedHeader(sign1.Protected, AlgorithmXDSA); err != nil {
		return nil, err
	}
	// Reconstruct Sig_structure to verify
	sigStructure := SigStructure{
		Context:     "Signature1",
		Protected:   sign1.Protected,
		ExternalAAD: msgToAuth,
		Payload:     sign1.Payload,
	}
	toBeSigned, _ := cbor.Marshal(&sigStructure)

	// Verify signature
	if err := verifier.Verify(toBeSigned, sign1.Signature); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return sign1.Payload, nil
}

// Seal signs a message then encrypts it to a recipient.
//
//   - msgToSeal: The message to sign and encrypt
//   - msgToAuth: Additional authenticated data (signed and bound to encryption, but not embedded)
//   - signer: The xDSA secret key to sign with
//   - recipient: The xHPKE public key to encrypt to
//   - domain: Application domain for HPKE key derivation
//
// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
func Seal(msgToSeal, msgToAuth []byte, signer *xdsa.SecretKey, recipient *xhpke.PublicKey, domain string) ([]byte, error) {
	// Create a COSE_Sign1 with the payload, binding the AAD
	signed := Sign(msgToSeal, msgToAuth, signer)

	// Build protected header
	protected, err := cbor.Marshal(&ProtectedHeader{Algorithm: AlgorithmXHPKE})
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	// Build and seal Enc_structure
	encStructure := EncStructure{
		Context:     "Encrypt0",
		Protected:   protected,
		ExternalAAD: msgToAuth,
	}
	aad, err := cbor.Marshal(&encStructure)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	encapKey, ciphertext, err := recipient.Seal(signed, aad, domain)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	// Build and encode COSE_Encrypt0
	encrypt0 := CoseEncrypt0{
		Protected: protected,
		Unprotected: EncapKeyHeader{
			EncapKey: encapKey[:],
		},
		Ciphertext: ciphertext,
	}
	result, err := cbor.Marshal(&encrypt0)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	return result, nil
}

// Open decrypts and verifies a sealed message.
//
//   - msgToOpen: The serialized COSE_Encrypt0 structure
//   - msgToAuth: The same additional authenticated data used during sealing
//   - recipient: The xHPKE secret key to decrypt with
//   - sender: The xDSA public key to verify the signature against
//   - domain: Application domain for HPKE key derivation
//
// Returns the original payload if decryption and verification succeed.
func Open(msgToOpen, msgToAuth []byte, recipient *xhpke.SecretKey, sender *xdsa.PublicKey, domain string) ([]byte, error) {
	// Parse COSE_Encrypt0
	var encrypt0 CoseEncrypt0
	if err := cbor.Unmarshal(msgToOpen, &encrypt0); err != nil {
		return nil, err
	}
	// Verify protected header
	if err := verifyProtectedHeader(encrypt0.Protected, AlgorithmXHPKE); err != nil {
		return nil, err
	}
	// Extract encapsulated key from the unprotected headers
	if len(encrypt0.Unprotected.EncapKey) != xhpke.EncapKeySize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidEncapKeySize,
			len(encrypt0.Unprotected.EncapKey), xhpke.EncapKeySize)
	}
	var encapKey [xhpke.EncapKeySize]byte
	copy(encapKey[:], encrypt0.Unprotected.EncapKey)

	// Rebuild and open Enc_structure
	encStructure := EncStructure{
		Context:     "Encrypt0",
		Protected:   encrypt0.Protected,
		ExternalAAD: msgToAuth,
	}
	aad, err := cbor.Marshal(&encStructure)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	signed, err := recipient.Open(&encapKey, encrypt0.Ciphertext, aad, domain)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	// Verify the signature and extract the payload
	return Verify(signed, msgToAuth, sender)
}

// verifyProtectedHeader verifies the protected header contains exactly the expected algorithm.
func verifyProtectedHeader(data []byte, expectedAlg int64) error {
	var header ProtectedHeader
	if err := cbor.Unmarshal(data, &header); err != nil {
		return err
	}
	if header.Algorithm != expectedAlg {
		return fmt.Errorf("%w: got %d, want %d", ErrUnexpectedAlgorithm, header.Algorithm, expectedAlg)
	}
	return nil
}
