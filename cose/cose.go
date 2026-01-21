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
	"time"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// DomainPrefix is the prefix of a public string known to both parties during
// cryptographic operation, with the purpose of binding the keys used to some
// application context.
//
// The final domain will be this prefix concatenated with another contextual one
// from an app layer action.
const DomainPrefix = "dark-bio-v1:"

// algorithm identifiers for COSE operations
const (
	// algorithmXDSA is the private COSE algorithm identifier for composite
	// ML-DSA-65 + Ed25519 signatures.
	algorithmXDSA = -70000

	// algorithmXHPKE is the private COSE algorithm identifier for X-Wing
	// (ML-KEM-768 + X25519) HPKE.
	algorithmXHPKE = -70001

	// HeaderTimestamp is the private COSE header label for Unix timestamp.
	HeaderTimestamp = -70002
)

// Error types for COSE operations
var (
	ErrUnexpectedAlgorithm = errors.New("cose: unexpected algorithm")
	ErrUnexpectedKey       = errors.New("cose: unexpected key")
	ErrUnexpectedPayload   = errors.New("cose: unexpected payload in detached signature")
	ErrMissingPayload      = errors.New("cose: missing payload in embedded signature")
	ErrInvalidSignature    = errors.New("cose: signature verification failed")
	ErrStaleSignature      = errors.New("cose: signature stale")
	ErrInvalidEncapKeySize = errors.New("cose: invalid encapsulated key size")
	ErrDecryptionFailed    = errors.New("cose: decryption failed")
)

// sigProtectedHeader is the protected header for COSE_Sign1.
type sigProtectedHeader struct {
	Algorithm int64            `cbor:"1,key"`
	Crit      critHeader       `cbor:"2,key"`
	Kid       xdsa.Fingerprint `cbor:"4,key"`
	Timestamp int64            `cbor:"-70002,key"`
}

// critHeader lists the critical headers that must be understood.
// Per RFC 9052, implementations must reject messages with unknown crit labels.
type critHeader struct {
	_         struct{} `cbor:"_,array"`
	Timestamp int64    // HeaderTimestamp label
}

// encProtectedHeader is the protected header for COSE_Encrypt0.
type encProtectedHeader struct {
	Algorithm int64             `cbor:"1,key"`
	Kid       xhpke.Fingerprint `cbor:"4,key"`
}

// emptyHeader is an empty unprotected header map (for COSE_Sign1).
type emptyHeader struct{}

// encapKeyHeader contains the encapsulated key (for COSE_Encrypt0).
type encapKeyHeader struct {
	EncapKey []byte `cbor:"-4,key"`
}

// coseSign1 is the COSE_Sign1 structure per RFC 9052 Section 4.2.
//
//	COSE_Sign1 = [
//	    protected:   bstr,
//	    unprotected: header_map,
//	    payload:     bstr / null,
//	    signature:   bstr
//	]
type coseSign1 struct {
	_           struct{} `cbor:"_,array"`
	Protected   []byte
	Unprotected emptyHeader
	Payload     []byte `cbor:"_,optional"` // nil for detached payload (encodes as null per RFC 9052)
	Signature   xdsa.Signature
}

// coseEncrypt0 is the COSE_Encrypt0 structure per RFC 9052 Section 5.2.
//
//	COSE_Encrypt0 = [
//	    protected:   bstr,
//	    unprotected: header_map,
//	    ciphertext:  bstr
//	]
type coseEncrypt0 struct {
	_           struct{} `cbor:"_,array"`
	Protected   []byte
	Unprotected encapKeyHeader
	Ciphertext  []byte
}

// sigStructure is the Sig_structure for computing signatures per RFC 9052 Section 4.4.
//
//	Sig_structure = [
//	    context:        "Signature1",
//	    body_protected: bstr,
//	    external_aad:   bstr,
//	    payload:        bstr
//	]
type sigStructure struct {
	_           struct{} `cbor:"_,array"`
	Context     string
	Protected   []byte
	ExternalAAD []byte
	Payload     []byte
}

// encStructure is the Enc_structure for computing AAD per RFC 9052 Section 5.3.
//
//	Enc_structure = [
//	    context:      "Encrypt0",
//	    protected:    bstr,
//	    external_aad: bstr
//	]
type encStructure struct {
	_           struct{} `cbor:"_,array"`
	Context     string
	Protected   []byte
	ExternalAAD []byte
}

// sigAAD wraps the domain info and message-to-auth for signing operations.
type sigAAD struct {
	_         struct{} `cbor:"_,array"`
	Info      []byte
	MsgToAuth cbor.Raw
}

// SignDetached creates a COSE_Sign1 digital signature without an embedded
// payload (i.e. payload is empty).
//
// Uses the current system time as the signature timestamp. For testing or
// custom timestamps, use SignDetachedAt.
//
//   - msgToAuth: The message to sign (not embedded in COSE_Sign1)
//   - signer: The xDSA secret key to sign with
//   - domain: Application domain for replay protection
//
// Returns the serialized COSE_Sign1 structure.
func SignDetached(msgToAuth any, signer xdsa.Signer, domain []byte) ([]byte, error) {
	return SignDetachedAt(msgToAuth, signer, domain, time.Now().Unix())
}

// SignDetachedAt creates a COSE_Sign1 digital signature without an embedded
// payload and with an explicit timestamp.
//
//   - msgToAuth: The message to sign (not embedded in COSE_Sign1)
//   - signer: The xDSA secret key to sign with
//   - domain: Application domain for replay protection
//   - timestamp: Unix timestamp in seconds to embed in the protected header
//
// Returns the serialized COSE_Sign1 structure.
func SignDetachedAt(msgToAuth any, signer xdsa.Signer, domain []byte, timestamp int64) ([]byte, error) {
	auth, err := cbor.Marshal(msgToAuth)
	if err != nil {
		return nil, err
	}
	return signDetachedAt(auth, signer, domain, timestamp), nil
}

// Sign creates a COSE_Sign1 digital signature of the msgToEmbed.
//
// Uses the current system time as the signature timestamp. For testing or
// custom timestamps, use SignAt.
//
//   - msgToEmbed: The message to sign (embedded in COSE_Sign1)
//   - msgToAuth: Additional authenticated data (not embedded, but signed)
//   - signer: The xDSA secret key to sign with
//   - domain: Application domain for replay protection
//
// Returns the serialized COSE_Sign1 structure.
func Sign(msgToEmbed, msgToAuth any, signer xdsa.Signer, domain []byte) ([]byte, error) {
	return SignAt(msgToEmbed, msgToAuth, signer, domain, time.Now().Unix())
}

// SignAt creates a COSE_Sign1 digital signature with an explicit timestamp.
//
//   - msgToEmbed: The message to sign (embedded in COSE_Sign1)
//   - msgToAuth: Additional authenticated data (not embedded, but signed)
//   - signer: The xDSA secret key to sign with
//   - domain: Application domain for replay protection
//   - timestamp: Unix timestamp in seconds to embed in the protected header
//
// Returns the serialized COSE_Sign1 structure.
func SignAt(msgToEmbed, msgToAuth any, signer xdsa.Signer, domain []byte, timestamp int64) ([]byte, error) {
	embed, err := cbor.Marshal(msgToEmbed)
	if err != nil {
		return nil, err
	}
	auth, err := cbor.Marshal(msgToAuth)
	if err != nil {
		return nil, err
	}
	return signAt(embed, auth, signer, domain, timestamp), nil
}

// signAt creates a COSE_Sign1 digital signature with an explicit timestamp (internal).
func signAt(msgToEmbed, msgToAuth []byte, signer xdsa.Signer, domain []byte, timestamp int64) []byte {
	// Restrict the user's domain to the context of this library
	info := []byte(DomainPrefix + string(domain))
	aad, err := cbor.Marshal(&sigAAD{
		Info:      info,
		MsgToAuth: msgToAuth,
	})
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	// Build protected header
	protected, err := cbor.Marshal(&sigProtectedHeader{
		Algorithm: algorithmXDSA,
		Crit:      critHeader{Timestamp: HeaderTimestamp},
		Kid:       signer.PublicKey().Fingerprint(),
		Timestamp: timestamp,
	})
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	// Build and sign Sig_structure
	sig := sigStructure{
		Context:     "Signature1",
		Protected:   protected,
		ExternalAAD: aad,
		Payload:     msgToEmbed,
	}
	toBeSigned, err := cbor.Marshal(&sig)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	signature, _ := signer.Sign(toBeSigned)

	// Build and encode COSE_Sign1
	sign1 := coseSign1{
		Protected:   protected,
		Unprotected: emptyHeader{},
		Payload:     msgToEmbed,
		Signature:   *signature,
	}
	result, err := cbor.Marshal(&sign1)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	return result
}

// signDetachedAt creates a COSE_Sign1 digital signature with null payload (internal).
func signDetachedAt(msgToAuth []byte, signer xdsa.Signer, domain []byte, timestamp int64) []byte {
	// Restrict the user's domain to the context of this library
	info := []byte(DomainPrefix + string(domain))
	aad, err := cbor.Marshal(&sigAAD{
		Info:      info,
		MsgToAuth: msgToAuth,
	})
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	// Build protected header
	protected, err := cbor.Marshal(&sigProtectedHeader{
		Algorithm: algorithmXDSA,
		Crit:      critHeader{Timestamp: HeaderTimestamp},
		Kid:       signer.PublicKey().Fingerprint(),
		Timestamp: timestamp,
	})
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	// Build and sign Sig_structure with empty payload for detached mode
	sig := sigStructure{
		Context:     "Signature1",
		Protected:   protected,
		ExternalAAD: aad,
		Payload:     []byte{},
	}
	toBeSigned, err := cbor.Marshal(&sig)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	signature, _ := signer.Sign(toBeSigned)

	// Build and encode COSE_Sign1 with null payload
	sign1 := coseSign1{
		Protected:   protected,
		Unprotected: emptyHeader{},
		Payload:     nil, // null payload for detached
		Signature:   *signature,
	}
	result, err := cbor.Marshal(&sign1)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	return result
}

// VerifyDetached validates a COSE_Sign1 digital signature with a detached payload.
//
// Uses the current system time for drift checking. For testing or custom
// timestamps, use VerifyDetachedAt.
//
//   - msgToCheck: The serialized COSE_Sign1 structure (with null payload)
//   - msgToAuth: The same message used during signing (verified but not embedded)
//   - verifier: The xDSA public key to verify against
//   - domain: Application domain for replay protection
//   - maxDrift: Signatures more in the past or future are rejected
func VerifyDetached(msgToCheck []byte, msgToAuth any, verifier *xdsa.PublicKey, domain []byte, maxDrift *uint64) error {
	return VerifyDetachedAt(msgToCheck, msgToAuth, verifier, domain, maxDrift, time.Now().Unix())
}

// VerifyDetachedAt validates a COSE_Sign1 digital signature with a detached payload
// and an explicit current time for drift checking.
//
//   - msgToCheck: The serialized COSE_Sign1 structure (with null payload)
//   - msgToAuth: The same message used during signing (verified but not embedded)
//   - verifier: The xDSA public key to verify against
//   - domain: Application domain for replay protection
//   - maxDrift: Signatures more in the past or future are rejected
//   - now: Unix timestamp in seconds to use for drift checking
func VerifyDetachedAt(msgToCheck []byte, msgToAuth any, verifier *xdsa.PublicKey, domain []byte, maxDrift *uint64, now int64) error {
	auth, err := cbor.Marshal(msgToAuth)
	if err != nil {
		return err
	}
	return verifyDetached(msgToCheck, auth, verifier, domain, maxDrift, now)
}

// verifyDetached validates a COSE_Sign1 digital signature with null payload (internal).
func verifyDetached(msgToCheck, msgToAuth []byte, verifier *xdsa.PublicKey, domain []byte, maxDrift *uint64, now int64) error {
	// Restrict the user's domain to the context of this library
	info := []byte(DomainPrefix + string(domain))
	aad, err := cbor.Marshal(&sigAAD{
		Info:      info,
		MsgToAuth: msgToAuth,
	})
	if err != nil {
		return err
	}
	// Parse COSE_Sign1
	var sign1 coseSign1
	if err := cbor.Unmarshal(msgToCheck, &sign1); err != nil {
		return err
	}
	// Verify payload is null (detached)
	if sign1.Payload != nil {
		return ErrUnexpectedPayload
	}
	// Verify the protected header
	header, err := verifySigProtectedHeader(sign1.Protected, algorithmXDSA, verifier)
	if err != nil {
		return err
	}
	// Check signature timestamp drift if maxDrift is specified
	if maxDrift != nil {
		drift := now - header.Timestamp
		if drift < 0 {
			drift = -drift
		}
		if uint64(drift) > *maxDrift {
			return fmt.Errorf("%w: time drift %ds exceeds max %ds", ErrStaleSignature, drift, *maxDrift)
		}
	}
	// Reconstruct Sig_structure to verify (empty payload for detached mode)
	sig := sigStructure{
		Context:     "Signature1",
		Protected:   sign1.Protected,
		ExternalAAD: aad,
		Payload:     []byte{},
	}
	toBeSigned, _ := cbor.Marshal(&sig)

	// Verify signature
	var xdsasig xdsa.Signature = sign1.Signature
	if err := verifier.Verify(toBeSigned, &xdsasig); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return nil
}

// Verify validates a COSE_Sign1 digital signature and returns the payload.
//
// Uses the current system time for drift checking. For testing or custom
// timestamps, use VerifyAt.
//
//   - msgToCheck: The serialized COSE_Sign1 structure
//   - msgToAuth: The same additional authenticated data used during signing
//   - verifier: The xDSA public key to verify against
//   - domain: Application domain for replay protection
//   - maxDrift: Signatures more in the past or future are rejected
//
// Returns the CBOR-decoded payload if verification succeeds.
func Verify[T any](msgToCheck []byte, msgToAuth any, verifier *xdsa.PublicKey, domain []byte, maxDrift *uint64) (T, error) {
	return VerifyAt[T](msgToCheck, msgToAuth, verifier, domain, maxDrift, time.Now().Unix())
}

// VerifyAt validates a COSE_Sign1 digital signature and returns the payload,
// using an explicit current time for drift checking.
//
//   - msgToCheck: The serialized COSE_Sign1 structure
//   - msgToAuth: The same additional authenticated data used during signing
//   - verifier: The xDSA public key to verify against
//   - domain: Application domain for replay protection
//   - maxDrift: Signatures more in the past or future are rejected
//   - now: Unix timestamp in seconds to use for drift checking
//
// Returns the CBOR-decoded payload if verification succeeds.
func VerifyAt[T any](msgToCheck []byte, msgToAuth any, verifier *xdsa.PublicKey, domain []byte, maxDrift *uint64, now int64) (T, error) {
	var zero T
	auth, err := cbor.Marshal(msgToAuth)
	if err != nil {
		return zero, err
	}
	payload, err := verify(msgToCheck, auth, verifier, domain, maxDrift, now)
	if err != nil {
		return zero, err
	}
	var result T
	if err := cbor.Unmarshal(payload, &result); err != nil {
		return zero, err
	}
	return result, nil
}

// verify validates a COSE_Sign1 digital signature and returns the payload (internal).
func verify(msgToCheck, msgToAuth []byte, verifier *xdsa.PublicKey, domain []byte, maxDrift *uint64, now int64) ([]byte, error) {
	// Restrict the user's domain to the context of this library
	info := []byte(DomainPrefix + string(domain))
	aad, err := cbor.Marshal(&sigAAD{
		Info:      info,
		MsgToAuth: msgToAuth,
	})
	if err != nil {
		return nil, err
	}
	// Parse COSE_Sign1
	var sign1 coseSign1
	if err := cbor.Unmarshal(msgToCheck, &sign1); err != nil {
		return nil, err
	}
	// Verify payload is present (embedded)
	if sign1.Payload == nil {
		return nil, ErrMissingPayload
	}
	// Verify the protected header
	header, err := verifySigProtectedHeader(sign1.Protected, algorithmXDSA, verifier)
	if err != nil {
		return nil, err
	}
	// Check signature timestamp drift if maxDrift is specified
	if maxDrift != nil {
		drift := now - header.Timestamp
		if drift < 0 {
			drift = -drift
		}
		if uint64(drift) > *maxDrift {
			return nil, fmt.Errorf("%w: time drift %ds exceeds max %ds", ErrStaleSignature, drift, *maxDrift)
		}
	}
	// Reconstruct Sig_structure to verify
	sig := sigStructure{
		Context:     "Signature1",
		Protected:   sign1.Protected,
		ExternalAAD: aad,
		Payload:     sign1.Payload,
	}
	toBeSigned, _ := cbor.Marshal(&sig)

	// Verify signature
	var xdsasig xdsa.Signature = sign1.Signature
	if err := verifier.Verify(toBeSigned, &xdsasig); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return sign1.Payload, nil
}

// Signer extracts the signer's fingerprint from a COSE_Sign1 signature without
// verifying it.
//
// This allows looking up the appropriate verification key before attempting
// full signature verification.
//
//   - signature: The serialized COSE_Sign1 structure
//
// Returns the signer's fingerprint from the protected header's kid field.
func Signer(signature []byte) (xdsa.Fingerprint, error) {
	var sign1 coseSign1
	if err := cbor.Unmarshal(signature, &sign1); err != nil {
		return xdsa.Fingerprint{}, err
	}
	var header sigProtectedHeader
	if err := cbor.Unmarshal(sign1.Protected, &header); err != nil {
		return xdsa.Fingerprint{}, err
	}
	return header.Kid, nil
}

// Peek extracts the embedded payload from a COSE_Sign1 signature without
// verifying it.
//
// Warning: This function does NOT verify the signature. The returned payload
// is unauthenticated and should not be trusted until verified with Verify.
// Use Signer to extract the signer's fingerprint for key lookup.
//
//   - signature: The serialized COSE_Sign1 structure
//
// Returns the CBOR-decoded payload.
func Peek[T any](signature []byte) (T, error) {
	var zero T

	var sign1 coseSign1
	if err := cbor.Unmarshal(signature, &sign1); err != nil {
		return zero, err
	}
	if sign1.Payload == nil {
		return zero, ErrMissingPayload
	}
	var payload T
	if err := cbor.Unmarshal(sign1.Payload, &payload); err != nil {
		return zero, err
	}
	return payload, nil
}

// Seal signs a message then encrypts it to a recipient.
//
// Uses the current system time as the signature timestamp. For testing or custom
// timestamps, use SealAt.
//
//   - msgToSeal: The message to sign and encrypt
//   - msgToAuth: Additional authenticated data (signed and bound to encryption, but not embedded)
//   - signer: The xDSA secret key to sign with
//   - recipient: The xHPKE public key to encrypt to
//   - domain: Application domain for HPKE key derivation
//
// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
func Seal(msgToSeal, msgToAuth any, signer xdsa.Signer, recipient *xhpke.PublicKey, domain []byte) ([]byte, error) {
	return SealAt(msgToSeal, msgToAuth, signer, recipient, domain, time.Now().Unix())
}

// SealAt signs a message then encrypts it to a recipient with an explicit timestamp.
//
//   - msgToSeal: The message to sign and encrypt
//   - msgToAuth: Additional authenticated data (signed and bound to encryption, but not embedded)
//   - signer: The xDSA secret key to sign with
//   - recipient: The xHPKE public key to encrypt to
//   - domain: Application domain for HPKE key derivation
//   - timestamp: Unix timestamp in seconds to embed in the signature's protected header
//
// Returns the serialized COSE_Encrypt0 structure containing the encrypted COSE_Sign1.
func SealAt(msgToSeal, msgToAuth any, signer xdsa.Signer, recipient *xhpke.PublicKey, domain []byte, timestamp int64) ([]byte, error) {
	// Pre-encode for internal use
	seal, err := cbor.Marshal(msgToSeal)
	if err != nil {
		return nil, err
	}
	auth, err := cbor.Marshal(msgToAuth)
	if err != nil {
		return nil, err
	}
	// Create a COSE_Sign1 with the payload, binding the AAD
	signed := signAt(seal, auth, signer, domain, timestamp)

	// Encrypt the signed message to the recipient
	return Encrypt(signed, cbor.Raw(auth), recipient, domain)
}

// Encrypt encrypts an already-signed COSE_Sign1 to a recipient.
//
// For most use cases, prefer Seal which signs and encrypts in one step.
// Use this only when re-encrypting a message (from Decrypt) to a different
// recipient without access to the original signer's key.
//
//   - sign1: The COSE_Sign1 structure (e.g., from Decrypt)
//   - msgToAuth: The same additional authenticated data used during sealing
//   - recipient: The xHPKE public key to encrypt to
//   - domain: Application domain for HPKE key derivation
//
// Returns the serialized COSE_Encrypt0 structure.
func Encrypt(sign1 []byte, msgToAuth any, recipient *xhpke.PublicKey, domain []byte) ([]byte, error) {
	auth, err := cbor.Marshal(msgToAuth)
	if err != nil {
		return nil, err
	}
	// Build protected header with recipient's fingerprint
	protected, err := cbor.Marshal(&encProtectedHeader{
		Algorithm: algorithmXHPKE,
		Kid:       recipient.Fingerprint(),
	})
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	// Restrict the user's domain to the context of this library
	info := []byte(DomainPrefix + string(domain))

	// Build and seal Enc_structure
	enc := encStructure{
		Context:     "Encrypt0",
		Protected:   protected,
		ExternalAAD: auth,
	}
	aad, err := cbor.Marshal(&enc)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	encapKey, ciphertext, err := recipient.Seal(sign1, aad, info)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	// Build and encode COSE_Encrypt0
	encrypt0 := coseEncrypt0{
		Protected: protected,
		Unprotected: encapKeyHeader{
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

// Open decrypts and verifies a sealed message, returning the payload.
//
// Uses the current system time for drift checking. For testing or custom
// timestamps, use OpenAt.
//
//   - msgToOpen: The serialized COSE_Encrypt0 structure
//   - msgToAuth: The same additional authenticated data used during sealing
//   - recipient: The xHPKE secret key to decrypt with
//   - sender: The xDSA public key to verify the signature against
//   - domain: Application domain for HPKE key derivation
//   - maxDrift: Signatures more in the past or future are rejected
//
// Returns the CBOR-decoded payload if decryption and verification succeed.
func Open[T any](msgToOpen []byte, msgToAuth any, recipient *xhpke.SecretKey, sender *xdsa.PublicKey, domain []byte, maxDrift *uint64) (T, error) {
	return OpenAt[T](msgToOpen, msgToAuth, recipient, sender, domain, maxDrift, time.Now().Unix())
}

// OpenAt decrypts and verifies a sealed message with an explicit current time
// for drift checking.
//
//   - msgToOpen: The serialized COSE_Encrypt0 structure
//   - msgToAuth: The same additional authenticated data used during sealing
//   - recipient: The xHPKE secret key to decrypt with
//   - sender: The xDSA public key to verify the signature against
//   - domain: Application domain for HPKE key derivation
//   - maxDrift: Signatures more in the past or future are rejected
//   - now: Unix timestamp in seconds to use for drift checking
//
// Returns the CBOR-decoded payload if decryption and verification succeed.
func OpenAt[T any](msgToOpen []byte, msgToAuth any, recipient *xhpke.SecretKey, sender *xdsa.PublicKey, domain []byte, maxDrift *uint64, now int64) (T, error) {
	var zero T

	// Decrypt the COSE_Encrypt0 to get the COSE_Sign1
	signed, err := Decrypt(msgToOpen, msgToAuth, recipient, domain)
	if err != nil {
		return zero, err
	}
	// Verify the signature and extract the payload
	payload, err := VerifyAt[T](signed, msgToAuth, sender, domain, maxDrift, now)
	if err != nil {
		return zero, err
	}
	return payload, nil
}

// Decrypt decrypts a sealed message without verifying the signature.
//
// This allows inspecting the signer (via Signer) before verification. Use
// Verify or VerifyAt to verify the decrypted COSE_Sign1 bytes.
//
//   - msgToOpen: The serialized COSE_Encrypt0 structure
//   - msgToAuth: The same additional authenticated data used during sealing
//   - recipient: The xHPKE secret key to decrypt with
//   - domain: Application domain for HPKE key derivation
//
// Returns the decrypted COSE_Sign1 structure (not yet verified).
func Decrypt(msgToOpen []byte, msgToAuth any, recipient *xhpke.SecretKey, domain []byte) ([]byte, error) {
	// Pre-encode for internal use
	auth, err := cbor.Marshal(msgToAuth)
	if err != nil {
		return nil, err
	}
	// Parse COSE_Encrypt0
	var encrypt0 coseEncrypt0
	if err := cbor.Unmarshal(msgToOpen, &encrypt0); err != nil {
		return nil, err
	}
	// Verify protected header
	if err := verifyEncProtectedHeader(encrypt0.Protected, algorithmXHPKE, recipient); err != nil {
		return nil, err
	}
	// Extract encapsulated key from the unprotected headers
	if len(encrypt0.Unprotected.EncapKey) != xhpke.EncapKeySize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidEncapKeySize,
			len(encrypt0.Unprotected.EncapKey), xhpke.EncapKeySize)
	}
	var encapKey [xhpke.EncapKeySize]byte
	copy(encapKey[:], encrypt0.Unprotected.EncapKey)

	// Restrict the user's domain to the context of this library
	info := []byte(DomainPrefix + string(domain))

	// Rebuild and open Enc_structure
	enc := encStructure{
		Context:     "Encrypt0",
		Protected:   encrypt0.Protected,
		ExternalAAD: auth,
	}
	aad, err := cbor.Marshal(&enc)
	if err != nil {
		panic(err) // cannot fail, be loud if it does
	}
	signed, err := recipient.Open(&encapKey, encrypt0.Ciphertext, aad, info)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}
	return signed, nil
}

// Recipient extracts the recipient's fingerprint from a COSE_Encrypt0 message
// without decrypting it.
//
// This allows looking up the appropriate decryption key before attempting
// full decryption.
//
//   - ciphertext: The serialized COSE_Encrypt0 structure
//
// Returns the recipient's fingerprint from the protected header's kid field.
func Recipient(ciphertext []byte) (xhpke.Fingerprint, error) {
	var encrypt0 coseEncrypt0
	if err := cbor.Unmarshal(ciphertext, &encrypt0); err != nil {
		return xhpke.Fingerprint{}, err
	}
	var header encProtectedHeader
	if err := cbor.Unmarshal(encrypt0.Protected, &header); err != nil {
		return xhpke.Fingerprint{}, err
	}
	return header.Kid, nil
}

// verifySigProtectedHeader verifies the signature protected header contains exactly
// the expected algorithm and that the key identifier matches the provided verifier.
// Also verifies the crit header contains the expected critical labels.
func verifySigProtectedHeader(data []byte, expectedAlg int64, verifier *xdsa.PublicKey) (*sigProtectedHeader, error) {
	var header sigProtectedHeader
	if err := cbor.Unmarshal(data, &header); err != nil {
		return nil, err
	}
	if header.Algorithm != expectedAlg {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnexpectedAlgorithm, header.Algorithm, expectedAlg)
	}
	if header.Crit.Timestamp != HeaderTimestamp {
		return nil, fmt.Errorf("%w: crit missing required label %d", ErrUnexpectedAlgorithm, HeaderTimestamp)
	}
	if header.Kid != verifier.Fingerprint() {
		return nil, fmt.Errorf("%w: got %x, want %x", ErrUnexpectedKey, header.Kid, verifier.Fingerprint())
	}
	return &header, nil
}

// verifyEncProtectedHeader verifies the encryption protected header contains exactly
// the expected algorithm and that the key identifier matches the provided recipient.
func verifyEncProtectedHeader(data []byte, expectedAlg int64, recipient *xhpke.SecretKey) error {
	var header encProtectedHeader
	if err := cbor.Unmarshal(data, &header); err != nil {
		return err
	}
	if header.Algorithm != expectedAlg {
		return fmt.Errorf("%w: got %d, want %d", ErrUnexpectedAlgorithm, header.Algorithm, expectedAlg)
	}
	if header.Kid != recipient.Fingerprint() {
		return fmt.Errorf("%w: got %x, want %x", ErrUnexpectedKey, header.Kid, recipient.Fingerprint())
	}
	return nil
}
