// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package claims

import (
	"errors"
	"fmt"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/cose"
	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// Errors returned by confirmation key operations.
var (
	ErrInvalidKeyType = errors.New("claims: unexpected key type")
	ErrInvalidKeySize = errors.New("claims: unexpected key size")
)

// ConfirmKey is the set of public key types that can be bound to a token
// via the cnf claim.
type ConfirmKey interface {
	*xdsa.PublicKey | *xhpke.PublicKey
}

// Confirm binds a public key to the token via the cnf claim (key 8, RFC 8747).
// The COSE_Key wrapping is handled internally.
type Confirm[T ConfirmKey] struct {
	Cnf confirmValue[T] `cbor:"8,key"`
}

// NewConfirm creates a Confirm value binding the given public key.
func NewConfirm[T ConfirmKey](key T) Confirm[T] {
	return Confirm[T]{Cnf: confirmValue[T]{key: key}}
}

// Key returns the bound public key.
func (c *Confirm[T]) Key() T {
	return c.Cnf.key
}

// confirmValue wraps a public key with CBOR encoding that produces the
// RFC 8747 confirmation key nesting.
type confirmValue[T ConfirmKey] struct {
	key T
}

// MarshalCBOR implements cbor.Marshaler.
func (c *confirmValue[T]) MarshalCBOR(enc *cbor.Encoder) error {
	var kty int64
	var x []byte

	// Marshal the supported key types into CBOR
	switch key := any(c.key).(type) {
	case *xdsa.PublicKey:
		kty = cose.AlgorithmXDSA
		pub := key.Marshal()
		x = pub[:]
	case *xhpke.PublicKey:
		kty = cose.AlgorithmXHPKE
		pub := key.Marshal()
		x = pub[:]
	default:
		panic("unreachable")
	}
	// Envelope the marshaled key into the CWT spec types
	return enc.Encode(&cnfMap{CoseKey: coseKey{Kty: kty, X: x}})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (c *confirmValue[T]) UnmarshalCBOR(dec *cbor.Decoder) error {
	// Decode the CWT claim envelope
	var cnf cnfMap
	if err := dec.Decode(&cnf); err != nil {
		return err
	}
	// Depending on the user's requested key type, enforce fields
	var zero T
	switch any(zero).(type) {
	case *xdsa.PublicKey:
		if cnf.CoseKey.Kty != cose.AlgorithmXDSA {
			return fmt.Errorf("%w: %d, want %d", ErrInvalidKeyType, cnf.CoseKey.Kty, cose.AlgorithmXDSA)
		}
		if len(cnf.CoseKey.X) != xdsa.PublicKeySize {
			return fmt.Errorf("%w: %d, want %d", ErrInvalidKeySize, len(cnf.CoseKey.X), xdsa.PublicKeySize)
		}
		key, err := xdsa.ParsePublicKey([xdsa.PublicKeySize]byte(cnf.CoseKey.X))
		if err != nil {
			return err
		}
		c.key = any(key).(T)

	case *xhpke.PublicKey:
		if cnf.CoseKey.Kty != cose.AlgorithmXHPKE {
			return fmt.Errorf("%w: %d, want %d", ErrInvalidKeyType, cnf.CoseKey.Kty, cose.AlgorithmXHPKE)
		}
		if len(cnf.CoseKey.X) != xhpke.PublicKeySize {
			return fmt.Errorf("%w: %d, want %d", ErrInvalidKeySize, len(cnf.CoseKey.X), xhpke.PublicKeySize)
		}
		key, err := xhpke.ParsePublicKey([xhpke.PublicKeySize]byte(cnf.CoseKey.X))
		if err != nil {
			return err
		}
		c.key = any(key).(T)

	default:
		panic("unreachable")
	}
	return nil
}

// cnfMap is the outer structure of a cnf claim value: { 1: COSE_Key }.
type cnfMap struct {
	CoseKey coseKey `cbor:"1,key"`
}

// coseKey is a minimal COSE_Key: { 1: kty, -2: x }.
type coseKey struct {
	Kty int64  `cbor:"1,key"`
	X   []byte `cbor:"-2,key"`
}
