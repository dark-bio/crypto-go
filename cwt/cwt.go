// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cwt implements CBOR Web Tokens on top of COSE Sign1.
//
// https://datatracker.ietf.org/doc/html/rfc8392
//
// Tokens carry a set of claims encoded as a CBOR map. Standard claims are
// provided as embeddable single-field structs (Issuer, Subject, etc.) that
// can be composed into application-specific token types.
//
// # Example
//
//	type DeviceCert struct {
//	    claims.Subject
//	    claims.Expiration
//	    claims.NotBefore
//	    claims.Confirm[*xdsa.PublicKey]
//	    UEID []byte `cbor:"256,key"`
//	}
//
//	token, err := cwt.Issue(cert, signerKey, "device-cert")
//	verified, err := cwt.Verify[DeviceCert](token, issuerPubKey, "device-cert", now)
package cwt

import (
	"errors"
	"fmt"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/cose"
	"github.com/dark-bio/crypto-go/xdsa"
)

// Errors returned by CWT operations.
var (
	ErrMissingNbf     = errors.New("cwt: missing nbf claim")
	ErrNotYetValid    = errors.New("cwt: token not yet valid")
	ErrAlreadyExpired = errors.New("cwt: token already expired")
)

// Issue signs a set of claims as a CWT using COSE Sign1.
//
// The claims value must be a struct whose fields encode as a CBOR map
// (using cbor:"N,key" tags and/or embedded claim types).
func Issue(claims any, signer xdsa.Signer, domain string) ([]byte, error) {
	claimsBytes, err := cbor.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return cose.Sign(cbor.Raw(claimsBytes), cbor.Null{}, signer, []byte(domain))
}

// Verify verifies a CWT's COSE signature and temporal validity, then decodes
// the claims into T.
//
// When now is non-nil, temporal claims are validated: nbf (key 5) must be present
// and nbf <= *now, and if exp (key 4) is present then *now <= exp. When now is nil,
// temporal validation is skipped entirely.
func Verify[T any](data []byte, verifier *xdsa.PublicKey, domain string, now *uint64) (*T, error) {
	// Verify COSE signature (skip COSE drift check — CWT handles temporal validation)
	raw, err := cose.Verify[cbor.Raw](data, cbor.Null{}, verifier, []byte(domain), nil)
	if err != nil {
		return nil, err
	}
	// Extract and validate temporal claims if requested
	if now != nil {
		nbf, exp, err := readTemporalClaims(raw)
		if err != nil {
			return nil, err
		}
		if *now < nbf {
			return nil, fmt.Errorf("%w: nbf %d > now %d", ErrNotYetValid, nbf, *now)
		}
		if exp != nil && *now > *exp {
			return nil, fmt.Errorf("%w: exp %d < now %d", ErrAlreadyExpired, *exp, *now)
		}
	}
	// Decode claims into T
	var result T
	if err := cbor.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Signer extracts the signer's fingerprint from a CWT without verifying
// the signature. The returned data is unauthenticated.
func Signer(data []byte) (xdsa.Fingerprint, error) {
	return cose.Signer(data)
}

// Peek extracts and decodes claims from a CWT without verifying the signature.
//
// Warning: This function does NOT verify the signature. The returned payload
// is unauthenticated and should not be trusted until verified with Verify.
// Use Signer to extract the signer's fingerprint for key lookup. The single
// case for this method is self-signed key discovery.
func Peek[T any](data []byte) (*T, error) {
	raw, err := cose.Peek[cbor.Raw](data)
	if err != nil {
		return nil, err
	}
	var result T
	if err := cbor.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// readTemporalClaims iterates a raw CBOR map looking for exp (key 4) and
// nbf (key 5). Returns nbf (required) and exp (optional, nil if absent).
func readTemporalClaims(raw cbor.Raw) (nbf uint64, exp *uint64, err error) {
	dec := cbor.NewDecoder(raw)

	n, err := dec.DecodeMapHeader()
	if err != nil {
		return 0, nil, err
	}
	var foundNbf bool
	for range n {
		key, err := dec.DecodeInt()
		if err != nil {
			return 0, nil, err
		}
		switch key {
		case 4: // exp
			val, err := dec.DecodeUint()
			if err != nil {
				return 0, nil, err
			}
			exp = &val

		case 5: // nbf
			val, err := dec.DecodeUint()
			if err != nil {
				return 0, nil, err
			}
			nbf = val
			foundNbf = true

		default:
			if _, err := dec.DecodeRaw(); err != nil {
				return 0, nil, err
			}
		}
	}
	if !foundNbf {
		return 0, nil, ErrMissingNbf
	}
	return nbf, exp, nil
}
