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
// Verify checks the signature against the supplied key and, when requested,
// the nbf and exp time bounds. Applications must establish trust in that key,
// check issuer and audience claims, and apply their own attestation policy.
// EAT claim relationships and proof of possession of a cnf key are not
// automatically checked.
package cwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/cose"
	"github.com/dark-bio/crypto-go/xdsa"
)

// Errors returned by CWT operations.
var (
	// ErrMissingNbf is returned by Verify when asked to check time but the
	// claims carry no nbf, key 5.
	ErrMissingNbf = errors.New("cwt: missing nbf claim")

	// ErrNotYetValid is returned by Verify when the token's nbf lies after the
	// time of the check. The wrapping error names both, in seconds since the
	// Unix epoch.
	ErrNotYetValid = errors.New("cwt: token not yet valid")

	// ErrAlreadyExpired is returned by Verify when the token's exp is at or
	// before the time of the check. The wrapping error names both, in seconds
	// since the Unix epoch.
	ErrAlreadyExpired = errors.New("cwt: token already expired")

	// ErrDuplicateKey is returned by Verify when the claims map carries a
	// temporal claim key twice.
	ErrDuplicateKey = errors.New("cwt: duplicate claim key")
)

// Issue signs a set of claims as a CWT using COSE Sign1.
//
// The claims must encode as a deterministic CBOR map.
func Issue(claims any, signer xdsa.Signer, domain []byte) ([]byte, error) {
	return IssueAt(claims, signer, domain, time.Now().Unix())
}

// IssueAt signs a claims map as a CWT with the given Unix timestamp in the
// protected COSE header.
func IssueAt(claims any, signer xdsa.Signer, domain []byte, timestamp int64) ([]byte, error) {
	claimsBytes, err := cbor.Marshal(claims)
	if err != nil {
		return nil, err
	}
	defer clear(claimsBytes)
	if _, err := cbor.NewDecoder(claimsBytes).DecodeMapHeader(); err != nil {
		return nil, err
	}
	if err := cbor.Verify(claimsBytes); err != nil {
		return nil, err
	}
	return cose.SignAt(cbor.Raw(claimsBytes), cbor.Null{}, signer, domain, timestamp)
}

// Verify checks a CWT's COSE signature and deterministic CBOR claims map,
// then decodes the claims into T.
//
// When now is non-nil, temporal claims are validated. The nbf claim (key 5)
// must be present and nbf <= *now, and if the exp claim (key 4) is present then
// *now < exp. When now is nil, temporal validation is skipped entirely.
//
// The COSE signature timestamp is not checked; temporal validity comes from the
// CWT claims. T determines the accepted claim schema. Successful verification
// does not establish issuer trust, enforce an audience, evaluate attestation
// policy or EAT claim relationships, or prove possession of a claims.Confirm
// key. The application must perform those checks.
func Verify[T any](data []byte, verifier *xdsa.PublicKey, domain []byte, now *uint64) (*T, error) {
	// Verify COSE signature (skip COSE drift check, CWT handles temporal validation)
	raw, err := cose.Verify[cbor.Raw](data, cbor.Null{}, verifier, domain, nil)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if err := validateClaims(raw, now); err != nil {
		return nil, err
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

// validateClaims checks the claims map and enforces its time bounds when now is set.
func validateClaims(raw cbor.Raw, now *uint64) error {
	// Read the outer map first to distinguish duplicate temporal claims
	dec := cbor.NewDecoder(raw)
	n, err := dec.DecodeMapHeader()
	if err != nil {
		return err
	}
	var prevVal int64
	var prev *int64
	var nbf, exp cbor.Raw
	for range n {
		key, err := dec.DecodeMapKey(prev)
		if err != nil {
			if errors.Is(err, cbor.ErrDuplicateMapKey) && (*prev == 4 || *prev == 5) {
				return fmt.Errorf("%w: %d", ErrDuplicateKey, *prev)
			}
			return err
		}
		prevVal = key
		prev = &prevVal
		value, err := dec.DecodeRaw()
		if err != nil {
			return err
		}
		switch key {
		case 4:
			exp = value
		case 5:
			nbf = value
		}
	}
	if err := dec.Finish(); err != nil {
		return err
	}
	// Validate nested values and the depth of the complete map
	if err := cbor.Verify(raw); err != nil {
		return err
	}
	if now == nil {
		return nil
	}
	// Decode the time bounds only when the caller requests a time check
	var expires uint64
	if exp != nil {
		expires, err = cbor.NewDecoder(exp).DecodeUint()
		if err != nil {
			return err
		}
	}
	if nbf == nil {
		return ErrMissingNbf
	}
	starts, err := cbor.NewDecoder(nbf).DecodeUint()
	if err != nil {
		return err
	}
	if *now < starts {
		return fmt.Errorf("%w: nbf %d > now %d", ErrNotYetValid, starts, *now)
	}
	if exp != nil && *now >= expires {
		return fmt.Errorf("%w: exp %d <= now %d", ErrAlreadyExpired, expires, *now)
	}
	return nil
}
