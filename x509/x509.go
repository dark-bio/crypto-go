// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

// Template contains parameters for issuing an X.509 certificate.
type Template struct {
	Subject    pkix.Name   // Subject distinguished name
	Issuer     pkix.Name   // Issuer distinguished name
	NotBefore  time.Time   // Certificate validity start time
	NotAfter   time.Time   // Certificate validity end time
	Role       Role        // End-entity or CA role
	Extensions []Extension // Non-standard extensions to append
}

// Verified is the result of a successful certificate verification. It bundles
// the extracted subject public key with the parsed certificate for further
// inspection.
type Verified[K any] struct {
	PublicKey   K                    // Subject public key extracted from certificate SPKI
	Certificate *stdx509.Certificate // Parsed certificate metadata (serial, validity, extensions, etc.)
}

// Role defines the role that an issued certificate may fulfil.
type Role struct {
	isCA    bool
	pathLen *uint8
}

// RoleLeaf returns a Role for an end-entity (leaf) certificate.
func RoleLeaf() Role {
	return Role{isCA: false}
}

// RoleAuthority returns a Role for a certificate authority, with an
// optional path length constraint. The path length limits how many intermediate
// CAs may follow (e.g. 0 means the CA can only sign end-entity certificates).
func RoleAuthority(pathLen *uint8) Role {
	return Role{isCA: true, pathLen: pathLen}
}

// IsCA reports whether this role represents a certificate authority.
func (r Role) IsCA() bool { return r.isCA }

// PathLen returns the path length constraint and whether one is set. It is only
// meaningful for CA roles.
func (r Role) PathLen() (uint8, bool) {
	if r.pathLen == nil {
		return 0, false
	}
	return *r.pathLen, true
}

// Extension is a non-standard X.509 certificate extension.
type Extension struct {
	OID      asn1.ObjectIdentifier // Extension OID
	Critical bool                  // Whether the extension is marked critical
	Value    []byte                // DER-encoded extension payload
}

// validityMode defines how time-based validity is checked during verification.
// It's an internal detail, mostly just to avoid magic numbers.
type validityMode int

const (
	validityNow      validityMode = iota // Check against current wall-clock time
	validityAt                           // Check against a specific time
	validityDisabled                     // Skip time-based checks
)

// ValidityCheck controls time-based validity checking during verification.
type ValidityCheck struct {
	mode validityMode
	at   time.Time // only used when mode == validityAt
}

// ValidityNow returns a ValidityCheck that validates against the current time.
func ValidityNow() ValidityCheck {
	return ValidityCheck{mode: validityNow}
}

// ValidityAt returns a ValidityCheck that validates against a specific time.
func ValidityAt(t time.Time) ValidityCheck {
	return ValidityCheck{mode: validityAt, at: t}
}

// ValidityDisabled returns a ValidityCheck that skips time-based validation.
func ValidityDisabled() ValidityCheck {
	return ValidityCheck{mode: validityDisabled}
}

// Timestamp returns the time to check against and whether time checking is
// enabled. If disabled, ok is false.
func (v ValidityCheck) Timestamp() (t time.Time, ok bool) {
	switch v.mode {
	case validityNow:
		return time.Now(), true
	case validityAt:
		return v.at, true
	default:
		return time.Time{}, false
	}
}

// Sentinel errors for certificate issuance and verification.
var (
	ErrEmptySubject          = errors.New("x509: subject DN must not be empty")
	ErrEmptyIssuer           = errors.New("x509: issuer DN must not be empty")
	ErrInvalidValidity       = errors.New("x509: NotBefore must be before NotAfter")
	ErrReservedExtensionOID  = errors.New("x509: custom extension OID under 2.5.29 is reserved")
	ErrDuplicateExtensionOID = errors.New("x509: duplicate extension OID in template")
	ErrMustBeLeaf            = errors.New("x509: key type can only be end-entity certificate")
	ErrInvalidKeyUsage       = errors.New("x509: key usage does not match certificate role")
	ErrExpiredCertificate    = errors.New("x509: certificate is not valid at the requested time")
	ErrIssuerNotCA           = errors.New("x509: issuer certificate is not a CA")
	ErrIssuerKeyUsage        = errors.New("x509: issuer does not have keyCertSign|cRLSign set")
	ErrIssuerPathLen         = errors.New("x509: issuer pathLenConstraint forbids CA children")
	ErrIssuerDNMismatch      = errors.New("x509: child issuer DN does not match issuer subject DN")
)
