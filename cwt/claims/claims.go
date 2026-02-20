// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package claims defines the standard CWT claim types.
//
// https://datatracker.ietf.org/doc/html/rfc8392
package claims

// Issuer identifies the principal that issued the token (key 1).
type Issuer struct {
	Iss string `cbor:"1,key"`
}

// Subject identifies the principal that is the subject of the token (key 2).
type Subject struct {
	Sub string `cbor:"2,key"`
}

// Audience identifies the recipients the token is intended for (key 3).
type Audience struct {
	Aud string `cbor:"3,key"`
}

// Expiration is the time on or after which the token must not be accepted (key 4).
type Expiration struct {
	Exp uint64 `cbor:"4,key"`
}

// NotBefore is the time before which the token must not be accepted (key 5).
type NotBefore struct {
	Nbf uint64 `cbor:"5,key"`
}

// IssuedAt is the time at which the token was issued (key 6).
type IssuedAt struct {
	Iat uint64 `cbor:"6,key"`
}

// TokenID is a unique identifier for the token (key 7).
type TokenID struct {
	Cti []byte `cbor:"7,key"`
}
