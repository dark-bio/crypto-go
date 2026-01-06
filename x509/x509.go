// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

// Params contains parameters for creating an X.509 certificate.
type Params struct {
	SubjectName string // Subject's common name (CN) in the certificate
	IssuerName  string // Issuer's common name (CN) in the certificate
	NotBefore   uint64 // Certificate validity start time (unix timestamp)
	NotAfter    uint64 // Certificate validity end time (unix timestamp)
	IsCA        bool   // Whether this certificate is a CA certificate
	PathLen     *uint8 // Max intermediate CAs allowed below this one (only if IsCA is true)
}
