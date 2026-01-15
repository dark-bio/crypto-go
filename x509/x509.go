// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/x509/pkix"
	"time"
)

// Params contains parameters for creating an X.509 certificate.
type Params struct {
	SubjectName pkix.Name // Subject's name in the certificate
	IssuerName  pkix.Name // Issuer's name in the certificate
	NotBefore   time.Time // Certificate validity start time (unix timestamp)
	NotAfter    time.Time // Certificate validity end time (unix timestamp)
	IsCA        bool      // Whether this certificate is a CA certificate
	PathLen     *uint8    // Max intermediate CAs allowed below this one (only if IsCA is true)
}
