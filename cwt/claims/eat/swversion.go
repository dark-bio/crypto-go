// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eat

// SWVersion is the software version identifier (key 271).
type SWVersion struct {
	SWVersion swVersionValue `cbor:"271,key"`
}

// NewSWVersion creates a SWVersion with the given version string.
func NewSWVersion(version string) SWVersion {
	return SWVersion{SWVersion: swVersionValue{Version: version}}
}

// Version returns the software version string.
func (v *SWVersion) Version() string {
	return v.SWVersion.Version
}

// swVersionValue encodes as a 1-element CBOR array per RFC 9711
// Section 4.2.7: [version: tstr]. The optional scheme is not supported.
type swVersionValue struct {
	_       struct{} `cbor:"_,array"`
	Version string
}
