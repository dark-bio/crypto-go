// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eat

// HWVersion is the hardware revision identifier (key 260).
type HWVersion struct {
	HWVersion hwVersionValue `cbor:"260,key"`
}

// NewHWVersion creates an HWVersion with the given version string.
func NewHWVersion(version string) HWVersion {
	return HWVersion{HWVersion: hwVersionValue{Version: version}}
}

// Version returns the hardware version string.
func (v *HWVersion) Version() string {
	return v.HWVersion.Version
}

// hwVersionValue encodes as a 1-element CBOR array per RFC 9711
// Section 4.2.5: [version: tstr]. The optional scheme is not supported.
type hwVersionValue struct {
	_       struct{} `cbor:"_,array"`
	Version string
}
