// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eat

import (
	"errors"
	"fmt"

	"github.com/dark-bio/crypto-go/cbor"
)

// Errors returned by OEM ID operations.
var (
	ErrInvalidOEMID = errors.New("eat: invalid OEM ID")
)

// OEMID identifies the hardware manufacturer (key 258, RFC 9711 Section 4.2.3).
// The OEM can be identified by a random ID, an IEEE OUI, or an IANA PEN.
type OEMID struct {
	OEM oemidValue `cbor:"258,key"`
}

// NewOEMRandom creates an OEMID from a 16-byte random manufacturer identifier.
func NewOEMRandom(id [16]byte) OEMID {
	return OEMID{OEM: oemidValue{kind: oemidRandom, random: id}}
}

// NewOEMIEEE creates an OEMID from a 3-byte IEEE OUI/MA-L.
func NewOEMIEEE(id [3]byte) OEMID {
	return OEMID{OEM: oemidValue{kind: oemidIEEE, ieee: id}}
}

// NewOEMPEN creates an OEMID from an IANA Private Enterprise Number.
func NewOEMPEN(pen uint64) OEMID {
	return OEMID{OEM: oemidValue{kind: oemidPEN, pen: pen}}
}

// Random returns the 16-byte random OEM ID and true, or zero and false
// if this is not a random OEM ID.
func (o *OEMID) Random() ([16]byte, bool) {
	if o.OEM.kind == oemidRandom {
		return o.OEM.random, true
	}
	return [16]byte{}, false
}

// IEEE returns the 3-byte IEEE OUI/MA-L and true, or zero and false
// if this is not an IEEE OEM ID.
func (o *OEMID) IEEE() ([3]byte, bool) {
	if o.OEM.kind == oemidIEEE {
		return o.OEM.ieee, true
	}
	return [3]byte{}, false
}

// PEN returns the IANA Private Enterprise Number and true, or zero and
// false if this is not a PEN OEM ID.
func (o *OEMID) PEN() (uint64, bool) {
	if o.OEM.kind == oemidPEN {
		return o.OEM.pen, true
	}
	return 0, false
}

// oemidKind discriminates the three OEM ID formats.
type oemidKind uint8

const (
	oemidRandom oemidKind = 1 // 16-byte random
	oemidIEEE   oemidKind = 2 // 3-byte IEEE OUI/MA-L
	oemidPEN    oemidKind = 3 // IANA Private Enterprise Number
)

// oemidValue holds an OEM ID in one of three formats with custom CBOR
// encoding per RFC 9711 Section 4.2.3.
type oemidValue struct {
	kind   oemidKind
	random [16]byte
	ieee   [3]byte
	pen    uint64
}

// MarshalCBOR implements cbor.Marshaler.
func (v *oemidValue) MarshalCBOR(enc *cbor.Encoder) error {
	switch v.kind {
	case oemidRandom:
		enc.EncodeBytes(v.random[:])
	case oemidIEEE:
		enc.EncodeBytes(v.ieee[:])
	case oemidPEN:
		enc.EncodeUint(v.pen)
	default:
		return ErrInvalidOEMID
	}
	return nil
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (v *oemidValue) UnmarshalCBOR(dec *cbor.Decoder) error {
	major, err := dec.PeekMajor()
	if err != nil {
		return err
	}
	switch major {
	case cbor.MajorUint: // integer → PEN
		pen, err := dec.DecodeUint()
		if err != nil {
			return err
		}
		v.kind = oemidPEN
		v.pen = pen

	case cbor.MajorBytes: // byte string → Random or IEEE
		bs, err := dec.DecodeBytes()
		if err != nil {
			return err
		}
		switch len(bs) {
		case 3:
			v.kind = oemidIEEE
			copy(v.ieee[:], bs)
		case 16:
			v.kind = oemidRandom
			copy(v.random[:], bs)
		default:
			return fmt.Errorf("%w: unexpected bstr length %d", ErrInvalidOEMID, len(bs))
		}

	default:
		return fmt.Errorf("%w: unexpected CBOR major type %d", ErrInvalidOEMID, major)
	}
	return nil
}
