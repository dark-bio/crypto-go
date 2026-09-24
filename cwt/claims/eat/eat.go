// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package eat defines EAT (Entity Attestation Token) claims.
//
// https://datatracker.ietf.org/doc/html/rfc9711
//
// These types encode claims and validate their supported wire representations.
// Applications must evaluate the claims against their attestation policy and
// enforce RFC 9711's relationships between claims. For example, hwmodel and
// oemboot require oemid, hwversion requires hwmodel, and swversion requires
// swname. DebugDisabledPermanently also requires oemid. These relationships
// are not checked by cwt.Verify.
package eat

import (
	"errors"
	"fmt"

	"github.com/dark-bio/crypto-go/cbor"
)

// Errors returned by EAT claim operations.
var (
	// ErrInvalidDebugState is returned when decoding a debug state outside the
	// five values RFC 9711 defines. The wrapping error carries the value.
	ErrInvalidDebugState = errors.New("eat: invalid debug state")

	// ErrInvalidUse is returned when decoding an intended use outside the five
	// values RFC 9711 defines. The wrapping error carries the value.
	ErrInvalidUse = errors.New("eat: invalid intended use")
)

// UEID is a globally unique device identifier such as a serial number
// or IMEI (key 256). The value is an opaque byte string including a
// type prefix byte per RFC 9711 Section 4.2.1.
//
// A RAND UEID uses prefix 0x01 followed by 16, 24, or 32 bytes of random
// identifier data provisioned once for the device. This type stores the bytes
// as supplied; callers must validate the prefix, length, and identifier policy.
type UEID struct {
	// UEID is the opaque device identifier, its first byte the RFC 9711 type
	// prefix.
	UEID []byte `cbor:"256,key"`
}

// HWModel is the product or board model identifier (key 259).
type HWModel struct {
	// HWModel is the opaque model identifier, as the manufacturer defines it.
	HWModel []byte `cbor:"259,key"`
}

// Uptime is the number of seconds since the last boot (key 261).
type Uptime struct {
	// Uptime is the seconds elapsed since the device last booted.
	Uptime uint64 `cbor:"261,key"`
}

// OEMBoot indicates whether the boot chain is OEM-authorized,
// i.e. secure boot passed (key 262).
type OEMBoot struct {
	// OEMBoot is true when every boot stage was OEM authorized.
	OEMBoot bool `cbor:"262,key"`
}

// DebugState represents the debug port state per RFC 9711 Section 4.2.9.
//
// DebugDisabledPermanently still lets the manufacturer identified by oemid
// re-enable debug, so the oemid claim must be present; the application must
// enforce this. DebugDisabledFullyPermanently lets no one re-enable it.
type DebugState uint64

const (
	DebugEnabled                  DebugState = 0 // Debug is currently enabled
	DebugDisabled                 DebugState = 1 // Debug is currently disabled
	DebugDisabledSinceBoot        DebugState = 2 // Debug was disabled at boot and has not been enabled since
	DebugDisabledPermanently      DebugState = 3 // Debug is disabled since boot, only the manufacturer may re-enable it
	DebugDisabledFullyPermanently DebugState = 4 // All debug is permanently disabled, the manufacturer's included
)

// MarshalCBOR implements cbor.Marshaler.
func (s *DebugState) MarshalCBOR(enc *cbor.Encoder) error {
	enc.EncodeUint(uint64(*s))
	return nil
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (s *DebugState) UnmarshalCBOR(dec *cbor.Decoder) error {
	v, err := dec.DecodeUint()
	if err != nil {
		return err
	}
	if v > 4 {
		return fmt.Errorf("%w: %d", ErrInvalidDebugState, v)
	}
	*s = DebugState(v)
	return nil
}

// DebugStatus is the debug port state (key 263).
type DebugStatus struct {
	// DebugStatus is the state of the device's debug facilities at attestation
	// time.
	DebugStatus DebugState `cbor:"263,key"`
}

// BootCount is the number of times the device has booted,
// as a monotonic counter (key 267).
type BootCount struct {
	// BootCount is the number of boots so far, never decreasing.
	BootCount uint64 `cbor:"267,key"`
}

// BootSeed is a random value unique to the current boot cycle (key 268).
type BootSeed struct {
	// BootSeed is random bytes drawn at boot, the same in every token of one
	// boot cycle.
	BootSeed []byte `cbor:"268,key"`
}

// SWName is the name of the firmware or software running on the
// device (key 270).
type SWName struct {
	// SWName is the name of the running firmware or software.
	SWName string `cbor:"270,key"`
}

// Use represents the token's intended purpose per RFC 9711 Section 4.3.3.
type Use uint64

const (
	UseGeneric           Use = 1 // General-purpose attestation
	UseRegistration      Use = 2 // Attestation for service registration
	UseProvisioning      Use = 3 // Attestation prior to key/config provisioning
	UseCertIssuance      Use = 4 // Attestation for certificate signing requests
	UseProofOfPossession Use = 5 // Attestation accompanying a proof-of-possession
)

// MarshalCBOR implements cbor.Marshaler.
func (u *Use) MarshalCBOR(enc *cbor.Encoder) error {
	enc.EncodeUint(uint64(*u))
	return nil
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (u *Use) UnmarshalCBOR(dec *cbor.Decoder) error {
	v, err := dec.DecodeUint()
	if err != nil {
		return err
	}
	if v < 1 || v > 5 {
		return fmt.Errorf("%w: %d", ErrInvalidUse, v)
	}
	*u = Use(v)
	return nil
}

// IntendedUse is the token's purpose (key 275).
type IntendedUse struct {
	// IntendedUse is the purpose the token was issued for.
	IntendedUse Use `cbor:"275,key"`
}
