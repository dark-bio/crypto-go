// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package eat defines EAT (Entity Attestation Token) claims.
//
// https://datatracker.ietf.org/doc/html/rfc9711
package eat

// UEID is a globally unique device identifier such as a serial number
// or IMEI (key 256). The value is an opaque byte string including a
// type prefix byte per RFC 9711 Section 4.2.1.
type UEID struct {
	UEID []byte `cbor:"256,key"`
}

// HWModel is the product or board model identifier (key 259).
type HWModel struct {
	HWModel []byte `cbor:"259,key"`
}

// Uptime is the number of seconds since the last boot (key 261).
type Uptime struct {
	Uptime uint64 `cbor:"261,key"`
}

// OEMBoot indicates whether the boot chain is OEM-authorized,
// i.e. secure boot passed (key 262).
type OEMBoot struct {
	OEMBoot bool `cbor:"262,key"`
}

// DebugState represents the debug port state per RFC 9711 Section 4.2.9.
type DebugState uint64

const (
	DebugEnabled                  DebugState = 0 // Debug is currently enabled
	DebugDisabled                 DebugState = 1 // Debug is currently disabled
	DebugDisabledSinceBoot        DebugState = 2 // Debug was disabled at boot and has not been enabled since
	DebugDisabledPermanently      DebugState = 3 // Debug is disabled and cannot be re-enabled
	DebugDisabledFullyPermanently DebugState = 4 // All debug, including DMA-based, is permanently disabled
)

// DebugStatus is the debug port state (key 263).
type DebugStatus struct {
	DebugStatus DebugState `cbor:"263,key"`
}

// BootCount is the number of times the device has booted,
// as a monotonic counter (key 267).
type BootCount struct {
	BootCount uint64 `cbor:"267,key"`
}

// BootSeed is a random value unique to the current boot cycle (key 268).
type BootSeed struct {
	BootSeed []byte `cbor:"268,key"`
}

// SWName is the name of the firmware or software running on the
// device (key 270).
type SWName struct {
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

// IntendedUse is the token's purpose (key 275).
type IntendedUse struct {
	IntendedUse Use `cbor:"275,key"`
}
