// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package eat

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dark-bio/crypto-go/cbor"
)

// TestOEMIDRandom verifies round-trip encoding of a random OEM ID.
func TestOEMIDRandom(t *testing.T) {
	id := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	type token struct{ OEMID }
	orig := token{OEMID: NewOEMRandom(id)}

	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	gotID, ok := got.Random()
	if !ok {
		t.Fatalf("expected random OEM ID")
	}
	if gotID != id {
		t.Fatalf("random OEM ID mismatch: got %x, want %x", gotID, id)
	}
}

// TestOEMIDIEEE verifies round-trip encoding of an IEEE OEM ID.
func TestOEMIDIEEE(t *testing.T) {
	id := [3]byte{0xAC, 0xDE, 0x48}

	type token struct{ OEMID }
	orig := token{OEMID: NewOEMIEEE(id)}

	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	gotID, ok := got.IEEE()
	if !ok {
		t.Fatalf("expected IEEE OEM ID")
	}
	if gotID != id {
		t.Fatalf("IEEE OEM ID mismatch: got %x, want %x", gotID, id)
	}
}

// TestOEMIDPEN verifies round-trip encoding of a PEN OEM ID.
func TestOEMIDPEN(t *testing.T) {
	var pen uint64 = 76543

	type token struct{ OEMID }
	orig := token{OEMID: NewOEMPEN(pen)}

	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	gotPEN, ok := got.PEN()
	if !ok {
		t.Fatalf("expected PEN OEM ID")
	}
	if gotPEN != pen {
		t.Fatalf("PEN mismatch: got %d, want %d", gotPEN, pen)
	}
}

// TestOEMIDWrongAccessor verifies that accessors return false for mismatched types.
func TestOEMIDWrongAccessor(t *testing.T) {
	o := NewOEMPEN(42)
	if _, ok := o.Random(); ok {
		t.Fatalf("Random() should return false for PEN")
	}
	if _, ok := o.IEEE(); ok {
		t.Fatalf("IEEE() should return false for PEN")
	}
}

// TestHWVersion verifies round-trip encoding of a hardware version.
func TestHWVersion(t *testing.T) {
	type token struct{ HWVersion }
	orig := token{HWVersion: NewHWVersion("1.2.3")}

	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Version() != "1.2.3" {
		t.Fatalf("version: got %q, want %q", got.Version(), "1.2.3")
	}
}

// TestSWVersion verifies round-trip encoding of a software version.
func TestSWVersion(t *testing.T) {
	type token struct{ SWVersion }
	orig := token{SWVersion: NewSWVersion("4.5.6")}

	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Version() != "4.5.6" {
		t.Fatalf("version: got %q, want %q", got.Version(), "4.5.6")
	}
}

// TestSimpleClaims verifies round-trip encoding of the simple EAT claims.
func TestSimpleClaims(t *testing.T) {
	type token struct {
		UEID
		HWModel
		Uptime
		OEMBoot
		DebugStatus
		BootCount
		BootSeed
		SWName
		IntendedUse
	}
	orig := token{
		UEID:        UEID{UEID: []byte{0x01, 0x02, 0x03}},
		HWModel:     HWModel{HWModel: []byte("board-v2")},
		Uptime:      Uptime{Uptime: 3600},
		OEMBoot:     OEMBoot{OEMBoot: true},
		DebugStatus: DebugStatus{DebugStatus: DebugDisabledPermanently},
		BootCount:   BootCount{BootCount: 42},
		BootSeed:    BootSeed{BootSeed: []byte{0xDE, 0xAD}},
		SWName:      SWName{SWName: "firmware-v3"},
		IntendedUse: IntendedUse{IntendedUse: UseCertIssuance},
	}
	data, err := cbor.Marshal(&orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got token
	if err := cbor.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Uptime.Uptime != 3600 {
		t.Fatalf("uptime: got %d, want 3600", got.Uptime.Uptime)
	}
	if !got.OEMBoot.OEMBoot {
		t.Fatalf("oem boot: got false, want true")
	}
	if got.DebugStatus.DebugStatus != DebugDisabledPermanently {
		t.Fatalf("debug status: got %d, want %d", got.DebugStatus.DebugStatus, DebugDisabledPermanently)
	}
	if got.SWName.SWName != "firmware-v3" {
		t.Fatalf("sw name: got %q, want %q", got.SWName.SWName, "firmware-v3")
	}
	if got.IntendedUse.IntendedUse != UseCertIssuance {
		t.Fatalf("intended use: got %d, want %d", got.IntendedUse.IntendedUse, UseCertIssuance)
	}
	if !bytes.Equal(got.UEID.UEID, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("ueid: got %x, want 010203", got.UEID.UEID)
	}
	if !bytes.Equal(got.HWModel.HWModel, []byte("board-v2")) {
		t.Fatalf("hw model: got %q, want %q", got.HWModel.HWModel, "board-v2")
	}
	if got.BootCount.BootCount != 42 {
		t.Fatalf("boot count: got %d, want 42", got.BootCount.BootCount)
	}
	if !bytes.Equal(got.BootSeed.BootSeed, []byte{0xDE, 0xAD}) {
		t.Fatalf("boot seed: got %x, want DEAD", got.BootSeed.BootSeed)
	}
}

// TestOEMIDInvalidLength tests that a byte string of invalid length is rejected.
func TestOEMIDInvalidLength(t *testing.T) {
	enc := cbor.NewEncoder()
	enc.EncodeMapHeader(1)
	enc.EncodeInt(258)
	enc.EncodeBytes([]byte{1, 2, 3, 4, 5}) // 5 bytes: neither 3 nor 16

	type token struct{ OEMID }
	var got token
	err := cbor.Unmarshal(enc.Bytes(), &got)
	if !errors.Is(err, ErrInvalidOEMID) {
		t.Fatalf("expected ErrInvalidOEMID, got %v", err)
	}
}

// TestOEMIDInvalidType tests that a non-bstr/uint CBOR type is rejected.
func TestOEMIDInvalidType(t *testing.T) {
	enc := cbor.NewEncoder()
	enc.EncodeMapHeader(1)
	enc.EncodeInt(258)
	if err := enc.EncodeText("not-bytes"); err != nil {
		t.Fatalf("encode: %v", err)
	}
	type token struct{ OEMID }
	var got token
	err := cbor.Unmarshal(enc.Bytes(), &got)
	if !errors.Is(err, ErrInvalidOEMID) {
		t.Fatalf("expected ErrInvalidOEMID, got %v", err)
	}
}
