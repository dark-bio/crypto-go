// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cwt_test

import (
	"errors"
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/cwt"
	"github.com/dark-bio/crypto-go/cwt/claims"
	"github.com/dark-bio/crypto-go/xdsa"
)

// Issues a device certificate binding the device's key, then verifies it
// inside and outside its validity window.
func Example() {
	type DeviceCert struct {
		claims.Subject
		claims.Expiration
		claims.NotBefore
		claims.Confirm[*xdsa.PublicKey]
		UEID []byte `cbor:"256,key"`
	}
	issuer := xdsa.GenerateKey()
	device := xdsa.GenerateKey()
	now := uint64(1_700_000_000)

	// Example RAND UEID from the generated identity, type 0x01 and 16 identifier bytes.
	// Provision it once and retain it for the device's lifetime, even if keys change.
	fingerprint := device.Fingerprint()
	ueid := append([]byte{0x01}, fingerprint[:16]...)

	cert := &DeviceCert{
		Subject:    claims.Subject{Sub: "ark-0001"},
		Expiration: claims.Expiration{Exp: now + 3600},
		NotBefore:  claims.NotBefore{Nbf: now},
		Confirm:    claims.NewConfirm(device.PublicKey()),
		UEID:       ueid,
	}
	token, err := cwt.Issue(cert, issuer, []byte("device-cert"))
	if err != nil {
		log.Fatal(err)
	}
	check := now + 60
	verified, err := cwt.Verify[DeviceCert](token, issuer.PublicKey(), []byte("device-cert"), &check)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(verified.Sub, verified.Key().Fingerprint() == device.Fingerprint())

	// Outside the validity window the token is rejected
	late := now + 7200
	_, err = cwt.Verify[DeviceCert](token, issuer.PublicKey(), []byte("device-cert"), &late)
	fmt.Println(errors.Is(err, cwt.ErrAlreadyExpired))
	// Output:
	// ark-0001 true
	// true
}
