// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file checks padding policies and the encrypted plaintext wire profile.

package cose

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/dark-bio/crypto-go/cbor"
	"github.com/dark-bio/crypto-go/xdsa"
	"github.com/dark-bio/crypto-go/xhpke"
)

// TestPaddingBuckets checks the specified bucket sequences and boundary targets.
func TestPaddingBuckets(t *testing.T) {
	// Pin each rounded-up step independently of the bucket calculation
	for _, tt := range []struct {
		// padding is the sender's bucket policy.
		padding BucketPadding
		// sizes are the fixed expected bucket sizes in bytes.
		sizes []int
	}{
		{BucketPadding{Floor: 8192, Step: 20}, []int{8192, 8602, 9033, 9485, 9960, 10458, 10981, 11531, 12108, 12714}},
		{BucketPadding{Floor: 100, Step: 3}, []int{100, 134, 179, 239, 319, 426}},
	} {
		for i, size := range tt.sizes {
			if got := tt.padding.paddedSize(size); got != size {
				t.Errorf("%v/%d: got %d, want %d", tt.padding, size, got, size)
			}
			if i+1 < len(tt.sizes) {
				if got := tt.padding.paddedSize(size + 1); got != tt.sizes[i+1] {
					t.Errorf("%v/%d: got %d, want %d", tt.padding, size+1, got, tt.sizes[i+1])
				}
			}
		}
	}

	// Check the floor, exact fits, transitions, and a larger envelope
	padding := BucketPadding{Floor: 8192, Step: 20}
	for _, tt := range []struct {
		// size is the input size in bytes.
		size int
		// want is the padded size in bytes.
		want int
	}{
		{0, 8192}, {1, 8192}, {8192, 8192}, {8193, 8602},
		{8602, 8602}, {8603, 9033}, {300000, 303278},
	} {
		if got := padding.paddedSize(tt.size); got != tt.want {
			t.Errorf("%d: got %d, want %d", tt.size, got, tt.want)
		}
	}

	// Preserve unpadded sizes and avoid overflow during ceiling division
	for _, size := range []int{0, 1, 8192, 8193, 300000, math.MaxInt} {
		if got := (NoPadding{}).paddedSize(size); got != size {
			t.Errorf("%d: got %d", size, got)
		}
	}
	if got := (BucketPadding{Floor: math.MaxInt - 1, Step: math.MaxInt}).paddedSize(math.MaxInt); got != math.MaxInt {
		t.Fatalf("padded size: %d", got)
	}
}

// TestPaddingInvalidPolicy checks that every encryption entry point panics on
// nil policies and nonpositive parameters, including when the first bucket fits.
func TestPaddingInvalidPolicy(t *testing.T) {
	// Use valid keys and payloads so each call reaches padding validation
	signer := xdsa.ParseSecretKey([xdsa.SecretKeySize]byte{})
	recipient := xhpke.ParseSecretKey([xhpke.SecretKeySize]byte{}).PublicKey()
	for _, tt := range []struct {
		// name identifies the invalid policy.
		name string
		// padding is the policy expected to panic.
		padding Padding
	}{
		{"nil", nil},
		{"nil-none", (*NoPadding)(nil)},
		{"nil-buckets", (*BucketPadding)(nil)},
		{"zero-floor", BucketPadding{Floor: 0, Step: 20}},
		{"negative-floor", BucketPadding{Floor: -1, Step: 20}},
		{"zero-step", BucketPadding{Floor: 8192, Step: 0}},
		{"negative-step", BucketPadding{Floor: 8192, Step: -1}},
	} {
		for _, entry := range []string{"Seal", "SealAt", "Encrypt"} {
			t.Run(tt.name+"/"+entry, func(t *testing.T) {
				defer func() {
					if recover() == nil {
						t.Fatal("expected panic")
					}
				}()
				switch entry {
				case "Seal":
					_, _ = Seal([]byte{0}, cbor.Null{}, signer, recipient, []byte("padding"), tt.padding)
				case "SealAt":
					_, _ = SealAt([]byte{0}, cbor.Null{}, signer, recipient, []byte("padding"), tt.padding, 1700000000)
				case "Encrypt":
					_, _ = Encrypt([]byte{0}, cbor.Null{}, recipient, []byte("padding"), tt.padding)
				}
			})
		}
	}
}

// TestPaddingBucketOverflow checks that an unrepresentable bucket panics.
func TestPaddingBucketOverflow(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	BucketPadding{Floor: math.MaxInt - 1, Step: 1}.paddedSize(math.MaxInt)
}

// openPlaintext opens the raw AEAD plaintext through xHPKE without stripping
// padding, so tests can inspect the wire profile independently of Decrypt.
func openPlaintext(t *testing.T, envelope []byte, aad any, recipient *xhpke.SecretKey, domain []byte) []byte {
	t.Helper()

	// Rebuild the authenticated headers from the envelope
	var encrypted coseEncrypt0
	if err := cbor.Unmarshal(envelope, &encrypted); err != nil {
		t.Fatal(err)
	}
	auth, err := cbor.Marshal(aad)
	if err != nil {
		t.Fatal(err)
	}
	auth, err = cbor.Marshal(&encStructure{
		Context: "Encrypt0", Protected: encrypted.Protected, ExternalAAD: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Open directly through xHPKE to keep padding visible
	encapKey := [xhpke.EncapKeySize]byte(encrypted.Unprotected.EncapKey)
	plaintext, err := recipient.Open(&encapKey, encrypted.Ciphertext, auth, domain)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

// sealPlaintext encrypts arbitrary plaintext through xHPKE to exercise the
// COSE reader independently of the sender's padding policy.
func sealPlaintext(t *testing.T, plaintext []byte, aad any, recipient *xhpke.PublicKey, domain []byte) []byte {
	t.Helper()

	// Bind the headers and external AAD required by the wire profile
	protected, err := cbor.Marshal(&encProtectedHeader{
		Algorithm: AlgorithmXHPKE, Kid: recipient.Fingerprint(),
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := cbor.Marshal(aad)
	if err != nil {
		t.Fatal(err)
	}
	auth, err = cbor.Marshal(&encStructure{
		Context: "Encrypt0", Protected: protected, ExternalAAD: auth,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Bypass the COSE sender and wrap the raw ciphertext
	encapKey, ciphertext, err := recipient.Seal(plaintext, auth, domain)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cbor.Marshal(&coseEncrypt0{
		Protected:   protected,
		Unprotected: encapKeyHeader{EncapKey: encapKey[:]},
		Ciphertext:  ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

// TestSealedPlaintextPadding checks both policies against a fixed Sign1 and
// exact raw padding bytes for sealing and re-encryption.
func TestSealedPlaintextPadding(t *testing.T) {
	// Reuse the fixed v0.16 signature as the expected plaintext prefix
	fx := fixtures(t, "v0.16.json")
	signer := xdsa.ParseSecretKey([xdsa.SecretKeySize]byte(mustHex(t, fx.XdsaSeed)))
	recipient := xhpke.ParseSecretKey([xhpke.SecretKeySize]byte(mustHex(t, fx.XhpkeSeed)))
	sign1 := mustHex(t, fx.Sign1)
	aad := []byte("cose fixture aad")
	domain := []byte("v016-fixtures")
	for _, tt := range []struct {
		// name identifies the sender's policy.
		name string
		// padding is the policy applied by both entry points.
		padding Padding
		// size is the expected raw plaintext size in bytes.
		size int
		// zeros is the expected count of trailing padding bytes.
		zeros int
	}{
		{"none", NoPadding{}, 3461, 0},
		{"buckets", BucketPadding{Floor: 8192, Step: 20}, 8192, 4731},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Seal a payload and re-encrypt the fixed signature under this policy
			sealed, err := SealAt([]byte("cose fixture payload"), aad, signer, recipient.PublicKey(), domain, tt.padding, 1700000000)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := Encrypt(sign1, aad, recipient.PublicKey(), domain, tt.padding)
			if err != nil {
				t.Fatal(err)
			}

			// Inspect through xHPKE, then check stripping and signature verification
			for i, envelope := range [][]byte{sealed, encrypted} {
				plaintext := openPlaintext(t, envelope, aad, recipient, domain)
				if len(plaintext) != tt.size {
					t.Fatalf("%d: plaintext size %d, want %d", i, len(plaintext), tt.size)
				}
				if !bytes.Equal(plaintext[:3461], sign1) {
					t.Fatalf("%d: signature prefix mismatch", i)
				}
				if !bytes.Equal(plaintext[3461:], make([]byte, tt.zeros)) {
					t.Fatalf("%d: padding mismatch", i)
				}
				decrypted, err := Decrypt(envelope, aad, recipient, domain)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(decrypted, sign1) {
					t.Fatalf("%d: decrypted signature mismatch", i)
				}
				payload, err := Open[[]byte](envelope, aad, recipient, signer.PublicKey(), domain, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(payload, []byte("cose fixture payload")) {
					t.Fatalf("%d: payload %q", i, payload)
				}
			}
		})
	}
}

// TestSealOpenWithPadding checks that structured payloads and authenticated
// data round-trip through Seal with bucket padding.
func TestSealOpenWithPadding(t *testing.T) {
	// Seal structured data using the current timestamp and a bucket policy
	signer := xdsa.GenerateKey()
	recipient := xhpke.GenerateKey()
	payload := testPayload{Num: 123, Str: "foo"}
	aad := testAAD{Str: "bar"}
	envelope, err := Seal(&payload, &aad, signer, recipient.PublicKey(), []byte("baz"), BucketPadding{Floor: 8192, Step: 20})
	if err != nil {
		t.Fatal(err)
	}

	// Check the raw padded size and the decoded payload
	if size := len(openPlaintext(t, envelope, &aad, recipient, []byte("baz"))); size != 8192 {
		t.Fatalf("plaintext size: %d", size)
	}
	recovered, err := Open[testPayload](envelope, &aad, recipient, signer.PublicKey(), []byte("baz"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if recovered != payload {
		t.Fatalf("payload: %+v", recovered)
	}
}

// TestDecryptPaddingValidation accepts off-bucket zero padding and rejects
// nonzeros at its start, middle and end through both Decrypt and Open.
func TestDecryptPaddingValidation(t *testing.T) {
	// Append 37 zeros to the fixed Sign1 independently of the sender's policy
	fx := fixtures(t, "v0.16.json")
	signer := xdsa.ParseSecretKey([xdsa.SecretKeySize]byte(mustHex(t, fx.XdsaSeed)))
	recipient := xhpke.ParseSecretKey([xhpke.SecretKeySize]byte(bytes.Repeat([]byte{7}, 32)))
	sign1 := mustHex(t, fx.Sign1)
	plaintext := make([]byte, 3498)
	copy(plaintext[:3461], sign1)
	aad := []byte("cose fixture aad")
	domain := []byte("v016-fixtures")
	envelope := sealPlaintext(t, plaintext, aad, recipient.PublicKey(), domain)

	// Accept any zero padding length and return the bare signed envelope
	decrypted, err := Decrypt(envelope, aad, recipient, domain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, sign1) {
		t.Fatal("decrypted signature mismatch")
	}
	payload, err := OpenAt[[]byte](envelope, aad, recipient, signer.PublicKey(), domain, uptr(0), 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, []byte("cose fixture payload")) {
		t.Fatalf("payload: %q", payload)
	}

	// Refuse each authenticated nonzero byte without relying on an AEAD failure
	for _, position := range []int{3461, 3479, 3497} {
		for _, b := range []byte{1, 255} {
			t.Run(fmt.Sprintf("%d/%d", position, b), func(t *testing.T) {
				plaintext[position] = b
				envelope := sealPlaintext(t, plaintext, aad, recipient.PublicKey(), domain)
				if _, err := Decrypt(envelope, aad, recipient, domain); !errors.Is(err, ErrInvalidPadding) {
					t.Fatalf("Decrypt: %v", err)
				}
				if _, err := Open[[]byte](envelope, aad, recipient, signer.PublicKey(), domain, nil); !errors.Is(err, ErrInvalidPadding) {
					t.Fatalf("Open: %v", err)
				}
				plaintext[position] = 0
			})
		}
	}
}

// TestDecryptMalformedCBOR rejects the same malformed plaintexts as crypto-rs
// during decryption, before signature verification.
func TestDecryptMalformedCBOR(t *testing.T) {
	recipient := xhpke.ParseSecretKey([xhpke.SecretKeySize]byte(bytes.Repeat([]byte{7}, 32)))
	for _, tt := range []struct {
		// plaintext is a malformed CBOR item to authenticate through xHPKE.
		plaintext []byte
		// want is the structural parsing error.
		want error
	}{
		{[]byte{}, cbor.ErrUnexpectedEOF},
		{[]byte{0x82, 0}, cbor.ErrUnexpectedEOF},
		{[]byte{0x81, 0x42, 0}, cbor.ErrUnexpectedEOF},
		{[]byte{0x18, 0}, cbor.ErrNonCanonical},
		{[]byte{0xc0, 0}, cbor.ErrUnsupportedType},
		{[]byte{0x9f, 0xff}, cbor.ErrInvalidAdditionalInfo},
		{[]byte{0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, cbor.ErrUnexpectedEOF},
		{append(bytes.Repeat([]byte{0x81}, 32), 0), cbor.ErrMaxDepthExceeded},
	} {
		envelope := sealPlaintext(t, tt.plaintext, cbor.Null{}, recipient.PublicKey(), []byte("padding"))
		if _, err := Decrypt(envelope, cbor.Null{}, recipient, []byte("padding")); !errors.Is(err, tt.want) {
			t.Errorf("%x: got %v, want %v", tt.plaintext, err, tt.want)
		}
	}
}

// TestDecryptPreservesCBORItem checks that structural parsing preserves map
// ordering and embedded zeros, leaving schema validation to verification.
func TestDecryptPreservesCBORItem(t *testing.T) {
	// Include out-of-order map keys and a byte string ending in zero
	recipient := xhpke.ParseSecretKey([xhpke.SecretKeySize]byte(bytes.Repeat([]byte{7}, 32)))
	plaintext := []byte{0x82, 0xa2, 2, 0, 1, 0, 0x43, 0, 1, 0, 0, 0, 0}
	envelope := sealPlaintext(t, plaintext, cbor.Null{}, recipient.PublicKey(), []byte("padding"))

	// Preserve the encoded item and remove only the following padding
	decrypted, err := Decrypt(envelope, cbor.Null{}, recipient, []byte("padding"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, []byte{0x82, 0xa2, 2, 0, 1, 0, 0x43, 0, 1, 0}) {
		t.Fatalf("decrypted item: %x", decrypted)
	}
}
