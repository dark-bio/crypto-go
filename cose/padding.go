// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file defines sender policies for padding encrypted envelopes.

package cose

import "math"

// Padding is a sender's policy for how many zero bytes to append to the signed
// envelope inside the encryption, so the ciphertext's length shows little about
// the message. This package provides the implementations. Receivers strip any
// number of zeros, so the policy is the sender's alone and can change without
// them.
type Padding interface {
	// paddedSize returns the plaintext size for an envelope of n bytes.
	paddedSize(n int) int
}

// NoPadding encrypts the signed envelope alone.
type NoPadding struct{}

// paddedSize preserves the envelope's size.
func (NoPadding) paddedSize(n int) int { return n }

// BucketPadding pads to the smallest of a series of sizes that fits, starting
// at Floor, with each next size the previous one plus 1/Step of it, rounded up.
// Both parameters must be at least 1.
type BucketPadding struct {
	// Floor is the smallest padded size in bytes.
	Floor int
	// Step divides each size to give its growth, rounded up.
	Step int
}

// paddedSize returns the smallest bucket that fits n bytes. It panics if Floor
// or Step is below 1, or the required bucket size overflows int.
func (p BucketPadding) paddedSize(n int) int {
	// Reject invalid parameters even when the envelope fits the first bucket
	if p.Floor < 1 {
		panic("cose: padding floor must be positive")
	}
	if p.Step < 1 {
		panic("cose: padding step must be positive")
	}

	// Grow by the rounded-up fraction without overflowing either calculation
	size := p.Floor
	for size < n {
		growth := size / p.Step
		if size%p.Step != 0 {
			growth++
		}
		if size > math.MaxInt-growth {
			panic("cose: padding bucket size overflow")
		}
		size += growth
	}
	return size
}
