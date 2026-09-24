// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbor_test

import (
	"errors"
	"fmt"
	"log"

	"github.com/dark-bio/crypto-go/cbor"
)

// Encodes built-in values and decodes them back.
func Example() {
	data, err := cbor.Marshal([]string{"one", "two"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", data)

	var values []string
	if err := cbor.Unmarshal(data, &values); err != nil {
		log.Fatal(err)
	}
	fmt.Println(values)
	// Output:
	// 82636f6e656374776f
	// [one two]
}

// Encodes a struct as an array, its fields in declaration order.
func Example_arrayMode() {
	type Foo struct {
		_ struct{} `cbor:"_,array"`
		A uint64
		B string
	}
	data, err := cbor.Marshal(&Foo{A: 1, B: "x"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", data)

	var foo Foo
	if err := cbor.Unmarshal(data, &foo); err != nil {
		log.Fatal(err)
	}
	fmt.Println(foo.A, foo.B)
	// Output:
	// 82016178
	// 1 x
}

// Encodes a struct as a map with a required, an optional and a nullable field.
func Example_mapMode() {
	type Bar struct {
		X uint64              `cbor:"1,key"`          // required
		Y []byte              `cbor:"2,key,optional"` // omitted when nil
		Z cbor.Option[uint64] `cbor:"3,key"`          // nullable, always present as a value or null
	}
	data, err := cbor.Marshal(&Bar{X: 7})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", data)

	var bar Bar
	if err := cbor.Unmarshal(data, &bar); err != nil {
		log.Fatal(err)
	}
	fmt.Println(bar.X, bar.Y == nil, bar.Z.Some)
	// Output:
	// a2010703f6
	// 7 true false
}

// Flattens an embedded struct's keys into the parent map.
func Example_embedding() {
	type Inner struct {
		A uint64 `cbor:"1,key"`
		B uint64 `cbor:"2,key"`
	}
	type Outer struct {
		Inner        // keys from Inner merge into Outer
		C     uint64 `cbor:"3,key"`
	}
	data, err := cbor.Marshal(&Outer{Inner: Inner{A: 1, B: 2}, C: 3})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", data)
	// Output: a3010102020303
}

// Embeds a struct behind a pointer, so either all of its keys are present or
// none are.
func Example_optionalEmbedding() {
	type Extra struct {
		A uint64 `cbor:"1,key"`
		B uint64 `cbor:"2,key"`
	}
	type Outer struct {
		*Extra        // all Extra keys present, or none
		C      uint64 `cbor:"3,key"`
	}
	data, err := cbor.Marshal(&Outer{C: 3})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", data)

	partial := []byte{0xa2, 0x01, 0x01, 0x03, 0x03} // only one of Extra's keys
	err = cbor.Unmarshal(partial, new(Outer))
	fmt.Println(errors.Is(err, cbor.ErrMissingMapKey))
	// Output:
	// a10303
	// true
}
