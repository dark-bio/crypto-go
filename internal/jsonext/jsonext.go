// crypto-go: cryptography primitives and wrappers
// Copyright 2026 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package jsonext provides strict JSON decoding for text-encoded values.
package jsonext

import (
	"encoding"
	"encoding/json"
	"errors"
)

// ErrNull is returned when a JSON null is decoded into a value that has no
// null form.
var ErrNull = errors.New("jsonext: expected a string, got null")

// UnmarshalText decodes a JSON string into a text unmarshaler. Unlike
// encoding/json, it rejects null instead of leaving the target unchanged.
func UnmarshalText(data []byte, target encoding.TextUnmarshaler) error {
	var text *string
	if err := json.Unmarshal(data, &text); err != nil {
		return err
	}
	if text == nil {
		return ErrNull
	}
	return target.UnmarshalText([]byte(*text))
}
