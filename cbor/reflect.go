// crypto-go: cryptography primitives and wrappers
// Copyright 2025 Dark Bio AG. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cbor

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Marshal encodes a value to CBOR. Supported types:
//   - uint, uint8, uint16, uint32, uint64: positive integers
//   - int, int8, int16, int32, int64: signed integers
//   - string: UTF-8 text strings
//   - []byte, [N]byte: byte strings
//   - structs with `cbor:"_,array"` tag: CBOR arrays (fields in order)
//   - structs with `cbor:"N,key"` tags: CBOR maps with integer keys
func Marshal(v any) ([]byte, error) {
	enc := NewEncoder()
	if err := encodeValue(enc, reflect.ValueOf(v)); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// encodeValue recursively encodes a reflect.Value to CBOR.
func encodeValue(enc *Encoder, v reflect.Value) error {
	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		enc.EncodeUint(v.Uint())
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		enc.EncodeInt(v.Int())
		return nil

	case reflect.String:
		enc.EncodeText(v.String())
		return nil

	case reflect.Slice:
		// Check for Raw type - pass through bytes directly
		if v.Type() == reflect.TypeOf(Raw{}) {
			enc.buf = append(enc.buf, v.Bytes()...)
			return nil
		}
		// Only []byte is permitted as a variable-length slice
		if v.Type().Elem().Kind() == reflect.Uint8 {
			enc.EncodeBytes(v.Bytes())
			return nil
		}
		return fmt.Errorf("%w: variable-length slices not permitted, use fixed arrays", ErrUnsupportedType)

	case reflect.Array:
		// Only [N]byte is permitted as a fixed array
		if v.Type().Elem().Kind() == reflect.Uint8 {
			slice := make([]byte, v.Len())
			for i := range v.Len() {
				slice[i] = byte(v.Index(i).Uint())
			}
			enc.EncodeBytes(slice)
			return nil
		}
		return fmt.Errorf("%w: only [N]byte arrays permitted, use structs with array tag", ErrUnsupportedType)

	case reflect.Struct:
		t := v.Type()

		// Count exportable fields
		fields := structFields(t)

		// Special case: empty struct encodes as empty array (matches Rust's () unit type)
		if len(fields) == 0 {
			enc.EncodeArrayHeader(0)
			return nil
		}
		// Check for array or tomap tag on the struct
		if wantArray(t) {
			enc.EncodeArrayHeader(len(fields))
			for _, f := range fields {
				if err := encodeValue(enc, v.FieldByIndex(f.Index)); err != nil {
					return err
				}
			}
			return nil
		}
		// Check for tomap tag - fields must have key tags
		mapFields, err := mapFields(t)
		if err != nil {
			return err
		}
		if len(mapFields) == 0 && len(fields) > 0 {
			return fmt.Errorf("%w: struct %s requires cbor:\"_,array\" or cbor:\"N,key\" tags", ErrUnsupportedType, t.Name())
		}
		// Sort fields by key for deterministic encoding
		slices.SortFunc(mapFields, func(a, b fieldInfo) int {
			return mapKeyCmp(a.key, b.key)
		})
		enc.EncodeMapHeader(len(mapFields))
		for _, mf := range mapFields {
			enc.EncodeInt(mf.key)
			if err := encodeValue(enc, v.FieldByIndex(mf.field.Index)); err != nil {
				return err
			}
		}
		return nil

	case reflect.Ptr:
		if v.IsNil() {
			return fmt.Errorf("%w: nil pointer", ErrUnsupportedType)
		}
		return encodeValue(enc, v.Elem())

	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedType, v.Type())
	}
}

// Unmarshal decodes CBOR data into a value. v must be a pointer.
func Unmarshal(data []byte, v any) error {
	dec := NewDecoder(data)
	if err := decodeValue(dec, reflect.ValueOf(v)); err != nil {
		return err
	}
	return dec.Finish()
}

// decodeValue recursively decodes CBOR into a reflect.Value.
func decodeValue(dec *Decoder, v reflect.Value) error {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := dec.DecodeUint()
		if err != nil {
			return err
		}
		v.SetUint(val)
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := dec.DecodeInt()
		if err != nil {
			return err
		}
		v.SetInt(val)
		return nil

	case reflect.String:
		val, err := dec.DecodeText()
		if err != nil {
			return err
		}
		v.SetString(val)
		return nil

	case reflect.Slice:
		// Check for Raw type - capture bytes without parsing
		if v.Type() == reflect.TypeOf(Raw{}) {
			start := dec.pos
			if err := skipObject(dec); err != nil {
				return err
			}
			v.SetBytes(append([]byte(nil), dec.data[start:dec.pos]...))
			return nil
		}
		// Only []byte is permitted as a variable-length slice
		if v.Type().Elem().Kind() == reflect.Uint8 {
			val, err := dec.DecodeBytes()
			if err != nil {
				return err
			}
			v.SetBytes(val)
			return nil
		}
		return fmt.Errorf("%w: variable-length slices not permitted, use fixed arrays", ErrUnsupportedType)

	case reflect.Array:
		// Only [N]byte is permitted as a fixed array
		if v.Type().Elem().Kind() == reflect.Uint8 {
			val, err := dec.DecodeBytesFixed(v.Len())
			if err != nil {
				return err
			}
			for i := range v.Len() {
				v.Index(i).SetUint(uint64(val[i]))
			}
			return nil
		}
		return fmt.Errorf("%w: only [N]byte arrays permitted, use structs with array tag", ErrUnsupportedType)

	case reflect.Struct:
		t := v.Type()
		fields := structFields(t)

		// Special case: empty struct decodes from empty array (matches Rust's () unit type)
		if len(fields) == 0 {
			length, err := dec.DecodeArrayHeader()
			if err != nil {
				return err
			}
			if length != 0 {
				return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, 0)
			}
			return nil
		}
		// Check if this is an array struct or tomap struct
		if wantArray(t) {
			length, err := dec.DecodeArrayHeader()
			if err != nil {
				return err
			}
			if int(length) != len(fields) {
				return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, len(fields))
			}
			for _, f := range fields {
				if err := decodeValue(dec, v.FieldByIndex(f.Index)); err != nil {
					return err
				}
			}
			return nil
		}
		// Must be a tomap struct - fields have key tags
		mapFields, err := mapFields(t)
		if err != nil {
			return err
		}
		if len(mapFields) == 0 && len(fields) > 0 {
			return fmt.Errorf("%w: struct %s requires cbor:\"_,array\" or cbor:\"N,key\" tags", ErrUnsupportedType, t.Name())
		}
		// Build lookup from key to field
		keyToField := make(map[int64]reflect.StructField, len(mapFields))
		for _, mf := range mapFields {
			keyToField[mf.key] = mf.field
		}
		// Decode the map
		length, err := dec.DecodeMapHeader()
		if err != nil {
			return err
		}
		if int(length) != len(mapFields) {
			return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, len(mapFields))
		}
		var prevKey *int64
		for range length {
			key, err := dec.DecodeInt()
			if err != nil {
				return err
			}
			// Verify deterministic ordering and no duplicates
			if prevKey != nil {
				switch cmp := mapKeyCmp(*prevKey, key); {
				case cmp == 0:
					return fmt.Errorf("%w: %d", ErrDuplicateMapKey, key)
				case cmp > 0:
					return fmt.Errorf("%w: %d must come before %d", ErrInvalidMapKeyOrder, key, *prevKey)
				}
			}
			prevKey = &key
			// Find the field for this key
			field, ok := keyToField[key]
			if !ok {
				return fmt.Errorf("%w: unknown map key %d", ErrUnsupportedType, key)
			}
			if err := decodeValue(dec, v.FieldByIndex(field.Index)); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedType, v.Type())
	}
}

// structFields returns the exported fields of a struct type.
func structFields(t reflect.Type) []reflect.StructField {
	var fields []reflect.StructField
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath == "" { // exported
			fields = append(fields, f)
		}
	}
	return fields
}

// wantArray checks if a struct type has the cbor:"_,array" tag pattern. The tag
// can be on any field and indicates the struct should encode as an array.
func wantArray(t reflect.Type) bool {
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("cbor")
		if tag == "" {
			continue
		}
		parts := strings.Split(tag, ",")
		for _, part := range parts[1:] {
			if part == "array" {
				return true
			}
		}
	}
	return false
}

// fieldInfo holds a struct field and its integer map key.
type fieldInfo struct {
	field reflect.StructField
	key   int64
}

// mapFields extracts fields with cbor:"N,key" tags from a struct type.
// Returns an error if a field has an invalid key tag.
func mapFields(t reflect.Type) ([]fieldInfo, error) {
	var fields []fieldInfo
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		tag := f.Tag.Get("cbor")
		if tag == "" {
			continue
		}
		parts := strings.Split(tag, ",")
		hasKeyAsInt := false
		for _, part := range parts[1:] {
			if part == "key" {
				hasKeyAsInt = true
				break
			}
		}
		if !hasKeyAsInt {
			continue
		}
		// Parse the integer key from the first part
		if parts[0] == "" || parts[0] == "_" {
			return nil, fmt.Errorf("%w: field %s has key but no integer key", ErrUnsupportedType, f.Name)
		}
		key, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: field %s has invalid key key %q", ErrUnsupportedType, f.Name, parts[0])
		}
		fields = append(fields, fieldInfo{field: f, key: key})
	}
	return fields, nil
}
