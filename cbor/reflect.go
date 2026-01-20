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

// Marshaler is the interface for types to marshal themselves to CBOR.
type Marshaler interface {
	MarshalCBOR(enc *Encoder) error
}

// Unmarshaler is the interface for types to unmarshal themselves from CBOR.
// Implementations must use the Decoder's methods to decode values, ensuring
// that type restrictions are enforced even for custom types.
type Unmarshaler interface {
	UnmarshalCBOR(dec *Decoder) error
}

// Marshal encodes a value to CBOR. Supported types:
//   - uint, uint8, uint16, uint32, uint64: positive integers
//   - int, int8, int16, int32, int64: signed integers
//   - string: UTF-8 text strings
//   - []byte, [N]byte: byte strings
//   - structs with `cbor:"_,array"` tag: CBOR arrays (fields in order)
//   - structs with `cbor:"N,key"` tags: CBOR maps with integer keys
//   - types implementing Marshaler: custom CBOR encoding
func Marshal(v any) ([]byte, error) {
	enc := NewEncoder()
	if err := encodeValue(enc, reflect.ValueOf(v), false); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// Unit is a special type that encodes as an empty CBOR array, matching Rust's () unit type.
// Use this for "nothing" values like detached signature payloads.
type Unit struct{}

// unitType is used for type comparison in reflection.
var unitType = reflect.TypeOf(Unit{})

// nullType is used for type comparison in reflection.
var nullType = reflect.TypeOf(Null{})

// Option represents an optional value that encodes as CBOR null when None.
// Use this for top-level optional values; for struct fields, use the "optional" tag instead.
type Option[T any] struct {
	Value T
	Some  bool
}

// MakeSome creates an Option containing a value.
func MakeSome[T any](v T) Option[T] {
	return Option[T]{Value: v, Some: true}
}

// MakeNone creates an empty Option.
func MakeNone[T any]() Option[T] {
	return Option[T]{}
}

// isOptionType checks if a type is Option[T] for some T.
func isOptionType(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	if t.NumField() != 2 {
		return false
	}
	f0, f1 := t.Field(0), t.Field(1)
	return f0.Name == "Value" && f1.Name == "Some" && f1.Type.Kind() == reflect.Bool
}

// encodeValue recursively encodes a reflect.Value to CBOR.
// The optional flag indicates whether nil values are allowed (from struct tag).
func encodeValue(enc *Encoder, v reflect.Value, optional bool) error {
	// Check if the value implements Marshaler (try pointer first, then value)
	if v.CanAddr() {
		if m, ok := v.Addr().Interface().(Marshaler); ok {
			return m.MarshalCBOR(enc)
		}
	}
	if v.CanInterface() {
		if m, ok := v.Interface().(Marshaler); ok {
			return m.MarshalCBOR(enc)
		}
	}
	switch v.Kind() {
	case reflect.Bool:
		enc.EncodeBool(v.Bool())
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		enc.EncodeUint(v.Uint())
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		enc.EncodeInt(v.Int())
		return nil

	case reflect.String:
		return enc.EncodeText(v.String())

	case reflect.Slice:
		// Check for Raw type - pass through bytes directly
		if v.Type() == reflect.TypeOf(Raw{}) {
			enc.buf = append(enc.buf, v.Bytes()...)
			return nil
		}
		// Only []byte is permitted as a variable-length slice
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.IsNil() {
				if !optional {
					return ErrUnexpectedNil
				}
				enc.EncodeNull()
				return nil
			}
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

		// Special case: Unit encodes as empty array (matches Rust's () unit type)
		if t == unitType {
			enc.EncodeArrayHeader(0)
			return nil
		}
		// Special case: Null encodes as CBOR null
		if t == nullType {
			enc.EncodeNull()
			return nil
		}
		// Special case: Option[T] encodes as null if None, or the inner value if Some
		if isOptionType(t) {
			someField := v.FieldByName("Some")
			if !someField.Bool() {
				enc.EncodeNull()
				return nil
			}
			return encodeValue(enc, v.FieldByName("Value"), false)
		}
		// Check for array or tomap tag on the struct
		if wantArray(t) {
			fields := arrayFields(t)
			enc.EncodeArrayHeader(len(fields))
			for _, f := range fields {
				if err := encodeValue(enc, v.FieldByIndex(f.field.Index), f.optional); err != nil {
					return err
				}
			}
			return nil
		}
		// Check for tomap tag - fields must have key tags
		mFields, err := mapFields(t)
		if err != nil {
			return err
		}
		if len(mFields) == 0 && len(structFields(t)) > 0 {
			return fmt.Errorf("%w: struct %s requires cbor:\"_,array\" or cbor:\"N,key\" tags", ErrUnsupportedType, t.Name())
		}
		// Sort fields by key for deterministic encoding
		slices.SortFunc(mFields, func(a, b fieldInfo) int {
			return mapKeyCmp(a.key, b.key)
		})
		enc.EncodeMapHeader(len(mFields))
		for _, mf := range mFields {
			enc.EncodeInt(mf.key)
			if err := encodeValue(enc, v.FieldByIndex(mf.field.Index), mf.optional); err != nil {
				return err
			}
		}
		return nil

	case reflect.Ptr:
		if v.IsNil() {
			if !optional {
				return ErrUnexpectedNil
			}
			enc.EncodeNull()
			return nil
		}
		return encodeValue(enc, v.Elem(), false)

	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedType, v.Type())
	}
}

// Unmarshal decodes CBOR data into a value. v must be a pointer.
func Unmarshal(data []byte, v any) error {
	dec := NewDecoder(data)
	if err := decodeValue(dec, reflect.ValueOf(v), false); err != nil {
		return err
	}
	return dec.Finish()
}

// decodeValue recursively decodes CBOR into a reflect.Value.
// The optional flag indicates whether null values are allowed (from struct tag).
func decodeValue(dec *Decoder, v reflect.Value, optional bool) error {
	// Check if the value implements Unmarshaler (must be addressable pointer receiver)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if u, ok := v.Interface().(Unmarshaler); ok {
			return u.UnmarshalCBOR(dec)
		}
	} else if v.CanAddr() {
		if u, ok := v.Addr().Interface().(Unmarshaler); ok {
			return u.UnmarshalCBOR(dec)
		}
	}
	// Handle pointer types specially - null decodes as nil pointer
	if v.Kind() == reflect.Ptr {
		// Option[T] handles null internally, so don't intercept it here
		if !isOptionType(v.Type().Elem()) {
			if dec.PeekNull() {
				if !optional {
					return ErrUnexpectedNull
				}
				if err := dec.DecodeNull(); err != nil {
					return err
				}
				v.Set(reflect.Zero(v.Type()))
				return nil
			}
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
		optional = false // inner value is no longer optional
	}

	switch v.Kind() {
	case reflect.Bool:
		val, err := dec.DecodeBool()
		if err != nil {
			return err
		}
		v.SetBool(val)
		return nil

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
			if dec.PeekNull() {
				if !optional {
					return ErrUnexpectedNull
				}
				if err := dec.DecodeNull(); err != nil {
					return err
				}
				v.SetBytes(nil)
				return nil
			}
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

		// Special case: Unit decodes from empty array (matches Rust's () unit type)
		if t == unitType {
			length, err := dec.DecodeArrayHeader()
			if err != nil {
				return err
			}
			if length != 0 {
				return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, 0)
			}
			return nil
		}
		// Special case: Null decodes from CBOR null
		if t == nullType {
			return dec.DecodeNull()
		}
		// Special case: Option[T] decodes as None from null, or Some(value) otherwise
		if isOptionType(t) {
			someField := v.FieldByName("Some")
			valueField := v.FieldByName("Value")
			if dec.PeekNull() {
				if err := dec.DecodeNull(); err != nil {
					return err
				}
				someField.SetBool(false)
				valueField.Set(reflect.Zero(valueField.Type()))
				return nil
			}
			if err := decodeValue(dec, valueField, false); err != nil {
				return err
			}
			someField.SetBool(true)
			return nil
		}
		// Check if this is an array struct or tomap struct
		if wantArray(t) {
			fields := arrayFields(t)
			length, err := dec.DecodeArrayHeader()
			if err != nil {
				return err
			}
			if int(length) != len(fields) {
				return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, len(fields))
			}
			for _, f := range fields {
				if err := decodeValue(dec, v.FieldByIndex(f.field.Index), f.optional); err != nil {
					return err
				}
			}
			return nil
		}
		// Must be a tomap struct - fields have key tags
		mFields, err := mapFields(t)
		if err != nil {
			return err
		}
		if len(mFields) == 0 && len(structFields(t)) > 0 {
			return fmt.Errorf("%w: struct %s requires cbor:\"_,array\" or cbor:\"N,key\" tags", ErrUnsupportedType, t.Name())
		}
		// Build lookup from key to field
		keyToField := make(map[int64]fieldInfo, len(mFields))
		for _, mf := range mFields {
			keyToField[mf.key] = mf
		}
		// Decode the map
		length, err := dec.DecodeMapHeader()
		if err != nil {
			return err
		}
		if int(length) != len(mFields) {
			return fmt.Errorf("%w: %d, want %d", ErrUnexpectedItemCount, length, len(mFields))
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
			fi, ok := keyToField[key]
			if !ok {
				return fmt.Errorf("%w: unknown map key %d", ErrUnsupportedType, key)
			}
			if err := decodeValue(dec, v.FieldByIndex(fi.field.Index), fi.optional); err != nil {
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
	field    reflect.StructField
	key      int64
	optional bool
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
		optional := false
		for _, part := range parts[1:] {
			if part == "key" {
				hasKeyAsInt = true
			}
			if part == "optional" {
				optional = true
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
		fields = append(fields, fieldInfo{field: f, key: key, optional: optional})
	}
	return fields, nil
}

// arrayFieldInfo holds a struct field info for array encoding.
type arrayFieldInfo struct {
	field    reflect.StructField
	optional bool
}

// arrayFields extracts fields from an array struct with their optional flags.
func arrayFields(t reflect.Type) []arrayFieldInfo {
	var fields []arrayFieldInfo
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		tag := f.Tag.Get("cbor")
		optional := false
		if tag != "" {
			parts := strings.Split(tag, ",")
			for _, part := range parts[1:] {
				if part == "optional" {
					optional = true
					break
				}
			}
		}
		fields = append(fields, arrayFieldInfo{field: f, optional: optional})
	}
	return fields
}
