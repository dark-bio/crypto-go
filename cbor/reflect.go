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
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// Encode appends a value to the encoder's buffer using reflection.
func (enc *Encoder) Encode(v any) error {
	return encodeValue(enc, reflect.ValueOf(v), false)
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
				fv, err := fieldByIndex(v, f.field.Index, false)
				if err != nil {
					return err
				}
				if err := encodeValue(enc, fv, f.optional); err != nil {
					return err
				}
			}
			return nil
		}
		// Check for tomap tag - fields must have key tags
		mFields, _, _, err := mapFields(t)
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
		// Count non-nil optional fields to determine the map header size.
		// Optional fields that are nil/None are omitted entirely.
		// Pointer embed fields whose embed pointer is nil are also omitted.
		count := 0
		for _, mf := range mFields {
			fv, err := fieldByIndex(v, mf.field.Index, false)
			if err != nil {
				if mf.ptrGroup > 0 && err == ErrUnexpectedNil {
					continue // nil pointer embed → field absent
				}
				return err
			}
			if !mf.optional || !isOptionalNil(fv) {
				count++
			}
		}
		enc.EncodeMapHeader(count)
		for _, mf := range mFields {
			fv, err := fieldByIndex(v, mf.field.Index, false)
			if err != nil {
				if mf.ptrGroup > 0 && err == ErrUnexpectedNil {
					continue // nil pointer embed → field absent
				}
				return err
			}
			if mf.optional && isOptionalNil(fv) {
				continue
			}
			enc.EncodeInt(mf.key)
			if err := encodeValue(enc, fv, mf.optional); err != nil {
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
	if err := dec.Decode(v); err != nil {
		return err
	}
	return dec.Finish()
}

// Decode reads a value from the decoder using reflection.
func (dec *Decoder) Decode(v any) error {
	return decodeValue(dec, reflect.ValueOf(v), false)
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
		// Option[T] handles null internally, so don't intercept it here.
		// Raw captures any CBOR value (including null) as raw bytes,
		// so don't intercept null for *Raw either.
		if !isOptionType(v.Type().Elem()) && v.Type().Elem() != reflect.TypeOf(Raw{}) {
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
			if err := skipObject(dec, maxDepth); err != nil {
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
				fv, err := fieldByIndex(v, f.field.Index, true)
				if err != nil {
					return err
				}
				if err := decodeValue(dec, fv, f.optional); err != nil {
					return err
				}
			}
			return nil
		}
		// Must be a tomap struct - fields have key tags
		mFields, parents, embeds, err := mapFields(t)
		if err != nil {
			return err
		}
		if len(mFields) == 0 && len(structFields(t)) > 0 {
			return fmt.Errorf("%w: struct %s requires cbor:\"_,array\" or cbor:\"N,key\" tags", ErrUnsupportedType, t.Name())
		}
		// Sort fields by key for deterministic decoding order
		slices.SortFunc(mFields, func(a, b fieldInfo) int {
			return mapKeyCmp(a.key, b.key)
		})
		// Decode the map header
		length, err := dec.DecodeMapHeader()
		if err != nil {
			return err
		}
		if int(length) > len(mFields) {
			return fmt.Errorf("%w: %d, want at most %d", ErrUnexpectedItemCount, length, len(mFields))
		}
		// Walk expected keys in sorted order against actual map entries.
		// Optional fields with missing keys default to zero value; required
		// fields must be present. Pointer embed fields are deferred — they
		// allow missing keys during the walk but validate all-or-none after.
		remaining := int(length)
		decoded := make([]bool, len(mFields))
		for idx, mf := range mFields {
			if remaining > 0 {
				nextKey, err := dec.PeekInt()
				if err != nil {
					return err
				}
				if nextKey == mf.key {
					dec.DecodeInt() // consume the peeked key
					remaining--
					// Optional fields use key omission for absent values,
					// so null is never valid when the key is present.
					if mf.optional && dec.PeekNull() {
						return ErrUnexpectedNull
					}
					fv, err := fieldByIndex(v, mf.field.Index, true)
					if err != nil {
						return err
					}
					if err := decodeValue(dec, fv, mf.optional); err != nil {
						return err
					}
					decoded[idx] = true
					continue
				}
				// Wire key doesn't match and is less than expected. All
				// expected keys below mf.key have been processed, so
				// this key is either known-but-out-of-order or unknown.
				if mapKeyCmp(nextKey, mf.key) < 0 {
					duplicate := false
					known := false
					for j, mf2 := range mFields {
						if mf2.key == nextKey {
							known = true
							duplicate = decoded[j]
							break
						}
					}
					if duplicate {
						return fmt.Errorf("%w: key %d", ErrDuplicateMapKey, nextKey)
					}
					if known {
						return fmt.Errorf("%w: %d must come before %d", ErrInvalidMapKeyOrder, nextKey, mf.key)
					}
					return fmt.Errorf("%w: %d, want at most %d", ErrUnexpectedItemCount, length, len(mFields))
				}
				// Wire key > expected: field is absent from wire data.
			}
			// Key not present (no more wire keys or wire key is past this field)
			if !mf.optional && mf.ptrGroup == 0 {
				return fmt.Errorf("%w: key %d", ErrMissingMapKey, mf.key)
			}
			// Optional field missing: zero to clear stale data from reused
			// destinations. ptrGroup fields are handled by the embed pointer
			// cleanup after validation.
			if mf.optional {
				if fv, err := fieldByIndex(v, mf.field.Index, false); err == nil {
					fv.Set(reflect.Zero(fv.Type()))
				}
			}
		}
		if remaining != 0 {
			// Unconsumed wire keys. Check for duplicate, out-of-order,
			// or unknown keys.
			nextKey, err := dec.PeekInt()
			if err != nil {
				return err
			}
			if mapKeyCmp(nextKey, mFields[len(mFields)-1].key) <= 0 {
				duplicate := false
				known := false
				for j, mf2 := range mFields {
					if mf2.key == nextKey {
						known = true
						duplicate = decoded[j]
						break
					}
				}
				if duplicate {
					return fmt.Errorf("%w: key %d", ErrDuplicateMapKey, nextKey)
				}
				if known {
					return fmt.Errorf("%w: %d must come before %d", ErrInvalidMapKeyOrder, nextKey, mFields[len(mFields)-1].key)
				}
			}
			return fmt.Errorf("%w: %d, want at most %d", ErrUnexpectedItemCount, length, len(mFields))
		}
		// Validate pointer embed all-or-none: if any key from a pointer
		// embed group was decoded, all non-optional keys in that group
		// must also have been decoded. Uses only decode-time state (the
		// decoded slice), not destination pointer values.
		//
		// For nested pointer embeds (*A containing *B), activity in an
		// inner group must propagate to outer groups via the parent
		// hierarchy. Without propagation, decoding a key from *B would
		// not activate *A's group, letting *A's required keys slip by.
		activeGroups := make(map[int]bool)
		for idx, mf := range mFields {
			if mf.ptrGroup > 0 && decoded[idx] {
				activeGroups[mf.ptrGroup] = true
			}
		}
		// Propagate activity upward through the parent chain.
		// Snapshot the initially-active groups to avoid mutating
		// activeGroups during iteration over it.
		initial := make([]int, 0, len(activeGroups))
		for g := range activeGroups {
			initial = append(initial, g)
		}
		for _, g := range initial {
			for p, ok := parents[g]; ok; p, ok = parents[p] {
				activeGroups[p] = true
			}
		}
		for idx, mf := range mFields {
			if mf.ptrGroup == 0 || decoded[idx] || mf.optional {
				continue
			}
			if activeGroups[mf.ptrGroup] {
				return fmt.Errorf("%w: key %d required (pointer embed has other keys present)", ErrMissingMapKey, mf.key)
			}
		}
		// Nil out embed pointers for inactive groups so that reused
		// destinations don't retain stale data from a previous decode.
		for group, embedIdx := range embeds {
			if activeGroups[group] {
				continue
			}
			pv, err := fieldByIndex(v, embedIdx, false)
			if err != nil {
				continue // parent pointer already nil
			}
			if pv.Kind() == reflect.Ptr && !pv.IsNil() {
				pv.Set(reflect.Zero(pv.Type()))
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
	ptrGroup int // >0: field belongs to pointer embed group N (nil = all fields absent)
}

// ptrGroupState tracks pointer embed group IDs and their parent hierarchy
// during field collection. Groups form a tree: when *A contains *B, B's
// group is a child of A's group.
type ptrGroupState struct {
	nextID  int
	parents map[int]int   // child group → parent group; absent = no parent
	embeds  map[int][]int // group → field index path to the embed pointer
}

// mapFields extracts fields with cbor:"N,key" tags from a struct type,
// recursing into anonymous (embedded) struct fields. Returns field info,
// the pointer embed group parent hierarchy (child → parent), the embed
// pointer field-index map (group → index path), and any error.
func mapFields(t reflect.Type) ([]fieldInfo, map[int]int, map[int][]int, error) {
	gs := &ptrGroupState{parents: make(map[int]int), embeds: make(map[int][]int)}
	fields, err := collectMapFields(t, nil, gs, map[reflect.Type]bool{t: true})
	if err != nil {
		return nil, nil, nil, err
	}
	// Detect duplicate keys across all fields (including embedded)
	seen := make(map[int64]string)
	for _, f := range fields {
		if prev, ok := seen[f.key]; ok {
			return nil, nil, nil, fmt.Errorf("%w: duplicate CBOR key %d (fields %s and %s)", ErrUnsupportedType, f.key, prev, f.field.Name)
		}
		seen[f.key] = f.field.Name
	}
	return fields, gs.parents, gs.embeds, nil
}

// collectMapFields recursively collects fields with cbor:"N,key" tags,
// following anonymous (embedded) struct fields. prefix is the field index
// path from the top-level struct to the current type. visited tracks
// types already being collected to detect self-referential embeds.
func collectMapFields(t reflect.Type, prefix []int, gs *ptrGroupState, visited map[reflect.Type]bool) ([]fieldInfo, error) {
	var fields []fieldInfo
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		tag := f.Tag.Get("cbor")
		if tag == "" {
			// Anonymous embedded struct field without a cbor tag: recurse into it.
			if f.Anonymous {
				embedType, ok := embeddedStructType(f.Type)
				if !ok {
					continue
				}
				if visited[embedType] {
					return nil, fmt.Errorf("%w: recursive embed %s", ErrUnsupportedType, embedType.Name())
				}
				if wantArray(embedType) {
					return nil, fmt.Errorf("%w: embedded field %s is array-mode", ErrUnsupportedType, f.Name)
				}
				visited[embedType] = true
				inner := make([]int, len(prefix)+1)
				copy(inner, prefix)
				inner[len(prefix)] = i
				prevID := gs.nextID
				sub, err := collectMapFields(embedType, inner, gs, visited)
				delete(visited, embedType)
				if err != nil {
					return nil, err
				}
				if len(sub) == 0 && len(structFields(embedType)) > 0 {
					return nil, fmt.Errorf("%w: embedded field %s has no CBOR map keys", ErrUnsupportedType, f.Name)
				}
				// Pointer embeds (*T): nil pointer = all fields absent.
				// Assign a group ID so decode can validate all-or-none.
				// Only set the group on fields that don't already belong
				// to a deeper (inner) pointer embed group. Inner groups
				// created during the recursive call become children of
				// this group in the hierarchy.
				if f.Type.Kind() == reflect.Ptr {
					gs.nextID++
					group := gs.nextID
					embedIdx := make([]int, len(inner))
					copy(embedIdx, inner)
					gs.embeds[group] = embedIdx
					for childID := prevID + 1; childID < group; childID++ {
						if _, ok := gs.parents[childID]; !ok {
							gs.parents[childID] = group
						}
					}
					for j := range sub {
						if sub[j].ptrGroup == 0 {
							sub[j].ptrGroup = group
						}
					}
				}
				fields = append(fields, sub...)
			}
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
			if f.Anonymous {
				return nil, fmt.Errorf("%w: anonymous field %s has cbor tag but no integer key", ErrUnsupportedType, f.Name)
			}
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
		if optional && !isOptionalCapable(f.Type) {
			return nil, fmt.Errorf("%w: field %s is optional but type %s is not nilable (use *T, []byte, or Option[T])", ErrUnsupportedType, f.Name, f.Type)
		}
		// Build full field index path for FieldByIndex navigation
		fullIndex := make([]int, len(prefix)+1)
		copy(fullIndex, prefix)
		fullIndex[len(prefix)] = i
		f.Index = fullIndex
		fields = append(fields, fieldInfo{field: f, key: key, optional: optional})
	}
	return fields, nil
}

// embeddedStructType unwraps an anonymous embedded field type and returns the
// struct type it refers to. Supports both T and *T anonymous fields.
func embeddedStructType(t reflect.Type) (reflect.Type, bool) {
	if t.Kind() == reflect.Struct {
		return t, true
	}
	if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct {
		return t.Elem(), true
	}
	return nil, false
}

// fieldByIndex resolves a nested field path, optionally allocating nil pointers
// encountered along the way when create is true.
func fieldByIndex(v reflect.Value, index []int, create bool) (reflect.Value, error) {
	cur := v
	for _, i := range index {
		if cur.Kind() == reflect.Ptr {
			if cur.IsNil() {
				if !create {
					return reflect.Value{}, ErrUnexpectedNil
				}
				cur.Set(reflect.New(cur.Type().Elem()))
			}
			cur = cur.Elem()
		}
		if cur.Kind() != reflect.Struct {
			return reflect.Value{}, fmt.Errorf("%w: %s", ErrUnsupportedType, cur.Type())
		}
		cur = cur.Field(i)
	}
	return cur, nil
}

// isOptionalCapable reports whether a type can meaningfully be optional in a
// map context (i.e., can distinguish "absent" from "zero value"). Only pointer
// types, byte slices, and Option[T] qualify.
func isOptionalCapable(t reflect.Type) bool {
	if t.Kind() == reflect.Ptr || (t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8) {
		return true
	}
	return isOptionType(t)
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

// isOptionalNil reports whether an optional field's value is nil/None and should
// be omitted from map encoding. Handles pointers, nil-able slices, and Option[T].
func isOptionalNil(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Ptr, reflect.Slice:
		return v.IsNil()
	case reflect.Struct:
		if isOptionType(v.Type()) {
			return !v.FieldByName("Some").Bool()
		}
	}
	return false
}
