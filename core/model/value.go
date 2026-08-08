package model

import (
	"bytes"
	"encoding/json"
)

// Value preserves the three states used by the reference implementation's dynamic schemas:
// a field can be absent, explicitly null, or contain a value. Its zero value
// is Absent.
type Value[T any] struct {
	state valueState
	value T
}

type valueState uint8

const (
	valueAbsent valueState = iota
	valueNull
	valuePresent
)

// Absent returns a value that was not supplied.
func Absent[T any]() Value[T] {
	return Value[T]{}
}

// Null returns a value that was explicitly supplied as null.
func Null[T any]() Value[T] {
	return Value[T]{state: valueNull}
}

// Present returns a supplied, non-null value. The contained Go value can be
// its type's zero value; presence is tracked independently.
func Present[T any](value T) Value[T] {
	return Value[T]{state: valuePresent, value: value}
}

// IsSet reports whether the field was supplied, including explicit null.
func (v Value[T]) IsSet() bool {
	return v.state != valueAbsent
}

// IsNull reports whether the field was explicitly supplied as null.
func (v Value[T]) IsNull() bool {
	return v.state == valueNull
}

// IsZero lets encoding/json's omitzero option omit absent values.
func (v Value[T]) IsZero() bool {
	return v.state == valueAbsent
}

// Get returns the contained value and true only for the present state.
func (v Value[T]) Get() (T, bool) {
	return v.value, v.state == valuePresent
}

// Or returns the contained value, or fallback for absent and null values.
func (v Value[T]) Or(fallback T) T {
	if v.state == valuePresent {
		return v.value
	}
	return fallback
}

// Interface converts the value to the representation used by dynamic records.
// The second return value is false only when the field is absent.
func (v Value[T]) Interface() (any, bool) {
	switch v.state {
	case valueNull:
		return nil, true
	case valuePresent:
		return v.value, true
	default:
		return nil, false
	}
}

func (v Value[T]) MarshalJSON() ([]byte, error) {
	if v.state != valuePresent {
		return []byte("null"), nil
	}
	return json.Marshal(v.value)
}

func (v *Value[T]) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		var zero T
		v.value = zero
		v.state = valueNull
		return nil
	}

	var decoded T
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	v.value = decoded
	v.state = valuePresent
	return nil
}

// Fields contains schema- or plugin-contributed fields. Map membership and
// Value state are both honored so callers can retain absent/null/value exactly.
type Fields map[string]Value[any]

// Set stores a present value.
func (f Fields) Set(name string, value any) {
	f[name] = Present[any](value)
}

// SetNull stores an explicit null.
func (f Fields) SetNull(name string) {
	f[name] = Null[any]()
}

// Unset removes a field, returning it to the absent state.
func (f Fields) Unset(name string) {
	delete(f, name)
}

// Lookup returns the field's tri-state value. A missing key returns Absent.
func (f Fields) Lookup(name string) Value[any] {
	return f[name]
}

// Apply copies all set fields into dst. Explicit null becomes a nil map value;
// absent fields are omitted.
func (f Fields) Apply(dst Record) {
	for name, field := range f {
		if value, ok := field.Interface(); ok {
			dst[name] = value
		}
	}
}

// Record is the dynamic row representation shared with storage adapters. A
// missing key is absent and a present key with a nil value is explicit null.
type Record map[string]any

// FieldsFromRecord extracts every field except the supplied core field names.
func FieldsFromRecord(record Record, coreFields ...string) Fields {
	core := make(map[string]struct{}, len(coreFields))
	for _, name := range coreFields {
		core[name] = struct{}{}
	}

	fields := make(Fields)
	for name, value := range record {
		if _, known := core[name]; known {
			continue
		}
		if value == nil {
			fields[name] = Null[any]()
		} else {
			fields[name] = Present(value)
		}
	}
	return fields
}
