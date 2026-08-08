package storage

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"
)

// RecordSchema is the Go counterpart of reference implementation's toZodSchema helper. It
// selects the fields visible on the input or output side and validates a
// record while stripping unknown fields.
type RecordSchema struct {
	fields map[string]FieldAttribute
}

// ToRecordSchema creates an input schema when clientSide is true and an output
// schema otherwise. Input-disabled and output-disabled fields are omitted on
// their respective side.
func ToRecordSchema(fields map[string]FieldAttribute, clientSide bool) RecordSchema {
	selected := make(map[string]FieldAttribute, len(fields))
	for name, field := range fields {
		if clientSide && !field.IsInput() {
			continue
		}
		if !clientSide && !field.IsReturned() {
			continue
		}
		selected[name] = field
	}
	return RecordSchema{fields: selected}
}

// HasField reports whether a field is part of this input/output schema.
func (schema RecordSchema) HasField(name string) bool {
	_, ok := schema.fields[name]
	return ok
}

// FieldNames returns the selected canonical fields in deterministic order.
func (schema RecordSchema) FieldNames() []string {
	names := make([]string, 0, len(schema.fields))
	for name := range schema.fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Parse validates selected fields and returns a stripped copy. Optional fields
// accept both absence and nil, matching Zod's nullish behavior in reference implementation.
func (schema RecordSchema) Parse(input Record) (Record, error) {
	output := make(Record, len(schema.fields))
	for name, field := range schema.fields {
		value, present := input[name]
		if !present {
			if field.IsRequired() {
				return nil, fmt.Errorf("storage schema: required field %q is missing", name)
			}
			continue
		}
		if value == nil {
			if field.IsRequired() {
				return nil, fmt.Errorf("storage schema: required field %q cannot be null", name)
			}
			output[name] = nil
			continue
		}
		if !validRecordSchemaValue(field, value) {
			return nil, fmt.Errorf("storage schema: field %q is not a valid %s", name, field.Type)
		}
		output[name] = value
	}
	return output, nil
}

func validRecordSchemaValue(field FieldAttribute, value any) bool {
	switch field.Type {
	case FieldString:
		_, ok := value.(string)
		return ok
	case FieldNumber:
		return finiteNumber(value)
	case FieldBoolean:
		_, ok := value.(bool)
		return ok
	case FieldDate:
		_, ok := value.(time.Time)
		return ok
	case FieldStringArray:
		return homogeneousSlice(value, reflect.String)
	case FieldNumberArray:
		return numberSlice(value)
	case FieldEnum:
		candidate, ok := value.(string)
		if !ok {
			return false
		}
		for _, allowed := range field.Enum {
			if candidate == allowed {
				return true
			}
		}
		return false
	case FieldJSON:
		_, err := json.Marshal(value)
		return err == nil
	default:
		return false
	}
}

func finiteNumber(value any) bool {
	switch number := value.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return true
	case float32:
		return !float32IsInvalid(number)
	case float64:
		return !math.IsNaN(number) && !math.IsInf(number, 0)
	case json.Number:
		parsed, err := number.Float64()
		return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
	default:
		return false
	}
}

func float32IsInvalid(value float32) bool {
	converted := float64(value)
	return math.IsNaN(converted) || math.IsInf(converted, 0)
}

func homogeneousSlice(value any, kind reflect.Kind) bool {
	items := reflect.ValueOf(value)
	if items.Kind() != reflect.Slice && items.Kind() != reflect.Array {
		return false
	}
	for index := 0; index < items.Len(); index++ {
		item := items.Index(index)
		for item.Kind() == reflect.Interface {
			if item.IsNil() {
				return false
			}
			item = item.Elem()
		}
		if item.Kind() != kind {
			return false
		}
	}
	return true
}

func numberSlice(value any) bool {
	items := reflect.ValueOf(value)
	if items.Kind() != reflect.Slice && items.Kind() != reflect.Array {
		return false
	}
	for index := 0; index < items.Len(); index++ {
		if !finiteNumber(items.Index(index).Interface()) {
			return false
		}
	}
	return true
}
