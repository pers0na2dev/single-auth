package sqlite

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

type encodedMutation struct {
	values  map[string]any
	present map[string]bool
}

func normalizeInput(configuration *config, model resolvedModel, data storage.Record) (storage.Record, error) {
	normalized := make(storage.Record, len(data))
	for name, value := range data {
		field, err := resolveField(configuration, model, name)
		if err != nil {
			if errors.Is(err, storage.ErrFieldNotFound) {
				continue
			}
			return nil, err
		}
		normalized[field.canonical] = value
	}
	return normalized, nil
}

func encodeCreate(configuration *config, model resolvedModel, data storage.Record, forceAllowID bool) (encodedMutation, error) {
	normalized, err := normalizeInput(configuration, model, data)
	if err != nil {
		return encodedMutation{}, err
	}
	if !forceAllowID {
		delete(normalized, "id")
	}
	if _, exists := normalized["id"]; !exists {
		generated, err := configuration.idGenerator(model.canonical)
		if err != nil {
			return encodedMutation{}, err
		}
		normalized["id"] = generated
	}
	return encodeNormalized(configuration, model, normalized, true)
}

func encodeUpdate(configuration *config, model resolvedModel, data storage.Record) (encodedMutation, error) {
	normalized, err := normalizeInput(configuration, model, data)
	if err != nil {
		return encodedMutation{}, err
	}
	return encodeNormalized(configuration, model, normalized, false)
}

func encodeNormalized(configuration *config, model resolvedModel, normalized storage.Record, create bool) (encodedMutation, error) {
	mutation := encodedMutation{
		values:  make(map[string]any, len(normalized)+2),
		present: make(map[string]bool, len(normalized)+2),
	}
	if id, exists := normalized["id"]; exists {
		if id != nil {
			id = fmt.Sprint(id)
		}
		mutation.values["id"] = id
		mutation.present["id"] = true
	}
	valueContext := storage.ValueContext{Now: configuration.clock}
	for _, field := range modelFields(model)[1:] {
		value, supplied := normalized[field.canonical]
		var err error
		if create {
			if (!supplied || (value == nil && field.attribute.IsRequired())) && field.attribute.DefaultValue != nil {
				value, err = field.attribute.DefaultValue(valueContext)
				if err != nil {
					return encodedMutation{}, fmt.Errorf("sqlite: default %s.%s: %w", model.canonical, field.canonical, err)
				}
				supplied = true
			}
		} else if !supplied && field.attribute.OnUpdate != nil {
			value, err = field.attribute.OnUpdate(valueContext)
			if err != nil {
				return encodedMutation{}, fmt.Errorf("sqlite: on-update %s.%s: %w", model.canonical, field.canonical, err)
			}
			supplied = true
		}
		if !supplied {
			continue
		}
		encoded, err := encodeValue(configuration, field, value)
		if err != nil {
			return encodedMutation{}, fmt.Errorf("sqlite: encode %s.%s: %w", model.canonical, field.canonical, err)
		}
		mutation.values[field.physical] = encoded
		mutation.present[field.physical] = true
	}
	return mutation, nil
}

func encodeValue(configuration *config, field resolvedField, value any) (any, error) {
	if field.canonical == "id" {
		if value == nil {
			return nil, nil
		}
		return fmt.Sprint(value), nil
	}
	encoded, err := storage.EncodeValue(configuration.capabilities, field.attribute, value)
	if err != nil || encoded == nil {
		return encoded, err
	}
	if field.attribute.Type == storage.FieldDate {
		if text, ok := encoded.(string); ok {
			date, parseErr := time.Parse(time.RFC3339Nano, text)
			if parseErr == nil {
				// Fixed-width UTC text preserves chronological order under SQLite's
				// TEXT affinity, including values at an exact second versus values
				// with sub-second precision.
				return date.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"), nil
			}
		}
	}
	if field.attribute.Type == storage.FieldNumber {
		return normalizeNumberForDriver(encoded)
	}
	return encoded, nil
}

func encodeArrayElement(configuration *config, field resolvedField, value any) (any, error) {
	attribute := field.attribute
	if attribute.Transform.Input != nil {
		transformed, err := attribute.Transform.Input(value)
		if err != nil {
			return nil, err
		}
		value = transformed
		attribute.Transform.Input = nil
	}
	switch attribute.Type {
	case storage.FieldStringArray:
		attribute.Type = storage.FieldString
	case storage.FieldNumberArray:
		attribute.Type = storage.FieldNumber
	default:
		return nil, fmt.Errorf("%w: %s is not an array field", storage.ErrInvalidQuery, field.canonical)
	}
	encoded, err := storage.EncodeValue(configuration.capabilities, attribute, value)
	if err != nil || encoded == nil {
		return encoded, err
	}
	if attribute.Type == storage.FieldNumber {
		return normalizeNumberForDriver(encoded)
	}
	return encoded, nil
}

func normalizeNumberForDriver(value any) (any, error) {
	switch number := value.(type) {
	case int:
		return int64(number), nil
	case int8:
		return int64(number), nil
	case int16:
		return int64(number), nil
	case int32:
		return int64(number), nil
	case int64:
		return number, nil
	case uint:
		if uint64(number) > math.MaxInt64 {
			return nil, fmt.Errorf("number %d exceeds SQLite INTEGER", number)
		}
		return int64(number), nil
	case uint8:
		return int64(number), nil
	case uint16:
		return int64(number), nil
	case uint32:
		return int64(number), nil
	case uint64:
		if number > math.MaxInt64 {
			return nil, fmt.Errorf("number %d exceeds SQLite INTEGER", number)
		}
		return int64(number), nil
	case float32:
		return float64(number), nil
	case float64:
		return number, nil
	default:
		return value, nil
	}
}

func decodeValue(configuration *config, field resolvedField, value any) (any, error) {
	if bytes, ok := value.([]byte); ok {
		value = string(bytes)
	}
	if field.canonical == "id" {
		if value == nil {
			return nil, nil
		}
		return fmt.Sprint(value), nil
	}
	decoded, err := storage.DecodeValue(configuration.capabilities, field.attribute, value)
	if err != nil {
		return nil, err
	}
	if field.attribute.Type == storage.FieldNumber {
		switch number := decoded.(type) {
		case int64:
			return int(number), nil
		case float64:
			if !math.IsNaN(number) && !math.IsInf(number, 0) && number == math.Trunc(number) && number >= math.MinInt64 && number <= math.MaxInt64 {
				return int(number), nil
			}
		}
	}
	return decoded, nil
}

func sliceValues(value any) ([]any, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: expected an array", storage.ErrInvalidQuery)
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array {
		return nil, fmt.Errorf("%w: expected an array", storage.ErrInvalidQuery)
	}
	items := make([]any, reflected.Len())
	for index := range reflected.Len() {
		items[index] = reflected.Index(index).Interface()
	}
	return items, nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
