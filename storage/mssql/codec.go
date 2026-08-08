package mssql

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

type encodedMutation struct {
	values  map[string]any
	present map[string]bool
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

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
	if id, exists := normalized["id"]; exists && forceAllowID {
		switch configuration.idType {
		case SerialID:
			if _, err := normalizeSerialID(id); err != nil {
				delete(normalized, "id")
			}
		case UUIDID:
			text, ok := id.(string)
			if !ok || !uuidPattern.MatchString(text) {
				delete(normalized, "id")
			}
		}
	}
	if _, exists := normalized["id"]; !exists && !configuration.databaseID {
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
			if configuration.idType == SerialID {
				numericID, err := normalizeSerialID(id)
				if err != nil {
					return encodedMutation{}, fmt.Errorf("mssql: encode %s.id: %w", model.canonical, err)
				}
				id = numericID
			} else {
				id = fmt.Sprint(id)
			}
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
					return encodedMutation{}, fmt.Errorf("mssql: default %s.%s: %w", model.canonical, field.canonical, err)
				}
				supplied = true
			}
		} else if !supplied && field.attribute.OnUpdate != nil {
			value, err = field.attribute.OnUpdate(valueContext)
			if err != nil {
				return encodedMutation{}, fmt.Errorf("mssql: on-update %s.%s: %w", model.canonical, field.canonical, err)
			}
			supplied = true
		}
		if !supplied {
			continue
		}
		encoded, err := encodeValue(configuration, field, value)
		if err != nil {
			return encodedMutation{}, fmt.Errorf("mssql: encode %s.%s: %w", model.canonical, field.canonical, err)
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
		if configuration.idType == SerialID {
			return normalizeSerialID(value)
		}
		return fmt.Sprint(value), nil
	}
	if configuration.idType == SerialID && field.attribute.References != nil && field.attribute.References.Field == "id" {
		if value == nil {
			return nil, nil
		}
		return normalizeSerialID(value)
	}
	if field.attribute.Type == storage.FieldJSON {
		if value == nil {
			return nil, nil
		}
		if field.attribute.Transform.Input != nil {
			transformed, err := field.attribute.Transform.Input(value)
			if err != nil {
				return nil, err
			}
			value = transformed
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("encode JSON field: %w", err)
		}
		return string(encoded), nil
	}
	// reference implementation serializes non-native dates with Date.toISOString(), which
	// always represents the instant in UTC. Keep the same invariant before the
	// value reaches SQL Server's zone-less DATETIME2(3) column.
	if field.attribute.Type == storage.FieldDate {
		if date, ok := value.(time.Time); ok {
			value = date.UTC()
		}
	}
	encoded, err := storage.EncodeValue(configuration.capabilities, field.attribute, value)
	if err != nil || encoded == nil {
		return encoded, err
	}
	if field.attribute.Type == storage.FieldNumber {
		return normalizeNumberForDriver(encoded)
	}
	return encoded, nil
}

func normalizeSerialID(value any) (int64, error) {
	var numeric int64
	switch typed := value.(type) {
	case int:
		numeric = int64(typed)
	case int8:
		numeric = int64(typed)
	case int16:
		numeric = int64(typed)
	case int32:
		numeric = int64(typed)
	case int64:
		numeric = typed
	case uint:
		if uint64(typed) > math.MaxInt32 {
			return 0, fmt.Errorf("serial ID %d exceeds SQL Server INTEGER", typed)
		}
		numeric = int64(typed)
	case uint8:
		numeric = int64(typed)
	case uint16:
		numeric = int64(typed)
	case uint32:
		if typed > math.MaxInt32 {
			return 0, fmt.Errorf("serial ID %d exceeds SQL Server INTEGER", typed)
		}
		numeric = int64(typed)
	case uint64:
		if typed > math.MaxInt32 {
			return 0, fmt.Errorf("serial ID %d exceeds SQL Server INTEGER", typed)
		}
		numeric = int64(typed)
	case float32:
		value := float64(typed)
		if value != math.Trunc(value) {
			return 0, fmt.Errorf("serial ID %v is not integral", typed)
		}
		numeric = int64(value)
	case float64:
		if typed != math.Trunc(typed) {
			return 0, fmt.Errorf("serial ID %v is not integral", typed)
		}
		numeric = int64(typed)
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("serial ID %q: %w", typed, err)
		}
		numeric = parsed
	default:
		return 0, fmt.Errorf("serial ID has unsupported type %T", value)
	}
	if numeric < math.MinInt32 || numeric > math.MaxInt32 {
		return 0, fmt.Errorf("serial ID %d exceeds SQL Server INTEGER", numeric)
	}
	return numeric, nil
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
			return nil, fmt.Errorf("number %d exceeds SQL Server BIGINT", number)
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
			return nil, fmt.Errorf("number %d exceeds SQL Server BIGINT", number)
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
	if field.attribute.References != nil && field.attribute.References.Field == "id" {
		if field.attribute.Transform.Output != nil {
			transformed, err := field.attribute.Transform.Output(value)
			if err != nil {
				return nil, err
			}
			value = transformed
		}
		if value == nil {
			return nil, nil
		}
		// reference implementation always exposes primary and foreign IDs as strings, even
		// when SQL Server stores them as INTEGER IDENTITY values.
		return fmt.Sprint(value), nil
	}
	if field.attribute.Type == storage.FieldJSON {
		if value != nil {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("decode JSON field: expected text, got %T", value)
			}
			var decoded any
			if err := json.Unmarshal([]byte(text), &decoded); err != nil {
				return nil, fmt.Errorf("decode JSON field: %w", err)
			}
			value = decoded
		}
		if field.attribute.Transform.Output != nil {
			return field.attribute.Transform.Output(value)
		}
		return value, nil
	}
	if field.attribute.Type == storage.FieldDate {
		if text, ok := value.(string); ok {
			parsed, err := parseMSSQLTime(text)
			if err != nil {
				return nil, err
			}
			value = parsed
		} else if date, ok := value.(time.Time); ok {
			value = date.UTC()
		}
	}
	if field.attribute.Type == storage.FieldBoolean {
		if text, ok := value.(string); ok {
			switch strings.ToLower(text) {
			case "1", "true":
				value = int64(1)
			case "0", "false":
				value = int64(0)
			default:
				return nil, fmt.Errorf("decode boolean field: invalid value %q", text)
			}
		}
	}
	if field.attribute.Type == storage.FieldNumber {
		if text, ok := value.(string); ok {
			integer, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("decode number field: %w", err)
			}
			value = integer
		}
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

func parseMSSQLTime(value string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.9999999",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05.9999999",
		"2006-01-02 15:04:05",
	}
	for _, format := range formats {
		if parsed, err := time.Parse(format, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("decode date field: invalid SQL Server datetime2 %q", value)
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
