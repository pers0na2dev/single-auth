package mongodb

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pers0na2dev/single-auth/storage"
)

type encodedMutation struct{ values bson.M }

func normalizeInput(configuration *config, model resolvedModel, data storage.Record) (storage.Record, error) {
	normalized := make(storage.Record, len(data))
	for name, value := range data {
		field, err := resolveField(configuration, model, name)
		if err != nil {
			// reference implementation's adapter factory only forwards configured fields.
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
	if id, exists := normalized["id"]; exists {
		if id == nil {
			delete(normalized, "id")
		} else if _, err := encodeID(configuration, id, true); err != nil {
			// ObjectID/UUID modes match reference implementation by replacing an invalid forced
			// identifier with a generated backend-shaped identifier.
			if configuration.idType == TextID {
				return encodedMutation{}, fmt.Errorf("mongodb: encode %s.id: %w", model.canonical, err)
			}
			delete(normalized, "id")
		}
	}
	if _, exists := normalized["id"]; !exists {
		generated, err := generateID(configuration, model.canonical)
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
	mutation := encodedMutation{values: make(bson.M, len(normalized)+2)}
	if id, exists := normalized["id"]; exists {
		encoded, err := encodeID(configuration, id, true)
		if err != nil {
			return encodedMutation{}, fmt.Errorf("mongodb: encode %s.id: %w", model.canonical, err)
		}
		mutation.values["_id"] = encoded
	}

	valueContext := storage.ValueContext{Now: configuration.clock}
	for _, field := range modelFields(model)[1:] {
		value, supplied := normalized[field.canonical]
		var err error
		if create {
			if (!supplied || (value == nil && field.attribute.IsRequired())) && field.attribute.DefaultValue != nil {
				value, err = field.attribute.DefaultValue(valueContext)
				if err != nil {
					return encodedMutation{}, fmt.Errorf("mongodb: default %s.%s: %w", model.canonical, field.canonical, err)
				}
				supplied = true
			}
		} else if !supplied && field.attribute.OnUpdate != nil {
			value, err = field.attribute.OnUpdate(valueContext)
			if err != nil {
				return encodedMutation{}, fmt.Errorf("mongodb: on-update %s.%s: %w", model.canonical, field.canonical, err)
			}
			supplied = true
		}
		if !supplied {
			continue
		}
		encoded, err := encodeValue(configuration, field, value)
		if err != nil {
			return encodedMutation{}, fmt.Errorf("mongodb: encode %s.%s: %w", model.canonical, field.canonical, err)
		}
		mutation.values[field.physical] = encoded
	}
	return mutation, nil
}

func generateID(configuration *config, model string) (any, error) {
	if configuration.idGenerator != nil {
		generated, err := configuration.idGenerator(model)
		if err != nil {
			return nil, fmt.Errorf("mongodb: generate %s ID: %w", model, err)
		}
		if generated == nil {
			return nil, fmt.Errorf("mongodb: generate %s ID: generator returned nil", model)
		}
		return generated, nil
	}
	switch configuration.idType {
	case ObjectID:
		return bson.NewObjectID(), nil
	case UUIDID:
		return newUUIDBinary()
	default:
		return nil, fmt.Errorf("mongodb: no ID generator configured for %q", configuration.idType)
	}
}

func encodeValue(configuration *config, field resolvedField, value any) (any, error) {
	if isIDField(field) {
		if value == nil {
			return nil, nil
		}
		if field.canonical != "id" && field.attribute.Transform.Input != nil {
			transformed, err := field.attribute.Transform.Input(value)
			if err != nil {
				return nil, err
			}
			value = transformed
		}
		return encodeID(configuration, value, true)
	}
	encoded, err := storage.EncodeValue(configuration.capabilities, field.attribute, value)
	if err != nil {
		return nil, err
	}
	return toBSONValue(encoded)
}

func encodeQueryValue(configuration *config, field resolvedField, value any) (any, error) {
	if !isIDField(field) {
		return encodeValue(configuration, field, value)
	}
	if value == nil {
		return nil, nil
	}
	encoded, err := encodeID(configuration, value, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", storage.ErrInvalidQuery, field.canonical, err)
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
	return storage.EncodeValue(configuration.capabilities, attribute, value)
}

func isIDField(field resolvedField) bool {
	return field.canonical == "id" || (field.attribute.References != nil && field.attribute.References.Field == "id")
}

func encodeID(configuration *config, value any, strict bool) (any, error) {
	switch configuration.idType {
	case ObjectID:
		switch typed := value.(type) {
		case bson.ObjectID:
			return typed, nil
		case string:
			identifier, err := bson.ObjectIDFromHex(typed)
			if err == nil {
				return identifier, nil
			}
			if !strict {
				return typed, nil
			}
			return nil, fmt.Errorf("invalid ObjectID %q", typed)
		default:
			return nil, fmt.Errorf("ObjectID has unsupported type %T", value)
		}
	case UUIDID:
		switch typed := value.(type) {
		case bson.Binary:
			if typed.Subtype == 4 && len(typed.Data) == 16 {
				return bson.Binary{Subtype: 4, Data: append([]byte(nil), typed.Data...)}, nil
			}
			return nil, fmt.Errorf("invalid BSON UUID")
		case string:
			identifier, err := parseUUID(typed)
			if err == nil {
				return identifier, nil
			}
			if !strict {
				return typed, nil
			}
			return nil, err
		default:
			return nil, fmt.Errorf("UUID has unsupported type %T", value)
		}
	case TextID:
		if value == nil {
			return nil, fmt.Errorf("text ID is nil")
		}
		switch typed := value.(type) {
		case string:
			return typed, nil
		case []byte:
			return string(typed), nil
		default:
			kind := reflect.TypeOf(value).Kind()
			if kind >= reflect.Int && kind <= reflect.Float64 {
				return fmt.Sprint(value), nil
			}
			return nil, fmt.Errorf("text ID has unsupported type %T", value)
		}
	default:
		return nil, fmt.Errorf("unsupported ID type %q", configuration.idType)
	}
}

func decodeValue(configuration *config, field resolvedField, value any) (any, error) {
	if isIDField(field) {
		decoded, err := decodeID(configuration, value)
		if err != nil {
			return nil, err
		}
		if field.canonical != "id" && field.attribute.Transform.Output != nil {
			return field.attribute.Transform.Output(decoded)
		}
		return decoded, nil
	}
	value = fromBSONValue(value)
	if field.attribute.Type == storage.FieldNumber {
		value = canonicalNumber(value)
	}
	decoded, err := storage.DecodeValue(configuration.capabilities, field.attribute, value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func decodeID(configuration *config, value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch typed := value.(type) {
	case bson.ObjectID:
		return typed.Hex(), nil
	case bson.Binary:
		if typed.Subtype == 4 && len(typed.Data) == 16 {
			return formatUUID(typed.Data), nil
		}
		return nil, fmt.Errorf("decode ID: invalid BSON binary subtype %d", typed.Subtype)
	case string:
		return typed, nil
	case []byte:
		return string(typed), nil
	default:
		if configuration.idType == TextID {
			return fmt.Sprint(value), nil
		}
		return nil, fmt.Errorf("decode ID: expected %s, got %T", configuration.idType, value)
	}
}

func decodeDocument(configuration *config, model resolvedModel, raw bson.M, selected []string) (storage.Record, error) {
	if raw == nil {
		return nil, nil
	}
	var selectedSet map[string]struct{}
	if len(selected) > 0 {
		fields, err := selectedFields(configuration, model, selected)
		if err != nil {
			return nil, err
		}
		selectedSet = make(map[string]struct{}, len(fields))
		for _, field := range fields {
			selectedSet[field.canonical] = struct{}{}
		}
	}
	decoded := make(storage.Record, len(raw))
	for physical, value := range raw {
		field, err := resolvePhysicalField(model, physical)
		if err != nil {
			if errors.Is(err, storage.ErrFieldNotFound) {
				if selectedSet == nil {
					decoded[physical] = fromBSONValue(value)
				}
				continue
			}
			return nil, err
		}
		if selectedSet != nil {
			if _, exists := selectedSet[field.canonical]; !exists {
				continue
			}
		}
		canonical, err := decodeValue(configuration, field, value)
		if err != nil {
			return nil, fmt.Errorf("mongodb: decode %s.%s: %w", model.canonical, field.canonical, err)
		}
		decoded[field.canonical] = canonical
	}
	return decoded, nil
}

func parseUUID(value string) (bson.Binary, error) {
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 {
		return bson.Binary{}, fmt.Errorf("invalid UUID %q", value)
	}
	data, err := hex.DecodeString(compact)
	if err != nil {
		return bson.Binary{}, fmt.Errorf("invalid UUID %q", value)
	}
	return bson.Binary{Subtype: 4, Data: data}, nil
}

func newUUIDBinary() (bson.Binary, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return bson.Binary{}, fmt.Errorf("mongodb: generate UUID: %w", err)
	}
	data[6] = (data[6] & 0x0f) | 0x40
	data[8] = (data[8] & 0x3f) | 0x80
	return bson.Binary{Subtype: 4, Data: data}, nil
}

func formatUUID(data []byte) string {
	encoded := hex.EncodeToString(data)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func canonicalNumber(value any) any {
	switch number := value.(type) {
	case int8:
		return int(number)
	case int16:
		return int(number)
	case int32:
		return int(number)
	case int64:
		if int64(int(number)) == number {
			return int(number)
		}
	case uint:
		if uint64(number) <= math.MaxInt {
			return int(number)
		}
	case uint8:
		return int(number)
	case uint16:
		return int(number)
	case uint32:
		if uint64(number) <= math.MaxInt {
			return int(number)
		}
	case uint64:
		if number <= math.MaxInt {
			return int(number)
		}
	case float32:
		converted := float64(number)
		if converted == math.Trunc(converted) && converted >= math.MinInt64 && converted <= math.MaxInt64 {
			return int(converted)
		}
		return converted
	case float64:
		if !math.IsNaN(number) && !math.IsInf(number, 0) && number == math.Trunc(number) && number >= math.MinInt64 && number <= math.MaxInt64 {
			return int(number)
		}
	}
	return value
}

func toBSONValue(value any) (any, error) {
	if value == nil {
		return nil, nil
	}
	switch typed := value.(type) {
	case bson.ObjectID, bson.Regex, bson.DateTime, time.Time:
		return typed, nil
	case bson.Binary:
		return bson.Binary{Subtype: typed.Subtype, Data: append([]byte(nil), typed.Data...)}, nil
	case bson.M:
		result := make(bson.M, len(typed))
		for key, item := range typed {
			converted, err := toBSONValue(item)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case map[string]any:
		result := make(bson.M, len(typed))
		for key, item := range typed {
			converted, err := toBSONValue(item)
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case bson.A:
		result := make(bson.A, len(typed))
		for index, item := range typed {
			converted, err := toBSONValue(item)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case []any:
		result := make(bson.A, len(typed))
		for index, item := range typed {
			converted, err := toBSONValue(item)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case int:
		return int64(typed), nil
	case int8:
		return int64(typed), nil
	case int16:
		return int64(typed), nil
	case int32:
		return int64(typed), nil
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return nil, fmt.Errorf("number %d exceeds BSON int64", typed)
		}
		return int64(typed), nil
	case uint8:
		return int64(typed), nil
	case uint16:
		return int64(typed), nil
	case uint32:
		return int64(typed), nil
	case uint64:
		if typed > math.MaxInt64 {
			return nil, fmt.Errorf("number %d exceeds BSON int64", typed)
		}
		return int64(typed), nil
	case float32:
		return float64(typed), nil
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Slice, reflect.Array:
		result := make(bson.A, reflected.Len())
		for index := range reflected.Len() {
			converted, err := toBSONValue(reflected.Index(index).Interface())
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	case reflect.Map:
		if reflected.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("BSON document map key has type %s, want string", reflected.Type().Key())
		}
		result := make(bson.M, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			converted, err := toBSONValue(iterator.Value().Interface())
			if err != nil {
				return nil, err
			}
			result[iterator.Key().String()] = converted
		}
		return result, nil
	}
	return value, nil
}

func fromBSONValue(value any) any {
	switch typed := value.(type) {
	case bson.DateTime:
		return typed.Time()
	case bson.Binary:
		return bson.Binary{Subtype: typed.Subtype, Data: append([]byte(nil), typed.Data...)}
	case bson.M:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = fromBSONValue(item)
		}
		return result
	case bson.D:
		result := make(map[string]any, len(typed))
		for _, element := range typed {
			result[element.Key] = fromBSONValue(element.Value)
		}
		return result
	case bson.A:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = fromBSONValue(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = fromBSONValue(item)
		}
		return result
	case int32:
		return int(typed)
	case int64:
		if int64(int(typed)) == typed {
			return int(typed)
		}
	}
	return value
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
