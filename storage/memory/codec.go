package memory

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/pers0na2dev/single-auth/storage"
)

type resolvedModel struct {
	canonical string
	physical  string
	schema    storage.ModelSchema
}

type resolvedField struct {
	canonical string
	physical  string
	attribute storage.FieldAttribute
}

func (e *executor) resolveModel(name string) (resolvedModel, error) {
	table, canonical, err := e.config.schema.ResolveModel(name)
	if err != nil {
		return resolvedModel{}, err
	}
	physical := table.ModelName
	if e.config.schema.UsePlural {
		physical += "s"
	}
	return resolvedModel{canonical: canonical, physical: physical, schema: table}, nil
}

func (e *executor) resolveField(model resolvedModel, name string) (resolvedField, error) {
	attribute, canonical, err := e.config.schema.ResolveField(model.canonical, name)
	if err != nil {
		return resolvedField{}, err
	}
	physical := attribute.FieldName
	if physical == "" {
		physical = canonical
	}
	return resolvedField{canonical: canonical, physical: physical, attribute: attribute}, nil
}

func (e *executor) encodeCreate(model resolvedModel, data storage.Record, forceAllowID bool) (storage.Record, error) {
	normalized, err := e.normalizeInput(model, data)
	if err != nil {
		return nil, err
	}
	if !forceAllowID {
		delete(normalized, "id")
	}
	if _, exists := normalized["id"]; !exists {
		generated, err := e.config.idGenerator(model.canonical)
		if err != nil {
			return nil, err
		}
		normalized["id"] = generated
	}
	return e.encodeNormalized(model, normalized, true)
}

func (e *executor) encodeUpdate(model resolvedModel, data storage.Record) (storage.Record, error) {
	normalized, err := e.normalizeInput(model, data)
	if err != nil {
		return nil, err
	}
	return e.encodeNormalized(model, normalized, false)
}

func (e *executor) normalizeInput(model resolvedModel, data storage.Record) (storage.Record, error) {
	normalized := make(storage.Record, len(data))
	for name, value := range data {
		field, err := e.resolveField(model, name)
		if err != nil {
			// reference implementation's adapter factory iterates known schema fields, so unknown
			// properties never reach the concrete adapter.
			if errors.Is(err, storage.ErrFieldNotFound) {
				continue
			}
			return nil, err
		}
		normalized[field.canonical] = value
	}
	return normalized, nil
}

func (e *executor) encodeNormalized(model resolvedModel, normalized storage.Record, create bool) (storage.Record, error) {
	encoded := make(storage.Record, len(normalized)+2)
	valueContext := storage.ValueContext{Now: e.config.clock}

	if id, exists := normalized["id"]; exists {
		encoded["id"] = cloneValue(id)
	}
	for canonical, attribute := range model.schema.Fields {
		value, supplied := normalized[canonical]
		if create {
			if (!supplied || (value == nil && attribute.IsRequired())) && attribute.DefaultValue != nil {
				var err error
				value, err = attribute.DefaultValue(valueContext)
				if err != nil {
					return nil, fmt.Errorf("memory: default %s.%s: %w", model.canonical, canonical, err)
				}
				supplied = true
			}
		} else if !supplied && attribute.OnUpdate != nil {
			var err error
			value, err = attribute.OnUpdate(valueContext)
			if err != nil {
				return nil, fmt.Errorf("memory: on-update %s.%s: %w", model.canonical, canonical, err)
			}
			supplied = true
		}
		if !supplied {
			continue
		}
		field := attribute
		if field.FieldName == "" {
			field.FieldName = canonical
		}
		value, err := storage.EncodeValue(e.config.capabilities, field, cloneValue(value))
		if err != nil {
			return nil, fmt.Errorf("memory: encode %s.%s: %w", model.canonical, canonical, err)
		}
		encoded[field.FieldName] = value
	}
	return encoded, nil
}

func (e *executor) encodeWhere(model resolvedModel, clauses []storage.Where) ([]storage.Where, error) {
	if clauses == nil {
		return nil, nil
	}
	encoded := make([]storage.Where, 0, len(clauses))
	for _, unsafe := range clauses {
		clause, err := unsafe.Normalize()
		if err != nil {
			return nil, err
		}
		field, err := e.resolveField(model, clause.Field)
		if err != nil {
			return nil, err
		}
		clause.Field = field.physical
		if clause.Operator == storage.OpIn || clause.Operator == storage.OpNotIn {
			items, err := sliceValues(clause.Value)
			if err != nil {
				return nil, err
			}
			converted := make([]any, 0, len(items))
			for _, item := range items {
				value, err := storage.EncodeValue(e.config.capabilities, field.attribute, cloneValue(item))
				if err != nil {
					return nil, fmt.Errorf("memory: encode where %s.%s: %w", model.canonical, field.canonical, err)
				}
				converted = append(converted, value)
			}
			clause.Value = converted
		} else {
			clause.Value, err = storage.EncodeValue(e.config.capabilities, field.attribute, cloneValue(clause.Value))
			if err != nil {
				return nil, fmt.Errorf("memory: encode where %s.%s: %w", model.canonical, field.canonical, err)
			}
		}
		encoded = append(encoded, clause)
	}
	return encoded, nil
}

func (e *executor) decodeRecord(model resolvedModel, raw storage.Record, selectFields []string) (storage.Record, error) {
	if raw == nil {
		return nil, nil
	}
	selected, err := e.selectedFields(model, selectFields)
	if err != nil {
		return nil, err
	}
	decoded := make(storage.Record, len(raw))
	for physical, value := range raw {
		field, err := e.resolveField(model, physical)
		if err != nil {
			if errors.Is(err, storage.ErrFieldNotFound) {
				if selected == nil {
					decoded[physical] = cloneValue(value)
				}
				continue
			}
			return nil, err
		}
		if selected != nil {
			if _, ok := selected[field.canonical]; !ok {
				continue
			}
		}
		if field.canonical == "id" {
			if value == nil {
				decoded["id"] = nil
			} else {
				decoded["id"] = fmt.Sprint(value)
			}
			continue
		}
		value, err = storage.DecodeValue(e.config.capabilities, field.attribute, cloneValue(value))
		if err != nil {
			return nil, fmt.Errorf("memory: decode %s.%s: %w", model.canonical, field.canonical, err)
		}
		decoded[field.canonical] = value
	}
	return decoded, nil
}

func (e *executor) selectedFields(model resolvedModel, fields []string) (map[string]struct{}, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	selected := make(map[string]struct{}, len(fields))
	for _, name := range fields {
		field, err := e.resolveField(model, name)
		if err != nil {
			return nil, err
		}
		selected[field.canonical] = struct{}{}
	}
	return selected, nil
}

func (e *executor) physicalSelect(model resolvedModel, fields []string) ([]string, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	physical := make([]string, 0, len(fields))
	seen := map[string]struct{}{}
	for _, name := range fields {
		field, err := e.resolveField(model, name)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[field.physical]; !exists {
			physical = append(physical, field.physical)
			seen[field.physical] = struct{}{}
		}
	}
	return physical, nil
}

func (e *executor) encodeSort(model resolvedModel, sortBy *storage.Sort) (*storage.Sort, error) {
	if sortBy == nil {
		return nil, nil
	}
	if sortBy.Direction != storage.Ascending && sortBy.Direction != storage.Descending {
		return nil, fmt.Errorf("%w: invalid sort direction %q", storage.ErrInvalidQuery, sortBy.Direction)
	}
	field, err := e.resolveField(model, sortBy.Field)
	if err != nil {
		return nil, err
	}
	return &storage.Sort{Field: field.physical, Direction: sortBy.Direction}, nil
}

func sliceValues(value any) ([]any, error) {
	if value == nil {
		return nil, fmt.Errorf("%w: expected an array", storage.ErrInvalidQuery)
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Slice && reflected.Kind() != reflect.Array {
		return nil, fmt.Errorf("%w: expected an array", storage.ErrInvalidQuery)
	}
	values := make([]any, reflected.Len())
	for index := 0; index < reflected.Len(); index++ {
		values[index] = reflected.Index(index).Interface()
	}
	return values, nil
}

func addNumeric(current any, delta float64) (any, error) {
	switch value := current.(type) {
	case nil:
		return delta, nil
	case int:
		if isIntegral(delta) {
			return value + int(delta), nil
		}
		return float64(value) + delta, nil
	case int8:
		if isIntegral(delta) {
			return value + int8(delta), nil
		}
		return float64(value) + delta, nil
	case int16:
		if isIntegral(delta) {
			return value + int16(delta), nil
		}
		return float64(value) + delta, nil
	case int32:
		if isIntegral(delta) {
			return value + int32(delta), nil
		}
		return float64(value) + delta, nil
	case int64:
		if isIntegral(delta) {
			return value + int64(delta), nil
		}
		return float64(value) + delta, nil
	case uint:
		if isIntegral(delta) && delta >= 0 {
			return value + uint(delta), nil
		}
		return float64(value) + delta, nil
	case uint8:
		if isIntegral(delta) && delta >= 0 {
			return value + uint8(delta), nil
		}
		return float64(value) + delta, nil
	case uint16:
		if isIntegral(delta) && delta >= 0 {
			return value + uint16(delta), nil
		}
		return float64(value) + delta, nil
	case uint32:
		if isIntegral(delta) && delta >= 0 {
			return value + uint32(delta), nil
		}
		return float64(value) + delta, nil
	case uint64:
		if isIntegral(delta) && delta >= 0 {
			return value + uint64(delta), nil
		}
		return float64(value) + delta, nil
	case float32:
		return value + float32(delta), nil
	case float64:
		return value + delta, nil
	case string:
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not numeric", storage.ErrInvalidIncrement, value)
		}
		return parsed + delta, nil
	default:
		return nil, fmt.Errorf("%w: %T is not numeric", storage.ErrInvalidIncrement, current)
	}
}

func isIntegral(number float64) bool {
	return number == float64(int64(number))
}
