package postgres

import (
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

type rowScanner interface {
	Scan(dest ...any) error
}

type scannedRecord struct {
	decoded storage.Record
	raw     map[string]any
}

func projection(fields []resolvedField) string {
	columns := make([]string, 0, len(fields)*2)
	for _, field := range fields {
		columns = append(columns, quoteIdentifier(field.physical))
		if field.canonical != "id" {
			columns = append(columns, quoteIdentifier(presenceColumn(field)))
		}
	}
	return strings.Join(columns, ", ")
}

func qualifiedProjection(alias string, fields []resolvedField) string {
	columns := make([]string, 0, len(fields)*2)
	prefix := quoteIdentifier(alias) + "."
	for _, field := range fields {
		columns = append(columns, prefix+quoteIdentifier(field.physical))
		if field.canonical != "id" {
			columns = append(columns, prefix+quoteIdentifier(presenceColumn(field)))
		}
	}
	return strings.Join(columns, ", ")
}

func scanRecord(configuration *config, scanner rowScanner, fields []resolvedField) (scannedRecord, error) {
	values := make([]any, 0, len(fields)*2)
	valuePointers := make([]any, 0, len(fields)*2)
	for _, field := range fields {
		values = append(values, nil)
		valuePointers = append(valuePointers, &values[len(values)-1])
		if field.canonical != "id" {
			values = append(values, nil)
			valuePointers = append(valuePointers, &values[len(values)-1])
		}
	}
	if err := scanner.Scan(valuePointers...); err != nil {
		return scannedRecord{}, err
	}

	decoded := make(storage.Record, len(fields))
	raw := make(map[string]any, len(fields))
	position := 0
	for _, field := range fields {
		value := values[position]
		position++
		present := true
		if field.canonical != "id" {
			present = presenceValue(values[position]) || value != nil
			position++
		}
		raw[field.physical] = value
		if !present {
			continue
		}
		canonical, err := decodeValue(configuration, field, value)
		if err != nil {
			return scannedRecord{}, fmt.Errorf("postgres: decode %s: %w", field.canonical, err)
		}
		decoded[field.canonical] = canonical
	}
	return scannedRecord{decoded: decoded, raw: raw}, nil
}

func presenceValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case []byte:
		return string(typed) == "t" || string(typed) == "true" || string(typed) == "1"
	case string:
		return typed == "t" || typed == "true" || typed == "1"
	default:
		return false
	}
}
