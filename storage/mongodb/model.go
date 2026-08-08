package mongodb

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"

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

func resolveModel(configuration *config, name string) (resolvedModel, error) {
	table, canonical, err := configuration.schema.ResolveModel(name)
	if err != nil {
		return resolvedModel{}, err
	}
	physical := table.ModelName
	if configuration.schema.UsePlural {
		physical += "s"
	}
	return resolvedModel{canonical: canonical, physical: physical, schema: table}, nil
}

func resolveField(configuration *config, model resolvedModel, name string) (resolvedField, error) {
	attribute, canonical, err := configuration.schema.ResolveField(model.canonical, name)
	if err != nil {
		return resolvedField{}, err
	}
	physical := attribute.FieldName
	if canonical == "id" {
		physical = "_id"
	} else if physical == "" {
		physical = canonical
	}
	return resolvedField{canonical: canonical, physical: physical, attribute: attribute}, nil
}

func resolvePhysicalField(model resolvedModel, physical string) (resolvedField, error) {
	if physical == "_id" || physical == "id" {
		return resolvedField{
			canonical: "id",
			physical:  "_id",
			attribute: storage.FieldAttribute{Type: storage.FieldString, FieldName: "id"},
		}, nil
	}
	for canonical, attribute := range model.schema.Fields {
		candidate := attribute.FieldName
		if candidate == "" {
			candidate = canonical
		}
		if candidate == physical {
			return resolvedField{canonical: canonical, physical: candidate, attribute: attribute}, nil
		}
	}
	return resolvedField{}, fmt.Errorf("%w: %s.%s", storage.ErrFieldNotFound, model.canonical, physical)
}

func modelFields(model resolvedModel) []resolvedField {
	names := make([]string, 0, len(model.schema.Fields))
	for canonical := range model.schema.Fields {
		if canonical != "id" {
			names = append(names, canonical)
		}
	}
	sort.Strings(names)
	fields := make([]resolvedField, 0, len(names)+1)
	fields = append(fields, resolvedField{
		canonical: "id",
		physical:  "_id",
		attribute: storage.FieldAttribute{Type: storage.FieldString, FieldName: "id"},
	})
	for _, canonical := range names {
		attribute := model.schema.Fields[canonical]
		physical := attribute.FieldName
		if physical == "" {
			physical = canonical
		}
		fields = append(fields, resolvedField{canonical: canonical, physical: physical, attribute: attribute})
	}
	return fields
}

func selectedFields(configuration *config, model resolvedModel, selected []string) ([]resolvedField, error) {
	if len(selected) == 0 {
		return nil, nil
	}
	fields := make([]resolvedField, 0, len(selected))
	seen := make(map[string]struct{}, len(selected))
	for _, name := range selected {
		field, err := resolveField(configuration, model, name)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[field.canonical]; exists {
			continue
		}
		seen[field.canonical] = struct{}{}
		fields = append(fields, field)
	}
	return fields, nil
}

func projection(fields []resolvedField) bson.D {
	if len(fields) == 0 {
		return nil
	}
	result := make(bson.D, 0, len(fields)+1)
	hasID := false
	for _, field := range fields {
		result = append(result, bson.E{Key: field.physical, Value: 1})
		hasID = hasID || field.physical == "_id"
	}
	if !hasID {
		result = append(result, bson.E{Key: "_id", Value: 0})
	}
	return result
}

func validateMongoNames(schema storage.Schema) error {
	for canonical, table := range schema.Models {
		physical := table.ModelName
		if physical == "" {
			physical = canonical
		}
		if schema.UsePlural {
			physical += "s"
		}
		if err := validateCollectionName(physical); err != nil {
			return err
		}
		if _, exists := table.Fields["id"]; exists {
			return fmt.Errorf("%w: model %q explicitly declares reserved id field", storage.ErrInvalidQuery, canonical)
		}
		for fieldName, attribute := range table.Fields {
			physicalField := attribute.FieldName
			if physicalField == "" {
				physicalField = fieldName
			}
			if physicalField == "_id" || physicalField == "id" {
				return fmt.Errorf("%w: model %q field %q uses reserved MongoDB field %q", storage.ErrInvalidQuery, canonical, fieldName, physicalField)
			}
			if strings.IndexByte(physicalField, 0) >= 0 || strings.Contains(physicalField, ".") || strings.HasPrefix(physicalField, "$") {
				return fmt.Errorf("%w: invalid MongoDB field name %q", storage.ErrInvalidQuery, physicalField)
			}
		}
	}
	return nil
}

func validateCollectionName(name string) error {
	if name == "" || strings.IndexByte(name, 0) >= 0 || strings.Contains(name, "$") || strings.HasPrefix(name, "system.") {
		return fmt.Errorf("%w: invalid MongoDB collection name %q", storage.ErrInvalidQuery, name)
	}
	if utf8.RuneCountInString(name) > 120 || len(name) > 120 {
		return fmt.Errorf("%w: MongoDB collection name %q exceeds 120 bytes", storage.ErrInvalidQuery, name)
	}
	return nil
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
