package postgres

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

const presencePrefix = "__single_present__"

type resolvedModel struct {
	canonical      string
	databaseSchema string
	physical       string
	schema         storage.ModelSchema
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
	databaseSchema, physical, err := splitPostgresModelName(configuration.databaseSchema, table.ModelName)
	if err != nil {
		return resolvedModel{}, err
	}
	if configuration.schema.UsePlural {
		physical += "s"
	}
	return resolvedModel{
		canonical: canonical, databaseSchema: databaseSchema,
		physical: physical, schema: table,
	}, nil
}

func resolveField(configuration *config, model resolvedModel, name string) (resolvedField, error) {
	attribute, canonical, err := configuration.schema.ResolveField(model.canonical, name)
	if err != nil {
		return resolvedField{}, err
	}
	physical := attribute.FieldName
	if physical == "" {
		physical = canonical
	}
	return resolvedField{canonical: canonical, physical: physical, attribute: attribute}, nil
}

func resolvePhysicalField(model resolvedModel, physical string) (resolvedField, error) {
	if physical == "id" {
		return resolvedField{
			canonical: "id",
			physical:  "id",
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
		physical:  "id",
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
		return modelFields(model), nil
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

func presenceColumn(field resolvedField) string { return presencePrefix + field.canonical }

func validateReservedNames(schema storage.Schema) error {
	for canonical, table := range schema.Models {
		physicalModel := table.ModelName
		if physicalModel == "" {
			physicalModel = canonical
		}
		databaseSchema, physicalModel, err := splitPostgresModelName(defaultDatabaseSchema, physicalModel)
		if err != nil {
			return err
		}
		if schema.UsePlural {
			physicalModel += "s"
		}
		if err := validatePostgresIdentifier("schema", databaseSchema); err != nil {
			return err
		}
		if err := validatePostgresIdentifier("model", physicalModel); err != nil {
			return err
		}
		if _, exists := table.Fields["id"]; exists {
			return fmt.Errorf("%w: model %q explicitly declares reserved id field", storage.ErrInvalidQuery, canonical)
		}
		for fieldName, attribute := range table.Fields {
			physical := attribute.FieldName
			if physical == "" {
				physical = fieldName
			}
			if strings.HasPrefix(physical, presencePrefix) {
				return fmt.Errorf(
					"%w: model %q field %q uses reserved prefix %q",
					storage.ErrInvalidQuery, canonical, fieldName, presencePrefix,
				)
			}
			if err := validatePostgresIdentifier("field", physical); err != nil {
				return err
			}
			if err := validatePostgresIdentifier("presence field", presencePrefix+fieldName); err != nil {
				return err
			}
		}
	}
	return nil
}

func validatePostgresIdentifier(kind, value string) error {
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("%w: PostgreSQL %s name contains NUL", storage.ErrInvalidQuery, kind)
	}
	// Standard PostgreSQL NAMEDATALEN is 64, leaving 63 bytes for an
	// identifier. Reject truncation instead of silently addressing a different
	// table or column.
	if len(value) > 63 {
		return fmt.Errorf("%w: PostgreSQL %s name %q exceeds 63 bytes", storage.ErrInvalidQuery, kind, value)
	}
	return nil
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func splitPostgresModelName(defaultSchema, name string) (string, string, error) {
	parts := strings.Split(name, ".")
	switch len(parts) {
	case 1:
		return defaultSchema, parts[0], nil
	case 2:
		if parts[0] == "" || parts[1] == "" {
			break
		}
		return parts[0], parts[1], nil
	}
	return "", "", fmt.Errorf(
		"%w: PostgreSQL model name %q must be table or schema.table",
		storage.ErrInvalidQuery, name,
	)
}

func qualifiedIdentifier(schema, name string) string {
	return quoteIdentifier(schema) + "." + quoteIdentifier(name)
}

func qualifiedTable(_ *config, model resolvedModel) string {
	return qualifiedIdentifier(model.databaseSchema, model.physical)
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
