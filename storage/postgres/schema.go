package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/pers0na2dev/single-auth/storage"
)

// SchemaPlan is deterministic PostgreSQL DDL for a storage schema.
type SchemaPlan struct{ Statements []string }

// SQL renders the plan as executable semicolon-terminated statements.
func (plan SchemaPlan) SQL() string {
	if len(plan.Statements) == 0 {
		return ""
	}
	return strings.Join(plan.Statements, ";\n") + ";\n"
}

type orderedModel struct {
	canonical string
	order     int
}

type foreignKeyPlan struct {
	model resolvedModel
	field resolvedField
	ref   resolvedModel
	to    resolvedField
}

// PlanSchema validates schema and emits tables first, indexes second, and
// idempotent foreign-key blocks last. Deferring foreign keys permits cyclic
// plugin schemas while ensuring referenced unique indexes already exist.
func PlanSchema(schema storage.Schema) (SchemaPlan, error) {
	return PlanSchemaWithDatabaseSchema(schema, TextID, defaultDatabaseSchema)
}

// PlanSchemaWithIDType plans a schema for text, UUID, or identity IDs.
func PlanSchemaWithIDType(schema storage.Schema, idType IDType) (SchemaPlan, error) {
	return PlanSchemaWithDatabaseSchema(schema, idType, defaultDatabaseSchema)
}

// PlanSchemaWithDatabaseSchema plans unqualified models inside one PostgreSQL
// namespace. The namespace must already exist. A schema.table ModelName
// overrides it for that model; every table reference quotes both parts.
func PlanSchemaWithDatabaseSchema(schema storage.Schema, idType IDType, databaseSchema string) (SchemaPlan, error) {
	if len(schema.Models) == 0 {
		schema = storage.CoreSchema()
	}
	schema = schema.Clone()
	if err := schema.Validate(); err != nil {
		return SchemaPlan{}, fmt.Errorf("postgres: schema plan: %w", err)
	}
	if err := validateReservedNames(schema); err != nil {
		return SchemaPlan{}, err
	}
	if idType == "" {
		idType = TextID
	}
	if idType != TextID && idType != UUIDID && idType != SerialID {
		return SchemaPlan{}, fmt.Errorf("postgres: unsupported ID type %q", idType)
	}
	if databaseSchema == "" {
		databaseSchema = defaultDatabaseSchema
	}
	if err := validatePostgresIdentifier("schema", databaseSchema); err != nil {
		return SchemaPlan{}, err
	}
	configuration := &config{schema: schema, databaseSchema: databaseSchema}
	models := make([]orderedModel, 0, len(schema.Models))
	for canonical, model := range schema.Models {
		if model.DisableMigrations {
			continue
		}
		models = append(models, orderedModel{canonical: canonical, order: model.Order})
	}
	sort.Slice(models, func(left, right int) bool {
		if models[left].order != models[right].order {
			return models[left].order < models[right].order
		}
		return models[left].canonical < models[right].canonical
	})

	statements := make([]string, 0, len(models)*3)
	resolved := make([]resolvedModel, 0, len(models))
	foreignKeys := make([]foreignKeyPlan, 0)
	for _, ordered := range models {
		model, err := resolveModel(configuration, ordered.canonical)
		if err != nil {
			return SchemaPlan{}, err
		}
		resolved = append(resolved, model)
		columns := []string{quoteIdentifier("id") + " " + idColumnType(idType) + " NOT NULL PRIMARY KEY"}
		for _, field := range modelFields(model)[1:] {
			definition, err := columnDefinition(field, idType)
			if err != nil {
				return SchemaPlan{}, err
			}
			columns = append(columns, definition)
			columns = append(columns, fmt.Sprintf(
				"%s BOOLEAN NOT NULL DEFAULT FALSE",
				quoteIdentifier(presenceColumn(field)),
			))
			if field.attribute.References != nil {
				target, err := resolveModel(configuration, field.attribute.References.Model)
				if err != nil {
					return SchemaPlan{}, err
				}
				to, err := resolveField(configuration, target, field.attribute.References.Field)
				if err != nil {
					return SchemaPlan{}, err
				}
				foreignKeys = append(foreignKeys, foreignKeyPlan{model: model, field: field, ref: target, to: to})
			}
		}
		statements = append(statements, fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s (\n  %s\n)",
			qualifiedTable(configuration, model), strings.Join(columns, ",\n  "),
		))
	}

	for _, model := range resolved {
		for _, field := range modelFields(model)[1:] {
			if !field.attribute.Index && !field.attribute.Unique {
				continue
			}
			kind := "INDEX"
			if field.attribute.Unique {
				kind = "UNIQUE INDEX"
			}
			name := postgresObjectName("idx", model.physical, field.physical)
			statements = append(statements, fmt.Sprintf(
				"CREATE %s IF NOT EXISTS %s ON %s (%s)",
				kind, quoteIdentifier(name), qualifiedTable(configuration, model), quoteIdentifier(field.physical),
			))
		}
	}

	for _, foreign := range foreignKeys {
		constraint := postgresObjectName("fk", foreign.model.physical, foreign.field.physical)
		statement := fmt.Sprintf(
			"DO $single$\nBEGIN\n  IF NOT EXISTS (\n    SELECT 1 FROM pg_constraint\n    WHERE conname = %s AND conrelid = to_regclass(%s)\n  ) THEN\n    ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s;\n  END IF;\nEXCEPTION\n  WHEN duplicate_object THEN NULL;\nEND\n$single$",
			quoteLiteral(constraint), quoteLiteral(qualifiedTable(configuration, foreign.model)),
			qualifiedTable(configuration, foreign.model), quoteIdentifier(constraint), quoteIdentifier(foreign.field.physical),
			qualifiedTable(configuration, foreign.ref), quoteIdentifier(foreign.to.physical), onDeleteSQL(foreign.field.attribute.References.OnDelete),
		)
		statements = append(statements, statement)
	}
	return SchemaPlan{Statements: statements}, nil
}

func idColumnType(idType IDType) string {
	switch idType {
	case UUIDID:
		return "UUID DEFAULT pg_catalog.gen_random_uuid()"
	case SerialID:
		return "INTEGER GENERATED BY DEFAULT AS IDENTITY"
	default:
		return "TEXT"
	}
}

func columnDefinition(field resolvedField, idType IDType) (string, error) {
	typeName := "TEXT"
	if field.attribute.References != nil && field.attribute.References.Field == "id" {
		switch idType {
		case UUIDID:
			typeName = "UUID"
		case SerialID:
			typeName = "INTEGER"
		default:
			typeName = "TEXT"
		}
	} else {
		switch field.attribute.Type {
		case storage.FieldString, storage.FieldEnum:
			typeName = "TEXT"
		case storage.FieldDate:
			typeName = "TIMESTAMPTZ"
		case storage.FieldJSON, storage.FieldStringArray, storage.FieldNumberArray:
			typeName = "JSONB"
		case storage.FieldNumber:
			if field.attribute.BigInt {
				typeName = "BIGINT"
			} else {
				typeName = "INTEGER"
			}
		case storage.FieldBoolean:
			typeName = "BOOLEAN"
		default:
			return "", fmt.Errorf("%w: unsupported PostgreSQL field type %q", storage.ErrInvalidQuery, field.attribute.Type)
		}
	}
	parts := []string{quoteIdentifier(field.physical), typeName}
	if field.attribute.Type == storage.FieldDate && field.attribute.DefaultValue != nil {
		parts = append(parts, "DEFAULT CURRENT_TIMESTAMP")
	}
	if field.attribute.IsRequired() {
		parts = append(parts, "NOT NULL")
	}
	if field.attribute.Type == storage.FieldEnum {
		values := make([]string, 0, len(field.attribute.Enum))
		for _, value := range field.attribute.Enum {
			values = append(values, quoteLiteral(value))
		}
		parts = append(parts, fmt.Sprintf("CHECK (%s IN (%s))", quoteIdentifier(field.physical), strings.Join(values, ", ")))
	}
	return strings.Join(parts, " "), nil
}

func onDeleteSQL(action storage.DeleteAction) string {
	switch action {
	case storage.Cascade:
		return "CASCADE"
	case storage.Restrict:
		return "RESTRICT"
	case storage.SetNull:
		return "SET NULL"
	case storage.SetDefault:
		return "SET DEFAULT"
	default:
		return "NO ACTION"
	}
}

func quoteLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func postgresObjectName(kind, table, field string) string {
	raw := "single_" + table + "_" + field + "_" + kind
	if len(raw) <= 63 {
		return raw
	}
	digest := sha256.Sum256([]byte(raw))
	suffix := "_" + hex.EncodeToString(digest[:6])
	limit := 63 - len(suffix)
	prefix := raw
	for len(prefix) > limit {
		_, size := utf8.DecodeLastRuneInString(prefix)
		if size == 0 {
			break
		}
		prefix = prefix[:len(prefix)-size]
	}
	return prefix + suffix
}

// EnsureSchema creates missing tables and reconciles additive fields using one
// transactional native PostgreSQL plan.
func (a *Adapter) EnsureSchema(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	plan, err := a.reconciliationPlan(ctx)
	if err != nil {
		return err
	}
	if len(plan.Statements) == 0 {
		return nil
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return normalizeError(ctx, "begin schema creation", err)
	}
	completed := false
	defer func() {
		if !completed {
			_ = tx.Rollback()
		}
	}()
	for _, statement := range plan.Statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return normalizeError(ctx, "create schema", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return normalizeError(ctx, "commit schema creation", err)
	}
	completed = true
	return nil
}

// CreateSchema returns deterministic migration SQL without modifying db.
func (a *Adapter) CreateSchema(ctx context.Context, schema storage.Schema, path string) (storage.SchemaCreation, error) {
	if err := contextError(ctx); err != nil {
		return storage.SchemaCreation{}, err
	}
	plan, err := PlanSchemaWithDatabaseSchema(schema, a.config.idType, a.config.databaseSchema)
	if err != nil {
		return storage.SchemaCreation{}, err
	}
	return storage.SchemaCreation{Code: plan.SQL(), Path: path, Append: true}, nil
}

var _ storage.SchemaCreator = (*Adapter)(nil)
var _ storage.SchemaEnsurer = (*Adapter)(nil)
