package mssql

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

// SchemaPlan is deterministic SQL Server DDL for a storage schema.
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

// PlanSchema validates schema and emits idempotent table blocks first, index
// blocks second, and foreign-key blocks last. Deferring foreign keys permits
// cyclic plugin schemas while ensuring every referenced table already exists.
func PlanSchema(schema storage.Schema) (SchemaPlan, error) {
	return PlanSchemaWithIDType(schema, TextID)
}

// PlanSchemaWithIDType plans a schema for text, UUID, or identity IDs.
func PlanSchemaWithIDType(schema storage.Schema, idType IDType) (SchemaPlan, error) {
	if len(schema.Models) == 0 {
		schema = storage.CoreSchema()
	}
	schema = schema.Clone()
	if err := schema.Validate(); err != nil {
		return SchemaPlan{}, fmt.Errorf("mssql: schema plan: %w", err)
	}
	if err := validateReservedNames(schema); err != nil {
		return SchemaPlan{}, err
	}
	if idType == "" {
		idType = TextID
	}
	if idType != TextID && idType != UUIDID && idType != SerialID {
		return SchemaPlan{}, fmt.Errorf("mssql: unsupported ID type %q", idType)
	}
	configuration := &config{schema: schema}
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
				"%s SMALLINT NOT NULL DEFAULT 0",
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
			"IF OBJECT_ID(%s, N'U') IS NULL\nBEGIN\n  CREATE TABLE %s (\n    %s\n  )\nEND",
			quoteLiteral(quoteIdentifier(model.physical)), quoteIdentifier(model.physical), strings.Join(columns, ",\n    "),
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
			name := mssqlObjectName("idx", model.physical, field.physical)
			statements = append(statements, fmt.Sprintf(
				"IF NOT EXISTS (\n  SELECT 1 FROM sys.indexes\n  WHERE [name] = %s AND [object_id] = OBJECT_ID(%s)\n)\nBEGIN\n  CREATE %s %s ON %s (%s)\nEND",
				quoteLiteral(name), quoteLiteral(quoteIdentifier(model.physical)), kind, quoteIdentifier(name), quoteIdentifier(model.physical), quoteIdentifier(field.physical),
			))
		}
	}

	for _, foreign := range foreignKeys {
		constraint := mssqlObjectName("fk", foreign.model.physical, foreign.field.physical)
		statement := fmt.Sprintf(
			"IF NOT EXISTS (\n  SELECT 1 FROM sys.foreign_keys\n  WHERE [name] = %s AND [parent_object_id] = OBJECT_ID(%s)\n)\nBEGIN\n  ALTER TABLE %s WITH CHECK ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s\nEND",
			quoteLiteral(constraint), quoteLiteral(quoteIdentifier(foreign.model.physical)),
			quoteIdentifier(foreign.model.physical), quoteIdentifier(constraint), quoteIdentifier(foreign.field.physical),
			quoteIdentifier(foreign.ref.physical), quoteIdentifier(foreign.to.physical), onDeleteSQL(foreign.field.attribute.References.OnDelete),
		)
		statements = append(statements, statement)
	}
	return SchemaPlan{Statements: statements}, nil
}

func idColumnType(idType IDType) string {
	switch idType {
	case SerialID:
		return "INTEGER IDENTITY(1,1)"
	default:
		return "VARCHAR(36)"
	}
}

func columnDefinition(field resolvedField, idType IDType) (string, error) {
	typeName := "TEXT"
	if field.attribute.References != nil && field.attribute.References.Field == "id" {
		switch idType {
		case SerialID:
			typeName = "INTEGER"
		default:
			typeName = "VARCHAR(36)"
		}
	} else if field.attribute.References != nil {
		typeName = "VARCHAR(36)"
	} else {
		switch field.attribute.Type {
		case storage.FieldString, storage.FieldEnum:
			if field.attribute.Unique || field.attribute.Sortable || field.attribute.Index || field.attribute.Type == storage.FieldEnum {
				typeName = "VARCHAR(255)"
			} else {
				typeName = "VARCHAR(8000)"
			}
		case storage.FieldDate:
			typeName = "DATETIME2(3)"
		case storage.FieldJSON, storage.FieldStringArray, storage.FieldNumberArray:
			typeName = "VARCHAR(8000)"
		case storage.FieldNumber:
			if field.attribute.BigInt {
				typeName = "BIGINT"
			} else {
				typeName = "INTEGER"
			}
		case storage.FieldBoolean:
			typeName = "SMALLINT"
		default:
			return "", fmt.Errorf("%w: unsupported SQL Server field type %q", storage.ErrInvalidQuery, field.attribute.Type)
		}
	}
	parts := []string{quoteIdentifier(field.physical), typeName}
	if field.attribute.IsRequired() {
		parts = append(parts, "NOT NULL")
	}
	if field.attribute.Type == storage.FieldDate && field.attribute.DefaultValue != nil {
		parts = append(parts, "DEFAULT CURRENT_TIMESTAMP")
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
	case storage.NoAction:
		return "NO ACTION"
	case storage.Cascade:
		return "CASCADE"
	case storage.Restrict:
		// SQL Server has no RESTRICT keyword; NO ACTION has the same immediate
		// rejection behavior for SQL Server's non-deferrable constraints.
		return "NO ACTION"
	case storage.SetNull:
		return "SET NULL"
	case storage.SetDefault:
		return "SET DEFAULT"
	default:
		// reference implementation's migration builder defaults an omitted reference action
		// (the empty Go value) to CASCADE.
		return "CASCADE"
	}
}

func quoteLiteral(value string) string { return "N'" + strings.ReplaceAll(value, "'", "''") + "'" }

func mssqlObjectName(kind, table, field string) string {
	raw := "single_" + table + "_" + field + "_" + kind
	if utf16Length(raw) <= 128 {
		return raw
	}
	digest := sha256.Sum256([]byte(raw))
	suffix := "_" + hex.EncodeToString(digest[:6])
	limit := 128 - utf16Length(suffix)
	prefix := raw
	for utf16Length(prefix) > limit {
		runes := []rune(prefix)
		prefix = string(runes[:len(runes)-1])
	}
	return prefix + suffix
}

// EnsureSchema creates missing tables and reconciles additive fields using one
// transactional native SQL Server plan.
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
	plan, err := PlanSchemaWithIDType(schema, a.config.idType)
	if err != nil {
		return storage.SchemaCreation{}, err
	}
	return storage.SchemaCreation{Code: plan.SQL(), Path: path, Append: true}, nil
}

var _ storage.SchemaCreator = (*Adapter)(nil)
var _ storage.SchemaEnsurer = (*Adapter)(nil)
