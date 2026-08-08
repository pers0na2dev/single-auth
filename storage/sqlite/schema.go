package sqlite

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

// SchemaPlan is deterministic SQLite DDL for a storage schema.
type SchemaPlan struct {
	Statements []string
}

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

// PlanSchema validates schema and returns deterministic create-table/index
// statements. Every statement is idempotent for a fresh or already-created
// schema with the same columns.
func PlanSchema(schema storage.Schema) (SchemaPlan, error) {
	if len(schema.Models) == 0 {
		schema = storage.CoreSchema()
	}
	schema = schema.Clone()
	if err := schema.Validate(); err != nil {
		return SchemaPlan{}, fmt.Errorf("sqlite: schema plan: %w", err)
	}
	if err := validateReservedNames(schema); err != nil {
		return SchemaPlan{}, err
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

	statements := make([]string, 0, len(models)*2)
	for _, ordered := range models {
		model, err := resolveModel(configuration, ordered.canonical)
		if err != nil {
			return SchemaPlan{}, err
		}
		columns := []string{quoteIdentifier("id") + " TEXT NOT NULL PRIMARY KEY"}
		for _, field := range modelFields(model)[1:] {
			definition, err := columnDefinition(configuration, model, field)
			if err != nil {
				return SchemaPlan{}, err
			}
			columns = append(columns, definition)
			columns = append(columns, fmt.Sprintf(
				"%s INTEGER NOT NULL DEFAULT 0 CHECK (%s IN (0, 1))",
				quoteIdentifier(presenceColumn(field)),
				quoteIdentifier(presenceColumn(field)),
			))
		}
		statements = append(statements, fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s (\n  %s\n)",
			quoteIdentifier(model.physical),
			strings.Join(columns, ",\n  "),
		))

		for _, field := range modelFields(model)[1:] {
			if !field.attribute.Index && !field.attribute.Unique {
				continue
			}
			kind := "INDEX"
			if field.attribute.Unique {
				kind = "UNIQUE INDEX"
			}
			indexName := "single_" + model.physical + "_" + field.physical
			statements = append(statements, fmt.Sprintf(
				"CREATE %s IF NOT EXISTS %s ON %s (%s)",
				kind,
				quoteIdentifier(indexName),
				quoteIdentifier(model.physical),
				quoteIdentifier(field.physical),
			))
		}
	}
	return SchemaPlan{Statements: statements}, nil
}

func columnDefinition(configuration *config, model resolvedModel, field resolvedField) (string, error) {
	typeName := "TEXT"
	switch field.attribute.Type {
	case storage.FieldString, storage.FieldDate, storage.FieldJSON, storage.FieldStringArray, storage.FieldNumberArray, storage.FieldEnum:
		typeName = "TEXT"
	case storage.FieldNumber:
		if field.attribute.BigInt {
			typeName = "INTEGER"
		} else {
			typeName = "NUMERIC"
		}
	case storage.FieldBoolean:
		typeName = "INTEGER"
	default:
		return "", fmt.Errorf("%w: unsupported SQLite field type %q", storage.ErrInvalidQuery, field.attribute.Type)
	}
	parts := []string{quoteIdentifier(field.physical), typeName}
	if field.attribute.IsRequired() {
		parts = append(parts, "NOT NULL")
	}
	if field.attribute.Type == storage.FieldDate && field.attribute.DefaultValue != nil {
		parts = append(parts, "DEFAULT CURRENT_TIMESTAMP")
	}
	if field.attribute.Type == storage.FieldBoolean {
		parts = append(parts, fmt.Sprintf("CHECK (%s IN (0, 1))", quoteIdentifier(field.physical)))
	}
	if field.attribute.Type == storage.FieldEnum {
		placeholders := make([]string, 0, len(field.attribute.Enum))
		for _, value := range field.attribute.Enum {
			placeholders = append(placeholders, quoteLiteral(value))
		}
		parts = append(parts, fmt.Sprintf("CHECK (%s IN (%s))", quoteIdentifier(field.physical), strings.Join(placeholders, ", ")))
	}
	if field.attribute.References != nil {
		target, err := resolveModel(configuration, field.attribute.References.Model)
		if err != nil {
			return "", err
		}
		targetField, err := resolveField(configuration, target, field.attribute.References.Field)
		if err != nil {
			return "", err
		}
		parts = append(parts, fmt.Sprintf(
			"REFERENCES %s (%s) ON DELETE %s",
			quoteIdentifier(target.physical),
			quoteIdentifier(targetField.physical),
			onDeleteSQL(field.attribute.References.OnDelete),
		))
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

func quoteLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

// EnsureSchema creates missing tables and reconciles additive fields using one
// transactional native SQLite plan.
func (a *Adapter) EnsureSchema(ctx context.Context) error {
	if err := a.acquireWrite(ctx); err != nil {
		return err
	}
	defer a.releaseWrite()
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

// CreateSchema implements storage.SchemaCreator and returns migration SQL
// without modifying the caller's database.
func (a *Adapter) CreateSchema(ctx context.Context, schema storage.Schema, path string) (storage.SchemaCreation, error) {
	if err := contextError(ctx); err != nil {
		return storage.SchemaCreation{}, err
	}
	plan, err := PlanSchema(schema)
	if err != nil {
		return storage.SchemaCreation{}, err
	}
	return storage.SchemaCreation{Code: plan.SQL(), Path: path, Append: true}, nil
}

var _ storage.Adapter = (*Adapter)(nil)
var _ storage.SchemaCreator = (*Adapter)(nil)
var _ storage.SchemaEnsurer = (*Adapter)(nil)
