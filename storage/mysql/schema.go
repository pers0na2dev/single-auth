package mysql

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pers0na2dev/single-auth/storage"
)

// SchemaPlan is deterministic MySQL DDL for a storage schema.
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

// PlanSchema validates schema and emits idempotent CREATE TABLE statements.
// Indexes and foreign keys are inline so CREATE TABLE IF NOT EXISTS is itself
// the idempotency boundary. Session-scoped FOREIGN_KEY_CHECKS permits cyclic
// plugin schemas and out-of-order references.
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
		return SchemaPlan{}, fmt.Errorf("mysql: schema plan: %w", err)
	}
	if err := validateReservedNames(schema); err != nil {
		return SchemaPlan{}, err
	}
	if idType == "" {
		idType = TextID
	}
	if idType != TextID && idType != UUIDID && idType != SerialID {
		return SchemaPlan{}, fmt.Errorf("mysql: unsupported ID type %q", idType)
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

	statements := make([]string, 0, len(models)+2)
	statements = append(statements, "SET FOREIGN_KEY_CHECKS = 0")
	for _, ordered := range models {
		model, err := resolveModel(configuration, ordered.canonical)
		if err != nil {
			return SchemaPlan{}, err
		}
		definitions := []string{quoteIdentifier("id") + " " + idColumnType(idType) + " NOT NULL PRIMARY KEY"}
		for _, field := range modelFields(model)[1:] {
			definition, err := columnDefinition(field, idType)
			if err != nil {
				return SchemaPlan{}, err
			}
			definitions = append(definitions, definition)
			definitions = append(definitions, fmt.Sprintf(
				"%s BOOLEAN NOT NULL DEFAULT FALSE",
				quoteIdentifier(presenceColumn(field)),
			))
		}
		for _, field := range modelFields(model)[1:] {
			if field.attribute.Index || field.attribute.Unique {
				kind := "KEY"
				if field.attribute.Unique {
					kind = "UNIQUE KEY"
				}
				name := mysqlObjectName("idx", model.physical, field.physical)
				definitions = append(definitions, fmt.Sprintf(
					"%s %s (%s)", kind, quoteIdentifier(name), quoteIdentifier(field.physical),
				))
			}
			if field.attribute.References != nil {
				target, err := resolveModel(configuration, field.attribute.References.Model)
				if err != nil {
					return SchemaPlan{}, err
				}
				to, err := resolveField(configuration, target, field.attribute.References.Field)
				if err != nil {
					return SchemaPlan{}, err
				}
				action, err := mysqlOnDeleteSQL(field.attribute)
				if err != nil {
					return SchemaPlan{}, err
				}
				constraint := mysqlObjectName("fk", model.physical, field.physical)
				definitions = append(definitions, fmt.Sprintf(
					"CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s",
					quoteIdentifier(constraint), quoteIdentifier(field.physical), quoteIdentifier(target.physical), quoteIdentifier(to.physical), action,
				))
			}
		}
		statements = append(statements, fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s (\n  %s\n) ENGINE=InnoDB",
			quoteIdentifier(model.physical), strings.Join(definitions, ",\n  "),
		))
	}
	statements = append(statements, "SET FOREIGN_KEY_CHECKS = 1")
	return SchemaPlan{Statements: statements}, nil
}

func idColumnType(idType IDType) string {
	switch idType {
	case SerialID:
		return "INTEGER AUTO_INCREMENT"
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
			if field.attribute.Unique || field.attribute.Index || field.attribute.Sortable || field.attribute.Type == storage.FieldEnum {
				typeName = "VARCHAR(255)"
			} else {
				typeName = "TEXT"
			}
		case storage.FieldDate:
			typeName = "TIMESTAMP(3)"
		case storage.FieldJSON, storage.FieldStringArray, storage.FieldNumberArray:
			typeName = "JSON"
		case storage.FieldNumber:
			if field.attribute.BigInt {
				typeName = "BIGINT"
			} else {
				typeName = "INTEGER"
			}
		case storage.FieldBoolean:
			typeName = "BOOLEAN"
		default:
			return "", fmt.Errorf("%w: unsupported MySQL field type %q", storage.ErrInvalidQuery, field.attribute.Type)
		}
	}
	parts := []string{quoteIdentifier(field.physical), typeName}
	if field.attribute.IsRequired() {
		parts = append(parts, "NOT NULL")
	}
	if field.attribute.Type == storage.FieldDate && field.attribute.DefaultValue != nil {
		parts = append(parts, "DEFAULT CURRENT_TIMESTAMP(3)")
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

func mysqlOnDeleteSQL(field storage.FieldAttribute) (string, error) {
	action := field.References.OnDelete
	switch action {
	case storage.Cascade:
		return "CASCADE", nil
	case storage.Restrict:
		return "RESTRICT", nil
	case storage.SetNull:
		if field.IsRequired() {
			return "", fmt.Errorf("%w: MySQL SET NULL reference must be optional", storage.ErrInvalidQuery)
		}
		return "SET NULL", nil
	case storage.SetDefault:
		return "", fmt.Errorf("%w: MySQL does not support ON DELETE SET DEFAULT", storage.ErrInvalidQuery)
	default:
		return "NO ACTION", nil
	}
}

func quoteLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func mysqlObjectName(kind, table, field string) string {
	raw := "single_" + table + "_" + field + "_" + kind
	if len(raw) <= 64 {
		return raw
	}
	digest := sha256.Sum256([]byte(raw))
	suffix := "_" + hex.EncodeToString(digest[:6])
	limit := 64 - len(suffix)
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

// EnsureSchema creates missing tables and reconciles additive fields on one
// pinned connection. MySQL DDL implicitly commits, so failure may leave an
// additive prefix applied; a retry always re-inspects the database first.
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
	connection, err := a.db.Conn(ctx)
	if err != nil {
		return normalizeError(ctx, "acquire schema connection", err)
	}
	defer connection.Close()
	checksDisabled := false
	for _, statement := range plan.Statements {
		if _, err := connection.ExecContext(ctx, statement); err != nil {
			if checksDisabled {
				restoreForeignKeyChecks(connection)
			}
			return normalizeError(ctx, "create schema", err)
		}
		switch strings.TrimSpace(statement) {
		case "SET FOREIGN_KEY_CHECKS = 0":
			checksDisabled = true
		case "SET FOREIGN_KEY_CHECKS = 1":
			checksDisabled = false
		}
	}
	return nil
}

func restoreForeignKeyChecks(connection *sql.Conn) {
	restoreContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, err := connection.ExecContext(restoreContext, "SET FOREIGN_KEY_CHECKS = 1")
	cancel()
	if err != nil {
		// A session with checks still disabled must never be returned to the
		// pool. database/sql discards the underlying connection when Raw reports
		// driver.ErrBadConn.
		_ = connection.Raw(func(any) error { return driver.ErrBadConn })
	}
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
