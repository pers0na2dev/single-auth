// Package migration plans and executes reference implementation-compatible relational
// schema migrations against an introspected database catalog.
package migration

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/pers0na2dev/single-auth/storage"
)

type Dialect string

const (
	SQLite   Dialect = "sqlite"
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
	MSSQL    Dialect = "mssql"
)

type IDMode string

const (
	TextID   IDMode = "text"
	UUIDID   IDMode = "uuid"
	SerialID IDMode = "serial"
)

// RollbackPolicy describes what remains in the database when Plan.Run fails
// after at least one DDL statement has executed.
type RollbackPolicy string

const (
	// RollbackAtomic means SQLite, PostgreSQL, and SQL Server roll back every
	// statement in the plan when the transaction fails.
	RollbackAtomic RollbackPolicy = "atomic"
	// RollbackMayPartiallyApply means MySQL may retain statements that completed
	// before the failure because MySQL DDL performs implicit commits. Callers
	// must Inspect and BuildFromDatabase again before retrying.
	RollbackMayPartiallyApply RollbackPolicy = "may-partially-apply"
)

// RollbackPolicyForDialect returns the failure policy used by Plan.Run for a
// supported dialect. Plan.Run still opens a transaction for every backend,
// but MySQL cannot provide transactional DDL semantics.
func RollbackPolicyForDialect(dialect Dialect) (RollbackPolicy, error) {
	switch dialect {
	case SQLite, Postgres, MSSQL:
		return RollbackAtomic, nil
	case MySQL:
		return RollbackMayPartiallyApply, nil
	default:
		return "", fmt.Errorf("migration: unsupported dialect %q", dialect)
	}
}

type Column struct {
	Name     string
	DataType string
}

type Table struct {
	Database string
	Schema   string
	Name     string
	Columns  []Column
}

type Catalog struct {
	Database string
	Schema   string
	Tables   []Table
}

type Options struct {
	Dialect Dialect
	IDMode  IDMode
}

type TableChange struct {
	Table  string
	Fields map[string]storage.FieldAttribute
	Order  int
}

type Plan struct {
	ToBeCreated []TableChange
	ToBeAdded   []TableChange
	Statements  []string
}

func (plan Plan) SQL() string {
	if len(plan.Statements) == 0 {
		return ";"
	}
	return strings.Join(plan.Statements, ";\n\n") + ";"
}

// Run executes statements in order inside one database transaction. SQLite,
// PostgreSQL, and SQL Server provide atomic rollback for the supported DDL.
// MySQL can retain successfully executed statements after an error; callers
// must re-inspect and build a fresh plan before retrying rather than reusing the
// failed Plan. See RollbackPolicyForDialect.
func (plan Plan) Run(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return fmt.Errorf("migration: database is nil")
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration: begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for index, statement := range plan.Statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migration: execute statement %d %q: %w", index+1, statement, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration: commit: %w", err)
	}
	committed = true
	return nil
}

func Build(schema storage.Schema, catalog Catalog, options Options) (Plan, error) {
	if !supportedDialect(options.Dialect) {
		return Plan{}, fmt.Errorf("migration: unsupported dialect %q", options.Dialect)
	}
	if options.IDMode == "" {
		options.IDMode = TextID
	}
	if options.IDMode != TextID && options.IDMode != UUIDID && options.IDMode != SerialID {
		return Plan{}, fmt.Errorf("migration: unsupported ID mode %q", options.IDMode)
	}
	schema = schema.Clone()
	if err := schema.Validate(); err != nil {
		return Plan{}, fmt.Errorf("migration: schema: %w", err)
	}

	tables := make(map[string]Table, len(catalog.Tables))
	for _, table := range catalog.Tables {
		if !tableBelongsToCatalog(table, catalog, options.Dialect) {
			continue
		}
		tables[table.Name] = table
	}

	type orderedModel struct {
		canonical string
		physical  string
		model     storage.ModelSchema
	}
	models := make([]orderedModel, 0, len(schema.Models))
	for canonical, raw := range schema.Models {
		model, _, err := schema.ResolveModel(canonical)
		if err != nil {
			return Plan{}, err
		}
		if raw.DisableMigrations {
			continue
		}
		model.ModelName = physicalModelName(schema, model)
		models = append(models, orderedModel{canonical: canonical, physical: model.ModelName, model: model})
	}
	sort.Slice(models, func(left, right int) bool {
		if models[left].model.Order != models[right].model.Order {
			return models[left].model.Order < models[right].model.Order
		}
		return models[left].physical < models[right].physical
	})

	plan := Plan{}
	deferredIndexes := make([]string, 0)
	deferredForeignKeys := make([]string, 0)
	for _, entry := range models {
		table, exists := tables[entry.physical]
		if !exists {
			change := TableChange{Table: entry.physical, Fields: cloneFields(entry.model.Fields), Order: entry.model.Order}
			plan.ToBeCreated = append(plan.ToBeCreated, change)
			statement, indexes, foreignKeys, err := createTableSQL(schema, entry.canonical, entry.model, options)
			if err != nil {
				return Plan{}, err
			}
			plan.Statements = append(plan.Statements, statement)
			deferredIndexes = append(deferredIndexes, indexes...)
			deferredForeignKeys = append(deferredForeignKeys, foreignKeys...)
			continue
		}
		columns := make(map[string]string, len(table.Columns))
		for _, column := range table.Columns {
			columns[column.Name] = column.DataType
		}
		missing := make(map[string]storage.FieldAttribute)
		fieldNames := sortedFieldNames(entry.model.Fields)
		for _, canonicalField := range fieldNames {
			field := entry.model.Fields[canonicalField]
			physical := field.FieldName
			if physical == "" {
				physical = canonicalField
			}
			dataType, exists := columns[physical]
			if exists && MatchType(dataType, field.Type, options.Dialect) {
				continue
			}
			if !exists {
				missing[canonicalField] = field
			}
		}
		if len(missing) == 0 {
			continue
		}
		plan.ToBeAdded = append(plan.ToBeAdded, TableChange{Table: entry.physical, Fields: cloneFields(missing), Order: entry.model.Order})
		for _, canonicalField := range sortedFieldNames(missing) {
			field := missing[canonicalField]
			physical := field.FieldName
			if physical == "" {
				physical = canonicalField
			}
			definition, err := columnSQL(schema, entry.canonical, canonicalField, field, options)
			if err != nil {
				return Plan{}, err
			}
			plan.Statements = append(plan.Statements, addColumnSQL(entry.physical, definition, options.Dialect))
			if field.Index && !field.Unique {
				deferredIndexes = append(deferredIndexes, createIndexSQL(entry.physical, physical, field.Unique, options.Dialect))
			}
			if field.References != nil && usesDeferredForeignKeys(options.Dialect) {
				foreignKey, err := foreignKeySQL(schema, entry.canonical, canonicalField, field, options)
				if err != nil {
					return Plan{}, err
				}
				deferredForeignKeys = append(deferredForeignKeys, foreignKey)
			}
		}
	}
	plan.Statements = append(plan.Statements, deferredIndexes...)
	plan.Statements = append(plan.Statements, deferredForeignKeys...)
	return plan, nil
}

func MatchType(columnDataType string, fieldType storage.FieldType, dialect Dialect) bool {
	normalized := normalizeColumnType(columnDataType)
	var expected map[storage.FieldType][]string
	switch dialect {
	case SQLite:
		expected = map[storage.FieldType][]string{
			storage.FieldString:      {"text"},
			storage.FieldEnum:        {"text"},
			storage.FieldNumber:      {"integer", "real", "bigint", "numeric"},
			storage.FieldBoolean:     {"integer", "boolean"},
			storage.FieldDate:        {"date", "integer", "text"},
			storage.FieldJSON:        {"text", "json"},
			storage.FieldStringArray: {"text", "json"},
			storage.FieldNumberArray: {"text", "json"},
		}
	case Postgres:
		expected = map[storage.FieldType][]string{
			storage.FieldString:      {"character varying", "varchar", "text", "uuid"},
			storage.FieldEnum:        {"character varying", "varchar", "text"},
			storage.FieldNumber:      {"int4", "integer", "bigint", "smallint", "numeric", "real", "double precision"},
			storage.FieldBoolean:     {"bool", "boolean"},
			storage.FieldDate:        {"timestamp with time zone", "timestamp without time zone", "timestamptz", "timestamp", "date"},
			storage.FieldJSON:        {"json", "jsonb"},
			storage.FieldStringArray: {"json", "jsonb"},
			storage.FieldNumberArray: {"json", "jsonb"},
		}
	case MySQL:
		expected = map[storage.FieldType][]string{
			storage.FieldString:      {"char", "varchar", "tinytext", "text", "mediumtext", "longtext"},
			storage.FieldEnum:        {"char", "varchar", "enum", "tinytext", "text", "mediumtext", "longtext"},
			storage.FieldNumber:      {"tinyint", "smallint", "mediumint", "int", "integer", "bigint", "decimal", "numeric", "float", "double", "real"},
			storage.FieldBoolean:     {"bool", "boolean", "tinyint"},
			storage.FieldDate:        {"date", "datetime", "timestamp"},
			storage.FieldJSON:        {"json"},
			storage.FieldStringArray: {"json"},
			storage.FieldNumberArray: {"json"},
		}
	case MSSQL:
		expected = map[storage.FieldType][]string{
			storage.FieldString:      {"char", "nchar", "varchar", "nvarchar", "text", "ntext", "uniqueidentifier"},
			storage.FieldEnum:        {"char", "nchar", "varchar", "nvarchar", "text", "ntext"},
			storage.FieldNumber:      {"tinyint", "smallint", "int", "integer", "bigint", "decimal", "numeric", "float", "real", "money", "smallmoney"},
			storage.FieldBoolean:     {"bit", "smallint", "tinyint", "boolean"},
			storage.FieldDate:        {"date", "datetime", "datetime2", "datetimeoffset", "smalldatetime"},
			storage.FieldJSON:        {"char", "nchar", "varchar", "nvarchar", "text", "ntext", "json"},
			storage.FieldStringArray: {"char", "nchar", "varchar", "nvarchar", "text", "ntext", "json"},
			storage.FieldNumberArray: {"char", "nchar", "varchar", "nvarchar", "text", "ntext", "json"},
		}
	default:
		return false
	}
	for _, candidate := range expected[fieldType] {
		if normalized == candidate {
			return true
		}
	}
	return false
}

func createTableSQL(schema storage.Schema, canonical string, model storage.ModelSchema, options Options) (string, []string, []string, error) {
	columns := []string{quoteIdentifier("id", options.Dialect) + " " + idColumnType(options) + " NOT NULL PRIMARY KEY"}
	indexes := make([]string, 0)
	foreignKeys := make([]string, 0)
	for _, canonicalField := range sortedFieldNames(model.Fields) {
		field := model.Fields[canonicalField]
		definition, err := columnSQL(schema, canonical, canonicalField, field, options)
		if err != nil {
			return "", nil, nil, err
		}
		columns = append(columns, definition)
		if field.Index && !field.Unique {
			physical := field.FieldName
			if physical == "" {
				physical = canonicalField
			}
			indexes = append(indexes, createIndexSQL(model.ModelName, physical, false, options.Dialect))
		}
		if field.References != nil && usesDeferredForeignKeys(options.Dialect) {
			foreignKey, err := foreignKeySQL(schema, canonical, canonicalField, field, options)
			if err != nil {
				return "", nil, nil, err
			}
			foreignKeys = append(foreignKeys, foreignKey)
		}
	}
	return fmt.Sprintf("CREATE TABLE %s (\n  %s\n)", quoteIdentifier(model.ModelName, options.Dialect), strings.Join(columns, ",\n  ")), indexes, foreignKeys, nil
}

func columnSQL(schema storage.Schema, model, canonical string, field storage.FieldAttribute, options Options) (string, error) {
	physical := field.FieldName
	if physical == "" {
		physical = canonical
	}
	typeName, err := fieldTypeSQL(field, canonical, options)
	if err != nil {
		return "", err
	}
	parts := []string{quoteIdentifier(physical, options.Dialect), typeName}
	if field.IsRequired() {
		parts = append(parts, "NOT NULL")
	}
	if field.Unique {
		parts = append(parts, "UNIQUE")
	}
	if field.Type == storage.FieldDate && field.DefaultValue != nil {
		switch options.Dialect {
		case SQLite, Postgres, MSSQL:
			parts = append(parts, "DEFAULT CURRENT_TIMESTAMP")
		case MySQL:
			parts = append(parts, "DEFAULT CURRENT_TIMESTAMP(3)")
		}
	}
	if field.Type == storage.FieldEnum && (options.Dialect == MySQL || options.Dialect == MSSQL) {
		values := make([]string, 0, len(field.Enum))
		for _, value := range field.Enum {
			values = append(values, quoteLiteral(value, options.Dialect))
		}
		parts = append(parts, fmt.Sprintf(
			"CHECK (%s IN (%s))",
			quoteIdentifier(physical, options.Dialect),
			strings.Join(values, ", "),
		))
	}
	if field.References != nil {
		reference, err := resolveReferenceDefinition(schema, model, canonical, field, options.Dialect)
		if err != nil {
			return "", err
		}
		if !usesDeferredForeignKeys(options.Dialect) {
			parts = append(
				parts,
				"REFERENCES",
				quoteIdentifier(reference.targetTable, options.Dialect),
				"("+quoteIdentifier(reference.targetField, options.Dialect)+")",
				"ON DELETE",
				reference.action,
			)
		}
	}
	return strings.Join(parts, " "), nil
}

func fieldTypeSQL(field storage.FieldAttribute, canonical string, options Options) (string, error) {
	if canonical == "id" {
		return idColumnType(options), nil
	}
	if field.References != nil && field.References.Field == "id" {
		switch options.IDMode {
		case UUIDID:
			if options.Dialect == Postgres {
				return "UUID", nil
			}
		case SerialID:
			return "INTEGER", nil
		}
		if options.Dialect == MySQL || options.Dialect == MSSQL {
			return "VARCHAR(36)", nil
		}
		return "TEXT", nil
	}
	if field.References != nil && (options.Dialect == MySQL || options.Dialect == MSSQL) {
		// Non-ID references keep the declared field type. In particular, indexed
		// string references such as oauthApplication.clientId must remain
		// VARCHAR(255) even when primary keys use integer identities.
		field.References = nil
		return fieldTypeSQL(field, canonical, options)
	}
	switch field.Type {
	case storage.FieldString, storage.FieldEnum:
		if options.Dialect == MySQL {
			if field.Unique || field.Index || field.Sortable || field.Type == storage.FieldEnum {
				return "VARCHAR(255)", nil
			}
			return "TEXT", nil
		}
		if options.Dialect == MSSQL {
			if field.Unique || field.Index || field.Sortable || field.Type == storage.FieldEnum {
				return "VARCHAR(255)", nil
			}
			return "VARCHAR(8000)", nil
		}
		return "TEXT", nil
	case storage.FieldBoolean:
		switch options.Dialect {
		case Postgres, MySQL:
			return "BOOLEAN", nil
		case MSSQL:
			return "SMALLINT", nil
		}
		return "INTEGER", nil
	case storage.FieldNumber:
		if field.BigInt {
			return "BIGINT", nil
		}
		return "INTEGER", nil
	case storage.FieldDate:
		switch options.Dialect {
		case Postgres:
			return "TIMESTAMPTZ", nil
		case MySQL:
			return "TIMESTAMP(3)", nil
		case MSSQL:
			return "DATETIME2(3)", nil
		}
		return "DATE", nil
	case storage.FieldJSON, storage.FieldStringArray, storage.FieldNumberArray:
		switch options.Dialect {
		case Postgres:
			return "JSONB", nil
		case MySQL:
			return "JSON", nil
		case MSSQL:
			return "VARCHAR(8000)", nil
		}
		return "TEXT", nil
	default:
		return "", fmt.Errorf("migration: unsupported field type %q", field.Type)
	}
}

func idColumnType(options Options) string {
	if options.IDMode == SerialID {
		switch options.Dialect {
		case Postgres:
			return "INTEGER GENERATED BY DEFAULT AS IDENTITY"
		case MySQL:
			return "INTEGER AUTO_INCREMENT"
		case MSSQL:
			return "INTEGER IDENTITY(1,1)"
		}
		return "INTEGER"
	}
	if options.IDMode == UUIDID && options.Dialect == Postgres {
		return "UUID DEFAULT pg_catalog.gen_random_uuid()"
	}
	if options.Dialect == MySQL || options.Dialect == MSSQL {
		return "VARCHAR(36)"
	}
	return "TEXT"
}

func createIndexSQL(table, field string, unique bool, dialect Dialect) string {
	kind := "INDEX"
	suffix := "idx"
	if unique {
		kind = "UNIQUE INDEX"
		suffix = "uidx"
	}
	return fmt.Sprintf(
		"CREATE %s %s ON %s (%s)",
		kind,
		quoteIdentifier(indexObjectName(table, field, suffix, dialect), dialect),
		quoteIdentifier(table, dialect),
		quoteIdentifier(field, dialect),
	)
}

type referenceDefinition struct {
	table       string
	field       string
	targetTable string
	targetField string
	action      string
}

func resolveReferenceDefinition(
	schema storage.Schema,
	model string,
	canonical string,
	field storage.FieldAttribute,
	dialect Dialect,
) (referenceDefinition, error) {
	physical := field.FieldName
	if physical == "" {
		physical = canonical
	}
	if dialect == MySQL && field.References.OnDelete == storage.SetNull && field.IsRequired() {
		return referenceDefinition{}, fmt.Errorf("migration: MySQL SET NULL reference %s.%s must be optional", model, canonical)
	}
	action, err := deleteActionSQLForDialect(field.References.OnDelete, dialect)
	if err != nil {
		return referenceDefinition{}, err
	}
	current, _, err := schema.ResolveModel(model)
	if err != nil {
		return referenceDefinition{}, fmt.Errorf("migration: resolve reference model %q: %w", model, err)
	}
	target, _, err := schema.ResolveModel(field.References.Model)
	if err != nil {
		return referenceDefinition{}, fmt.Errorf("migration: resolve reference target %q: %w", field.References.Model, err)
	}
	targetField, _, err := schema.ResolveField(field.References.Model, field.References.Field)
	if err != nil {
		return referenceDefinition{}, fmt.Errorf(
			"migration: resolve reference target %s.%s: %w",
			field.References.Model,
			field.References.Field,
			err,
		)
	}
	return referenceDefinition{
		table:       physicalModelName(schema, current),
		field:       physical,
		targetTable: physicalModelName(schema, target),
		targetField: targetField.FieldName,
		action:      action,
	}, nil
}

func physicalModelName(schema storage.Schema, model storage.ModelSchema) string {
	name := model.ModelName
	if schema.UsePlural {
		name += "s"
	}
	return name
}

func foreignKeySQL(
	schema storage.Schema,
	model string,
	canonical string,
	field storage.FieldAttribute,
	options Options,
) (string, error) {
	reference, err := resolveReferenceDefinition(schema, model, canonical, field, options.Dialect)
	if err != nil {
		return "", err
	}
	constraint := databaseObjectName(options.Dialect, "fk", reference.table, reference.field)
	withCheck := ""
	if options.Dialect == MSSQL {
		withCheck = " WITH CHECK"
	}
	return fmt.Sprintf(
		"ALTER TABLE %s%s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s",
		quoteIdentifier(reference.table, options.Dialect),
		withCheck,
		quoteIdentifier(constraint, options.Dialect),
		quoteIdentifier(reference.field, options.Dialect),
		quoteIdentifier(reference.targetTable, options.Dialect),
		quoteIdentifier(reference.targetField, options.Dialect),
		reference.action,
	), nil
}

func usesDeferredForeignKeys(dialect Dialect) bool {
	return dialect == Postgres || dialect == MySQL || dialect == MSSQL
}

func indexObjectName(table, field, suffix string, dialect Dialect) string {
	if dialect == MySQL || dialect == MSSQL {
		return databaseObjectName(dialect, "idx", table, field)
	}
	name := table + "_" + field + "_" + suffix
	if dialect == Postgres {
		return truncateUTF8ObjectName(name, 63)
	}
	return name
}

func databaseObjectName(dialect Dialect, kind, table, field string) string {
	raw := "single_" + table + "_" + field + "_" + kind
	switch dialect {
	case Postgres:
		return truncateUTF8ObjectName(raw, 63)
	case MySQL:
		return truncateUTF8ObjectName(raw, 64)
	case MSSQL:
		return truncateUTF16ObjectName(raw, 128)
	default:
		return raw
	}
}

func truncateUTF8ObjectName(raw string, limit int) string {
	if len(raw) <= limit {
		return raw
	}
	suffix := objectNameHashSuffix(raw)
	prefix := raw
	for len(prefix) > limit-len(suffix) {
		_, size := utf8.DecodeLastRuneInString(prefix)
		prefix = prefix[:len(prefix)-size]
	}
	return prefix + suffix
}

func truncateUTF16ObjectName(raw string, limit int) string {
	if utf16ObjectNameLength(raw) <= limit {
		return raw
	}
	suffix := objectNameHashSuffix(raw)
	prefix := raw
	for utf16ObjectNameLength(prefix) > limit-utf16ObjectNameLength(suffix) {
		runes := []rune(prefix)
		prefix = string(runes[:len(runes)-1])
	}
	return prefix + suffix
}

func objectNameHashSuffix(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return "_" + hex.EncodeToString(digest[:6])
}

func utf16ObjectNameLength(value string) int {
	return len(utf16.Encode([]rune(value)))
}

func addColumnSQL(table, definition string, dialect Dialect) string {
	keyword := "ADD COLUMN"
	if dialect == MSSQL {
		keyword = "ADD"
	}
	return fmt.Sprintf("ALTER TABLE %s %s %s", quoteIdentifier(table, dialect), keyword, definition)
}

func deleteActionSQLForDialect(action storage.DeleteAction, dialect Dialect) (string, error) {
	switch action {
	case storage.NoAction:
		return "NO ACTION", nil
	case storage.Restrict:
		if dialect == MSSQL {
			return "NO ACTION", nil
		}
		return "RESTRICT", nil
	case storage.SetNull:
		return "SET NULL", nil
	case storage.SetDefault:
		if dialect == MySQL {
			return "", fmt.Errorf("migration: MySQL does not support ON DELETE SET DEFAULT")
		}
		return "SET DEFAULT", nil
	default:
		return "CASCADE", nil
	}
}

func supportedDialect(dialect Dialect) bool {
	return dialect == SQLite || dialect == Postgres || dialect == MySQL || dialect == MSSQL
}

func tableBelongsToCatalog(table Table, catalog Catalog, dialect Dialect) bool {
	switch dialect {
	case Postgres:
		if catalog.Database != "" && table.Database != catalog.Database {
			return false
		}
		return catalog.Schema == "" || table.Schema == catalog.Schema
	case MySQL:
		database := catalog.Database
		if database == "" {
			database = catalog.Schema
		}
		tableDatabase := table.Database
		if tableDatabase == "" {
			tableDatabase = table.Schema
		}
		return database == "" || tableDatabase == database
	case MSSQL:
		if catalog.Database != "" && table.Database != catalog.Database {
			return false
		}
		return catalog.Schema == "" || table.Schema == catalog.Schema
	default:
		return true
	}
}

func normalizeColumnType(dataType string) string {
	normalized := strings.ToLower(strings.TrimSpace(dataType))
	if index := strings.IndexByte(normalized, '('); index >= 0 {
		normalized = normalized[:index]
	}
	normalized = strings.Join(strings.Fields(normalized), " ")
	normalized = strings.TrimSuffix(normalized, " unsigned")
	return normalized
}

func quoteIdentifier(identifier string, dialect Dialect) string {
	switch dialect {
	case MySQL:
		return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
	case MSSQL:
		return "[" + strings.ReplaceAll(identifier, "]", "]]") + "]"
	default:
		return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
	}
}

func quoteLiteral(value string, dialect Dialect) string {
	prefix := ""
	if dialect == MSSQL {
		prefix = "N"
	}
	return prefix + "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func sortedFieldNames(fields map[string]storage.FieldAttribute) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cloneFields(fields map[string]storage.FieldAttribute) map[string]storage.FieldAttribute {
	clone := make(map[string]storage.FieldAttribute, len(fields))
	for name, field := range fields {
		field.Enum = append([]string(nil), field.Enum...)
		clone[name] = field
	}
	return clone
}
