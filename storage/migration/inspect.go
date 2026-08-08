package migration

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/pers0na2dev/single-auth/storage"
)

const (
	postgresNamespaceQuery = `SELECT current_database(), current_schema()`
	postgresDatabaseQuery  = `SELECT current_database()`
	postgresColumnsQuery   = `SELECT table_catalog, table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE table_catalog = $1 AND table_schema = $2
ORDER BY table_name, ordinal_position`
	mysqlDatabaseQuery = `SELECT DATABASE()`
	mysqlColumnsQuery  = `SELECT table_schema, table_name, column_name, column_type
FROM information_schema.columns
WHERE table_schema = ?
ORDER BY table_name, ordinal_position`
	mssqlNamespaceQuery = `SELECT DB_NAME(), SCHEMA_NAME()`
	mssqlColumnsQuery   = `SELECT DB_NAME(), s.name, t.name, c.name, ty.name
FROM sys.tables AS t
JOIN sys.schemas AS s ON s.schema_id = t.schema_id
JOIN sys.columns AS c ON c.object_id = t.object_id
JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
WHERE s.name = @p1
ORDER BY t.name, c.column_id`
)

func Inspect(ctx context.Context, database *sql.DB, dialect Dialect) (Catalog, error) {
	if database == nil {
		return Catalog{}, fmt.Errorf("migration: database is nil")
	}
	switch dialect {
	case SQLite:
		return inspectSQLite(ctx, database)
	case Postgres:
		return inspectPostgres(ctx, database)
	case MySQL:
		return inspectMySQL(ctx, database)
	case MSSQL:
		return inspectMSSQL(ctx, database)
	default:
		return Catalog{}, fmt.Errorf("migration: unsupported dialect %q", dialect)
	}
}

func BuildFromDatabase(ctx context.Context, database *sql.DB, schema storage.Schema, options Options) (Plan, error) {
	catalog, err := Inspect(ctx, database, options.Dialect)
	if err != nil {
		return Plan{}, err
	}
	return Build(schema, catalog, options)
}

func inspectSQLite(ctx context.Context, database *sql.DB) (Catalog, error) {
	rows, err := database.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect SQLite tables: %w", err)
	}
	defer rows.Close()
	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return Catalog{}, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return Catalog{}, err
	}
	catalog := Catalog{Tables: make([]Table, 0, len(names))}
	for _, name := range names {
		columnRows, err := database.QueryContext(ctx, `PRAGMA table_info(`+sqliteQuote(name)+`)`)
		if err != nil {
			return Catalog{}, fmt.Errorf("migration: inspect SQLite table %q: %w", name, err)
		}
		table := Table{Name: name}
		for columnRows.Next() {
			var cid, notNull, primaryKey int
			var columnName, dataType string
			var defaultValue any
			if err := columnRows.Scan(&cid, &columnName, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
				columnRows.Close()
				return Catalog{}, err
			}
			table.Columns = append(table.Columns, Column{Name: columnName, DataType: dataType})
		}
		if err := columnRows.Close(); err != nil {
			return Catalog{}, err
		}
		catalog.Tables = append(catalog.Tables, table)
	}
	return catalog, nil
}

func inspectPostgres(ctx context.Context, database *sql.DB) (Catalog, error) {
	var currentDatabase, currentSchema sql.NullString
	if err := database.QueryRowContext(ctx, postgresNamespaceQuery).Scan(&currentDatabase, &currentSchema); err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect PostgreSQL namespace: %w", err)
	}
	if !currentDatabase.Valid || strings.TrimSpace(currentDatabase.String) == "" {
		return Catalog{}, fmt.Errorf("migration: inspect PostgreSQL: connection has no current database")
	}
	if !currentSchema.Valid || strings.TrimSpace(currentSchema.String) == "" {
		return Catalog{}, fmt.Errorf("migration: inspect PostgreSQL: search_path has no existing schema")
	}

	return inspectPostgresNamespace(ctx, database, currentDatabase.String, currentSchema.String)
}

// InspectPostgresSchema inspects one explicit PostgreSQL schema in the current
// database. It is used by adapters configured for a namespace that is not the
// connection's current search_path.
func InspectPostgresSchema(ctx context.Context, database *sql.DB, schema string) (Catalog, error) {
	if database == nil {
		return Catalog{}, fmt.Errorf("migration: database is nil")
	}
	schema = strings.TrimSpace(schema)
	if schema == "" {
		return Catalog{}, fmt.Errorf("migration: PostgreSQL schema is empty")
	}
	var currentDatabase sql.NullString
	if err := database.QueryRowContext(ctx, postgresDatabaseQuery).Scan(&currentDatabase); err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect PostgreSQL current database: %w", err)
	}
	if !currentDatabase.Valid || strings.TrimSpace(currentDatabase.String) == "" {
		return Catalog{}, fmt.Errorf("migration: inspect PostgreSQL: connection has no current database")
	}
	return inspectPostgresNamespace(ctx, database, currentDatabase.String, schema)
}

func inspectPostgresNamespace(ctx context.Context, database *sql.DB, catalogDatabase, catalogSchema string) (Catalog, error) {
	rows, err := database.QueryContext(ctx, postgresColumnsQuery, catalogDatabase, catalogSchema)
	if err != nil {
		return Catalog{}, fmt.Errorf(
			"migration: inspect PostgreSQL database %q schema %q: %w",
			catalogDatabase,
			catalogSchema,
			err,
		)
	}
	defer rows.Close()
	byName := make(map[string]*Table)
	order := make([]string, 0)
	for rows.Next() {
		var databaseName, schemaName, tableName, columnName, dataType string
		if err := rows.Scan(&databaseName, &schemaName, &tableName, &columnName, &dataType); err != nil {
			return Catalog{}, fmt.Errorf("migration: inspect PostgreSQL columns: %w", err)
		}
		if databaseName != catalogDatabase || schemaName != catalogSchema {
			continue
		}
		table := byName[tableName]
		if table == nil {
			table = &Table{Database: databaseName, Schema: schemaName, Name: tableName}
			byName[tableName] = table
			order = append(order, tableName)
		}
		table.Columns = append(table.Columns, Column{Name: columnName, DataType: dataType})
	}
	if err := rows.Err(); err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect PostgreSQL columns: %w", err)
	}
	catalog := Catalog{
		Database: catalogDatabase,
		Schema:   catalogSchema,
		Tables:   make([]Table, 0, len(order)),
	}
	for _, name := range order {
		catalog.Tables = append(catalog.Tables, *byName[name])
	}
	return catalog, nil
}

func inspectMySQL(ctx context.Context, database *sql.DB) (Catalog, error) {
	var currentDatabase sql.NullString
	if err := database.QueryRowContext(ctx, mysqlDatabaseQuery).Scan(&currentDatabase); err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect MySQL current database: %w", err)
	}
	if !currentDatabase.Valid || strings.TrimSpace(currentDatabase.String) == "" {
		return Catalog{}, fmt.Errorf("migration: inspect MySQL: connection has no current database")
	}

	rows, err := database.QueryContext(ctx, mysqlColumnsQuery, currentDatabase.String)
	if err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect MySQL database %q: %w", currentDatabase.String, err)
	}
	defer rows.Close()

	byName := make(map[string]*Table)
	order := make([]string, 0)
	for rows.Next() {
		var databaseName, tableName, columnName, dataType string
		if err := rows.Scan(&databaseName, &tableName, &columnName, &dataType); err != nil {
			return Catalog{}, fmt.Errorf("migration: inspect MySQL columns: %w", err)
		}
		if databaseName != currentDatabase.String {
			continue
		}
		table := byName[tableName]
		if table == nil {
			table = &Table{Database: databaseName, Name: tableName}
			byName[tableName] = table
			order = append(order, tableName)
		}
		table.Columns = append(table.Columns, Column{Name: columnName, DataType: dataType})
	}
	if err := rows.Err(); err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect MySQL columns: %w", err)
	}

	catalog := Catalog{Database: currentDatabase.String, Tables: make([]Table, 0, len(order))}
	for _, name := range order {
		catalog.Tables = append(catalog.Tables, *byName[name])
	}
	return catalog, nil
}

func inspectMSSQL(ctx context.Context, database *sql.DB) (Catalog, error) {
	var currentDatabase, currentSchema sql.NullString
	if err := database.QueryRowContext(ctx, mssqlNamespaceQuery).Scan(&currentDatabase, &currentSchema); err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect SQL Server namespace: %w", err)
	}
	if !currentDatabase.Valid || strings.TrimSpace(currentDatabase.String) == "" {
		return Catalog{}, fmt.Errorf("migration: inspect SQL Server: connection has no current database")
	}
	schema := "dbo"
	if currentSchema.Valid && strings.TrimSpace(currentSchema.String) != "" {
		schema = currentSchema.String
	}

	rows, err := database.QueryContext(ctx, mssqlColumnsQuery, schema)
	if err != nil {
		return Catalog{}, fmt.Errorf(
			"migration: inspect SQL Server database %q schema %q: %w",
			currentDatabase.String,
			schema,
			err,
		)
	}
	defer rows.Close()

	byName := make(map[string]*Table)
	order := make([]string, 0)
	for rows.Next() {
		var databaseName, schemaName, tableName, columnName, dataType string
		if err := rows.Scan(&databaseName, &schemaName, &tableName, &columnName, &dataType); err != nil {
			return Catalog{}, fmt.Errorf("migration: inspect SQL Server columns: %w", err)
		}
		if databaseName != currentDatabase.String || schemaName != schema {
			continue
		}
		table := byName[tableName]
		if table == nil {
			table = &Table{Database: databaseName, Schema: schemaName, Name: tableName}
			byName[tableName] = table
			order = append(order, tableName)
		}
		table.Columns = append(table.Columns, Column{Name: columnName, DataType: dataType})
	}
	if err := rows.Err(); err != nil {
		return Catalog{}, fmt.Errorf("migration: inspect SQL Server columns: %w", err)
	}

	catalog := Catalog{
		Database: currentDatabase.String,
		Schema:   schema,
		Tables:   make([]Table, 0, len(order)),
	}
	for _, name := range order {
		catalog.Tables = append(catalog.Tables, *byName[name])
	}
	return catalog, nil
}

func firstConcreteSchema(searchPath string) string {
	for _, raw := range strings.Split(searchPath, ",") {
		candidate := strings.Trim(strings.TrimSpace(raw), `"'`)
		variable := strings.TrimLeft(candidate, `\`)
		if candidate == "" || strings.HasPrefix(variable, "$") {
			continue
		}
		return candidate
	}
	return "public"
}

func sqliteQuote(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
