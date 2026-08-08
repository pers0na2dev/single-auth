// Package migrationcontract contains the shared native relational migration
// acceptance corpus used by SQLite, PostgreSQL, MySQL, and SQL Server E2E
// tests.
package migrationcontract

import (
	"database/sql"
	"fmt"
	"sort"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
)

const (
	parentTable = "migration_contract_parent"
	childTable  = "migration_contract_child"
	failureA    = "migration_failure_a"
	failureB    = "migration_failure_b"
)

// Run executes the same observable migration lifecycle against one live
// relational database. The caller owns database setup and cleanup.
func Run(t *testing.T, database *sql.DB, dialect migration.Dialect) {
	t.Helper()
	if database == nil {
		t.Fatal("migration contract database is nil")
	}

	schema := initialSchema()
	t.Run("initial create inspect and repeated no-op", func(t *testing.T) {
		plan := buildFromDatabase(t, database, schema, dialect)
		assertCreatedTables(t, plan, childTable, parentTable)
		minimumStatements := 4
		if dialect == migration.SQLite {
			// SQLite permits a forward reference in CREATE TABLE, so its foreign
			// key is inline rather than a fourth deferred statement.
			minimumStatements = 3
		}
		if len(plan.Statements) < minimumStatements {
			t.Fatalf("initial %s plan has %d statements, want tables, index, and foreign-key definition: %#v", dialect, len(plan.Statements), plan.Statements)
		}
		if err := plan.Run(t.Context(), database); err != nil {
			t.Fatalf("run initial %s migration: %v", dialect, err)
		}

		catalog := inspect(t, database, dialect)
		assertNamespace(t, catalog, dialect)
		assertSchemaTypes(t, catalog, dialect, schema)
		assertIndexExists(t, database, dialect, childTable, "parent_id")
		assertForeignKeyExists(t, database, dialect)
		assertDatabaseDefaultAndUniqueness(t, database, dialect)

		assertNoop(t, buildFromDatabase(t, database, schema, dialect), dialect)
	})

	upgraded := schema.Clone()
	child := upgraded.Models["child"]
	child.Fields["migrationTag"] = storage.FieldAttribute{
		Type:      storage.FieldString,
		FieldName: "migration_tag",
		Required:  storage.Bool(false),
		Index:     true,
	}
	upgraded.Models["child"] = child

	t.Run("additive indexed upgrade converges", func(t *testing.T) {
		plan := buildFromDatabase(t, database, upgraded, dialect)
		if len(plan.ToBeCreated) != 0 || len(plan.ToBeAdded) != 1 || plan.ToBeAdded[0].Table != childTable {
			t.Fatalf("unexpected %s additive plan: %#v", dialect, plan)
		}
		if _, exists := plan.ToBeAdded[0].Fields["migrationTag"]; !exists {
			t.Fatalf("%s additive plan omitted migrationTag: %#v", dialect, plan)
		}
		if err := plan.Run(t.Context(), database); err != nil {
			t.Fatalf("run %s additive migration: %v", dialect, err)
		}

		catalog := inspect(t, database, dialect)
		assertSchemaTypes(t, catalog, dialect, upgraded)
		assertIndexExists(t, database, dialect, childTable, "migration_tag")
		assertNoop(t, buildFromDatabase(t, database, upgraded, dialect), dialect)
	})

	t.Run("failure follows declared rollback policy and replans", func(t *testing.T) {
		policy, err := migration.RollbackPolicyForDialect(dialect)
		if err != nil {
			t.Fatal(err)
		}
		failurePlan := migration.Plan{Statements: []string{
			createProbeTableSQL(dialect, failureA),
			"THIS IS NOT VALID SQL",
			createProbeTableSQL(dialect, failureB),
		}}
		if err := failurePlan.Run(t.Context(), database); err == nil {
			t.Fatalf("%s failure probe unexpectedly succeeded", dialect)
		}

		aExists := tableExists(t, database, dialect, failureA)
		bExists := tableExists(t, database, dialect, failureB)
		if bExists {
			t.Fatalf("%s executed a statement after the failing statement", dialect)
		}
		switch policy {
		case migration.RollbackAtomic:
			if aExists {
				t.Fatalf("%s retained DDL despite atomic rollback policy", dialect)
			}
		case migration.RollbackMayPartiallyApply:
			if !aExists {
				t.Fatalf("%s did not demonstrate its documented partial-apply policy", dialect)
			}
		default:
			t.Fatalf("%s returned unknown rollback policy %q", dialect, policy)
		}

		recoverySchema := storage.Schema{Models: map[string]storage.ModelSchema{
			"failureA": {ModelName: failureA, Order: 0, Fields: map[string]storage.FieldAttribute{}},
			"failureB": {ModelName: failureB, Order: 1, Fields: map[string]storage.FieldAttribute{}},
		}}
		recovery := buildFromDatabase(t, database, recoverySchema, dialect)
		wantCreate := 2
		if policy == migration.RollbackMayPartiallyApply {
			wantCreate = 1
		}
		if len(recovery.ToBeCreated) != wantCreate {
			t.Fatalf("%s recovery creates %d tables, want %d: %#v", dialect, len(recovery.ToBeCreated), wantCreate, recovery)
		}
		if err := recovery.Run(t.Context(), database); err != nil {
			t.Fatalf("run %s recovery migration: %v", dialect, err)
		}
		assertNoop(t, buildFromDatabase(t, database, recoverySchema, dialect), dialect)
	})
}

func initialSchema() storage.Schema {
	optional := storage.Bool(false)
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"child": {
			ModelName: childTable,
			Order:     0,
			Fields: map[string]storage.FieldAttribute{
				"parentId": {
					Type:      storage.FieldString,
					FieldName: "parent_id",
					Index:     true,
					References: &storage.Reference{
						Model:    "parent",
						Field:    "id",
						OnDelete: storage.Cascade,
					},
				},
				"createdAt": {
					Type:         storage.FieldDate,
					FieldName:    "created_at",
					DefaultValue: storage.StaticValue("now"),
				},
				"enabled": {
					Type:      storage.FieldBoolean,
					FieldName: "enabled",
					Required:  optional,
				},
				"payload": {
					Type:      storage.FieldJSON,
					FieldName: "payload",
					Required:  optional,
				},
				"sequence": {
					Type:      storage.FieldNumber,
					FieldName: "sequence_no",
					Required:  optional,
					BigInt:    true,
				},
			},
		},
		"parent": {
			ModelName: parentTable,
			Order:     100,
			Fields: map[string]storage.FieldAttribute{
				"code": {
					Type:      storage.FieldString,
					FieldName: "code",
					Index:     true,
					Unique:    true,
				},
			},
		},
	}}
}

func buildFromDatabase(t *testing.T, database *sql.DB, schema storage.Schema, dialect migration.Dialect) migration.Plan {
	t.Helper()
	plan, err := migration.BuildFromDatabase(t.Context(), database, schema, migration.Options{Dialect: dialect})
	if err != nil {
		t.Fatalf("build %s migration: %v", dialect, err)
	}
	return plan
}

func inspect(t *testing.T, database *sql.DB, dialect migration.Dialect) migration.Catalog {
	t.Helper()
	catalog, err := migration.Inspect(t.Context(), database, dialect)
	if err != nil {
		t.Fatalf("inspect %s migration namespace: %v", dialect, err)
	}
	return catalog
}

func assertCreatedTables(t *testing.T, plan migration.Plan, expected ...string) {
	t.Helper()
	actual := make([]string, len(plan.ToBeCreated))
	for index, change := range plan.ToBeCreated {
		actual[index] = change.Table
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if fmt.Sprint(actual) != fmt.Sprint(expected) {
		t.Fatalf("created tables = %q, want %q", actual, expected)
	}
}

func assertNamespace(t *testing.T, catalog migration.Catalog, dialect migration.Dialect) {
	t.Helper()
	switch dialect {
	case migration.Postgres:
		if catalog.Database == "" || catalog.Schema == "" {
			t.Fatalf("PostgreSQL namespace is incomplete: %#v", catalog)
		}
	case migration.MySQL:
		if catalog.Database == "" {
			t.Fatalf("MySQL database namespace is empty: %#v", catalog)
		}
	case migration.MSSQL:
		if catalog.Database == "" || catalog.Schema == "" {
			t.Fatalf("SQL Server namespace is incomplete: %#v", catalog)
		}
	}

	for _, tableName := range []string{parentTable, childTable} {
		table := findTable(t, catalog, tableName)
		if table.Database != catalog.Database || table.Schema != catalog.Schema {
			t.Fatalf(
				"%s table %q namespace %q.%q differs from catalog %q.%q",
				dialect,
				tableName,
				table.Database,
				table.Schema,
				catalog.Database,
				catalog.Schema,
			)
		}
	}
}

func assertSchemaTypes(t *testing.T, catalog migration.Catalog, dialect migration.Dialect, schema storage.Schema) {
	t.Helper()
	for canonical, rawModel := range schema.Models {
		resolved, _, err := schema.ResolveModel(canonical)
		if err != nil {
			t.Fatal(err)
		}
		table := findTable(t, catalog, resolved.ModelName)
		columns := make(map[string]string, len(table.Columns))
		for _, column := range table.Columns {
			columns[column.Name] = column.DataType
		}
		for canonicalField, field := range rawModel.Fields {
			physical := field.FieldName
			if physical == "" {
				physical = canonicalField
			}
			dataType, exists := columns[physical]
			if !exists {
				t.Fatalf("%s table %q is missing column %q", dialect, table.Name, physical)
			}
			if !migration.MatchType(dataType, field.Type, dialect) {
				t.Fatalf("%s column %s.%s type %q does not match %q", dialect, table.Name, physical, dataType, field.Type)
			}
		}
	}
}

func assertNoop(t *testing.T, plan migration.Plan, dialect migration.Dialect) {
	t.Helper()
	if len(plan.ToBeCreated) != 0 || len(plan.ToBeAdded) != 0 || len(plan.Statements) != 0 || plan.SQL() != ";" {
		t.Fatalf("%s repeated migration is not a no-op: %#v", dialect, plan)
	}
}

func findTable(t *testing.T, catalog migration.Catalog, name string) migration.Table {
	t.Helper()
	for _, table := range catalog.Tables {
		if table.Name == name {
			return table
		}
	}
	t.Fatalf("catalog does not contain table %q: %#v", name, catalog)
	return migration.Table{}
}

func assertDatabaseDefaultAndUniqueness(t *testing.T, database *sql.DB, dialect migration.Dialect) {
	t.Helper()
	parent := quoteIdentifier(parentTable, dialect)
	child := quoteIdentifier(childTable, dialect)
	id := quoteIdentifier("id", dialect)
	code := quoteIdentifier("code", dialect)
	parentID := quoteIdentifier("parent_id", dialect)
	createdAt := quoteIdentifier("created_at", dialect)

	if _, err := database.ExecContext(t.Context(), fmt.Sprintf(
		"INSERT INTO %s (%s, %s) VALUES ('migration-parent-1', 'unique-code')",
		parent,
		id,
		code,
	)); err != nil {
		t.Fatalf("insert %s migration parent: %v", dialect, err)
	}
	if _, err := database.ExecContext(t.Context(), fmt.Sprintf(
		"INSERT INTO %s (%s, %s) VALUES ('migration-child-1', 'migration-parent-1')",
		child,
		id,
		parentID,
	)); err != nil {
		t.Fatalf("insert %s migration child using database date default: %v", dialect, err)
	}
	var defaultCount int
	if err := database.QueryRowContext(t.Context(), fmt.Sprintf(
		"SELECT COUNT(*) FROM %s WHERE %s = 'migration-child-1' AND %s IS NOT NULL",
		child,
		id,
		createdAt,
	)).Scan(&defaultCount); err != nil {
		t.Fatalf("inspect %s migration date default: %v", dialect, err)
	}
	if defaultCount != 1 {
		t.Fatalf("%s migration date default did not populate created_at", dialect)
	}
	if _, err := database.ExecContext(t.Context(), fmt.Sprintf(
		"INSERT INTO %s (%s, %s) VALUES ('migration-parent-2', 'unique-code')",
		parent,
		id,
		code,
	)); err == nil {
		t.Fatalf("%s migration unique field accepted a duplicate", dialect)
	}
}

func assertIndexExists(t *testing.T, database *sql.DB, dialect migration.Dialect, table, field string) {
	t.Helper()
	index := table + "_" + field + "_idx"
	if dialect == migration.MySQL || dialect == migration.MSSQL {
		index = "single_" + table + "_" + field + "_idx"
	}
	var count int
	var err error
	switch dialect {
	case migration.SQLite:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&count)
	case migration.Postgres:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND tablename = $1 AND indexname = $2`, table, index).Scan(&count)
	case migration.MySQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`, table, index).Scan(&count)
	case migration.MSSQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT_BIG(*) FROM sys.indexes AS i JOIN sys.tables AS t ON t.object_id = i.object_id JOIN sys.schemas AS s ON s.schema_id = t.schema_id WHERE s.name = SCHEMA_NAME() AND t.name = @p1 AND i.name = @p2`, table, index).Scan(&count)
	default:
		t.Fatalf("unsupported index-inspection dialect %q", dialect)
	}
	if err != nil {
		t.Fatalf("inspect %s index %q: %v", dialect, index, err)
	}
	if count != 1 {
		t.Fatalf("%s index %q count = %d, want 1", dialect, index, count)
	}
}

func assertForeignKeyExists(t *testing.T, database *sql.DB, dialect migration.Dialect) {
	t.Helper()
	if dialect == migration.SQLite {
		rows, err := database.QueryContext(t.Context(), `PRAGMA foreign_key_list("migration_contract_child")`)
		if err != nil {
			t.Fatalf("inspect SQLite migration foreign key: %v", err)
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var id, sequence int
			var table, from, to, onUpdate, onDelete, match string
			if err := rows.Scan(&id, &sequence, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
				t.Fatal(err)
			}
			if table == parentTable && from == "parent_id" && to == "id" {
				count++
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("SQLite migration foreign-key count = %d, want 1", count)
		}
		return
	}

	var count int
	var err error
	switch dialect {
	case migration.Postgres:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM information_schema.table_constraints WHERE constraint_schema = current_schema() AND table_name = $1 AND constraint_type = 'FOREIGN KEY'`, childTable).Scan(&count)
	case migration.MySQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM information_schema.key_column_usage WHERE constraint_schema = DATABASE() AND table_name = ? AND column_name = 'parent_id' AND referenced_table_name = ? AND referenced_column_name = 'id'`, childTable, parentTable).Scan(&count)
	case migration.MSSQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT_BIG(*) FROM sys.foreign_key_columns WHERE parent_object_id = OBJECT_ID(N'[migration_contract_child]', N'U') AND referenced_object_id = OBJECT_ID(N'[migration_contract_parent]', N'U')`).Scan(&count)
	default:
		t.Fatalf("unsupported foreign-key inspection dialect %q", dialect)
	}
	if err != nil {
		t.Fatalf("inspect %s migration foreign key: %v", dialect, err)
	}
	if count != 1 {
		t.Fatalf("%s migration foreign-key count = %d, want 1", dialect, count)
	}
}

func tableExists(t *testing.T, database *sql.DB, dialect migration.Dialect, table string) bool {
	t.Helper()
	var count int
	var err error
	switch dialect {
	case migration.SQLite:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&count)
	case migration.Postgres:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM information_schema.tables WHERE table_catalog = current_database() AND table_schema = current_schema() AND table_name = $1`, table).Scan(&count)
	case migration.MySQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?`, table).Scan(&count)
	case migration.MSSQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT_BIG(*) FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id WHERE s.name = SCHEMA_NAME() AND t.name = @p1`, table).Scan(&count)
	default:
		t.Fatalf("unsupported table-inspection dialect %q", dialect)
	}
	if err != nil {
		t.Fatalf("inspect %s table %q: %v", dialect, table, err)
	}
	return count == 1
}

func createProbeTableSQL(dialect migration.Dialect, table string) string {
	typeName := "TEXT"
	if dialect == migration.MySQL || dialect == migration.MSSQL {
		typeName = "VARCHAR(36)"
	}
	return fmt.Sprintf(
		"CREATE TABLE %s (%s %s NOT NULL PRIMARY KEY)",
		quoteIdentifier(table, dialect),
		quoteIdentifier("id", dialect),
		typeName,
	)
}

func quoteIdentifier(identifier string, dialect migration.Dialect) string {
	switch dialect {
	case migration.MySQL:
		return "`" + identifier + "`"
	case migration.MSSQL:
		return "[" + identifier + "]"
	default:
		return `"` + identifier + `"`
	}
}
