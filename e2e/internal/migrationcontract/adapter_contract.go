package migrationcontract

import (
	"database/sql"
	"fmt"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
)

const (
	adapterParentTable = "adapter_migration_parent"
	adapterChildTable  = "adapter_migration_child"
)

// AdapterFactory binds one live database to an adapter configured with the
// supplied schema. The returned adapter must also implement SchemaEnsurer.
type AdapterFactory func(storage.Schema) (storage.Adapter, error)

// RunAdapterEnsureSchema verifies the public Auth.RunMigrations ->
// Adapter.EnsureSchema path against a real backend. It deliberately starts
// from a valid older schema and then adds a field carrying an index and foreign
// key, proving that runtime migration does more than idempotent initial CREATE.
func RunAdapterEnsureSchema(
	t *testing.T,
	database *sql.DB,
	dialect migration.Dialect,
	factory AdapterFactory,
) {
	t.Helper()
	if database == nil {
		t.Fatal("adapter migration contract database is nil")
	}
	if factory == nil {
		t.Fatal("adapter migration contract factory is nil")
	}

	initial := adapterInitialSchema(dialect)
	initialAdapter := newAdapter(t, factory, initial)
	runPublicMigrations(t, initialAdapter)

	initialCatalog := inspect(t, database, dialect)
	assertNamespace(t, initialCatalog, dialect)
	assertSchemaTypes(t, initialCatalog, dialect, initial)
	assertPresenceColumns(t, initialCatalog, initial)
	assertAdapterDateDefaultAndUnique(t, database, dialect)

	upgraded := initial.Clone()
	child := upgraded.Models["child"]
	referenceField := "id"
	if dialect != migration.SQLite {
		// The initial plain column is VARCHAR(255) on MySQL/SQL Server. Pointing
		// it at the parent's unique VARCHAR(255) code exercises metadata-only FK
		// reconciliation without an unsafe implicit column-type rewrite.
		referenceField = "code"
	}
	child.Fields["parentId"] = storage.FieldAttribute{
		Type:      storage.FieldString,
		FieldName: "parent_id",
		Required:  storage.Bool(false),
		Index:     true,
		Sortable:  true,
		References: &storage.Reference{
			Model:    "parent",
			Field:    referenceField,
			OnDelete: storage.Cascade,
		},
	}
	child.Fields["migrationTag"] = storage.FieldAttribute{
		Type:      storage.FieldString,
		FieldName: "migration_tag",
		Required:  storage.Bool(false),
	}
	upgraded.Models["child"] = child

	upgradedAdapter := newAdapter(t, factory, upgraded)
	runPublicMigrations(t, upgradedAdapter)
	// A second public call must re-inspect and converge without attempting any
	// additional DDL. Backend sqlmock tests assert the zero-statement detail;
	// this live call proves the externally observable idempotency.
	runPublicMigrations(t, upgradedAdapter)

	upgradedCatalog := inspect(t, database, dialect)
	assertNamespace(t, upgradedCatalog, dialect)
	assertSchemaTypes(t, upgradedCatalog, dialect, upgraded)
	assertPresenceColumns(t, upgradedCatalog, upgraded)
	assertAdapterIndexExists(t, database, dialect, adapterChildTable, "parent_id")
	assertAdapterForeignKeyExists(t, database, dialect, referenceField)
	assertNoop(t, buildFromDatabase(t, database, upgraded, dialect), dialect)
}

func adapterInitialSchema(dialect migration.Dialect) storage.Schema {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"child": {
			ModelName: adapterChildTable,
			Order:     0,
			Fields: map[string]storage.FieldAttribute{
				"createdAt": {
					Type:         storage.FieldDate,
					FieldName:    "created_at",
					DefaultValue: storage.StaticValue("now"),
				},
				"note": {
					Type:      storage.FieldString,
					Required:  storage.Bool(false),
					FieldName: "note",
				},
			},
		},
		"parent": {
			ModelName: adapterParentTable,
			Order:     100,
			Fields: map[string]storage.FieldAttribute{
				"code": {
					Type:      storage.FieldString,
					FieldName: "code",
					Unique:    true,
				},
			},
		},
	}}
	// PostgreSQL, MySQL, and SQL Server can add a foreign-key constraint to an
	// existing column. Starting with the plain column proves metadata-only
	// index/FK reconciliation and MySQL recovery after partially applied DDL.
	// SQLite cannot ADD CONSTRAINT without rebuilding the whole table, so its
	// native additive path creates the referenced column and inline FK together.
	if dialect != migration.SQLite {
		child := schema.Models["child"]
		child.Fields["parentId"] = storage.FieldAttribute{
			Type:      storage.FieldString,
			FieldName: "parent_id",
			Required:  storage.Bool(false),
			Sortable:  true,
		}
		schema.Models["child"] = child
	}
	return schema
}

func newAdapter(t *testing.T, factory AdapterFactory, schema storage.Schema) storage.Adapter {
	t.Helper()
	adapter, err := factory(schema)
	if err != nil {
		t.Fatalf("create native adapter: %v", err)
	}
	if adapter == nil {
		t.Fatal("native adapter factory returned nil")
	}
	if _, ok := adapter.(storage.SchemaEnsurer); !ok {
		t.Fatalf("adapter %q does not implement storage.SchemaEnsurer", adapter.ID())
	}
	return adapter
}

func runPublicMigrations(t *testing.T, adapter storage.Adapter) {
	t.Helper()
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:  "http://localhost:3000",
		Database: adapter,
	})
	if err != nil {
		t.Fatalf("initialize auth for public migration: %v", err)
	}
	if err := auth.RunMigrationsContext(t.Context()); err != nil {
		t.Fatalf("run public migration through adapter %q: %v", adapter.ID(), err)
	}
}

func assertPresenceColumns(t *testing.T, catalog migration.Catalog, schema storage.Schema) {
	t.Helper()
	for canonical, raw := range schema.Models {
		if raw.DisableMigrations {
			continue
		}
		resolved, _, err := schema.ResolveModel(canonical)
		if err != nil {
			t.Fatal(err)
		}
		physicalModel := resolved.ModelName
		if schema.UsePlural {
			physicalModel += "s"
		}
		table := findTable(t, catalog, physicalModel)
		columns := make(map[string]struct{}, len(table.Columns))
		for _, column := range table.Columns {
			columns[column.Name] = struct{}{}
		}
		for canonicalField := range raw.Fields {
			presence := "__single_present__" + canonicalField
			if _, exists := columns[presence]; !exists {
				t.Fatalf("table %q is missing adapter presence column %q", table.Name, presence)
			}
		}
	}
}

func assertAdapterDateDefaultAndUnique(t *testing.T, database *sql.DB, dialect migration.Dialect) {
	t.Helper()
	parent := quoteIdentifier(adapterParentTable, dialect)
	child := quoteIdentifier(adapterChildTable, dialect)
	id := quoteIdentifier("id", dialect)
	code := quoteIdentifier("code", dialect)
	createdAt := quoteIdentifier("created_at", dialect)

	if _, err := database.ExecContext(t.Context(), fmt.Sprintf(
		"INSERT INTO %s (%s, %s) VALUES ('adapter-parent-1', 'adapter-unique')",
		parent,
		id,
		code,
	)); err != nil {
		t.Fatalf("insert %s adapter parent: %v", dialect, err)
	}
	if _, err := database.ExecContext(t.Context(), fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES ('adapter-child-1')",
		child,
		id,
	)); err != nil {
		t.Fatalf("insert %s adapter child using database date default: %v", dialect, err)
	}
	var defaultCount int
	if err := database.QueryRowContext(t.Context(), fmt.Sprintf(
		"SELECT COUNT(*) FROM %s WHERE %s = 'adapter-child-1' AND %s IS NOT NULL",
		child,
		id,
		createdAt,
	)).Scan(&defaultCount); err != nil {
		t.Fatalf("inspect %s adapter date default: %v", dialect, err)
	}
	if defaultCount != 1 {
		t.Fatalf("%s adapter date default did not populate created_at", dialect)
	}
	if _, err := database.ExecContext(t.Context(), fmt.Sprintf(
		"INSERT INTO %s (%s, %s) VALUES ('adapter-parent-2', 'adapter-unique')",
		parent,
		id,
		code,
	)); err == nil {
		t.Fatalf("%s adapter unique field accepted a duplicate", dialect)
	}
}

func assertAdapterIndexExists(t *testing.T, database *sql.DB, dialect migration.Dialect, table, field string) {
	t.Helper()
	index := "single_" + table + "_" + field
	if dialect != migration.SQLite {
		index += "_idx"
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
		t.Fatalf("unsupported adapter index-inspection dialect %q", dialect)
	}
	if err != nil {
		t.Fatalf("inspect %s adapter index %q: %v", dialect, index, err)
	}
	if count != 1 {
		t.Fatalf("%s adapter index %q count = %d, want 1", dialect, index, count)
	}
}

func assertAdapterForeignKeyExists(t *testing.T, database *sql.DB, dialect migration.Dialect, targetColumn string) {
	t.Helper()
	if dialect == migration.SQLite {
		rows, err := database.QueryContext(t.Context(), `PRAGMA foreign_key_list("adapter_migration_child")`)
		if err != nil {
			t.Fatalf("inspect SQLite adapter foreign key: %v", err)
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			var id, sequence int
			var table, from, to, onUpdate, onDelete, match string
			if err := rows.Scan(&id, &sequence, &table, &from, &to, &onUpdate, &onDelete, &match); err != nil {
				t.Fatal(err)
			}
			if table == adapterParentTable && from == "parent_id" && to == targetColumn {
				count++
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("SQLite adapter foreign-key count = %d, want 1", count)
		}
		return
	}

	var count int
	var err error
	switch dialect {
	case migration.Postgres:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM information_schema.table_constraints AS tc JOIN information_schema.key_column_usage AS child ON child.constraint_catalog = tc.constraint_catalog AND child.constraint_schema = tc.constraint_schema AND child.constraint_name = tc.constraint_name JOIN information_schema.constraint_column_usage AS parent ON parent.constraint_catalog = tc.constraint_catalog AND parent.constraint_schema = tc.constraint_schema AND parent.constraint_name = tc.constraint_name WHERE tc.constraint_type = 'FOREIGN KEY' AND child.constraint_schema = current_schema() AND child.table_name = $1 AND child.column_name = 'parent_id' AND parent.table_name = $2 AND parent.column_name = $3`, adapterChildTable, adapterParentTable, targetColumn).Scan(&count)
	case migration.MySQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM information_schema.key_column_usage WHERE constraint_schema = DATABASE() AND table_name = ? AND column_name = 'parent_id' AND referenced_table_name = ? AND referenced_column_name = ?`, adapterChildTable, adapterParentTable, targetColumn).Scan(&count)
	case migration.MSSQL:
		err = database.QueryRowContext(t.Context(), `SELECT COUNT_BIG(*) FROM sys.foreign_key_columns AS fkc JOIN sys.columns AS pc ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id JOIN sys.columns AS rc ON rc.object_id = fkc.referenced_object_id AND rc.column_id = fkc.referenced_column_id WHERE fkc.parent_object_id = OBJECT_ID(N'[adapter_migration_child]', N'U') AND fkc.referenced_object_id = OBJECT_ID(N'[adapter_migration_parent]', N'U') AND pc.name = N'parent_id' AND rc.name = @p1`, targetColumn).Scan(&count)
	default:
		t.Fatalf("unsupported adapter foreign-key inspection dialect %q", dialect)
	}
	if err != nil {
		t.Fatalf("inspect %s adapter foreign key: %v", dialect, err)
	}
	if count != 1 {
		t.Fatalf("%s adapter foreign-key count = %d, want 1", dialect, count)
	}
}
