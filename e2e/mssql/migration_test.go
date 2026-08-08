package mssql_e2e_test

import (
	"context"
	"database/sql"
	"io"
	"os"
	"sort"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	tcmssql "github.com/testcontainers/testcontainers-go/modules/mssql"

	"github.com/pers0na2dev/single-auth/e2e/internal/migrationcontract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
	mssqlstore "github.com/pers0na2dev/single-auth/storage/mssql"
)

func TestMSSQLMigrationAgainstRealServer(t *testing.T) {
	database := openMigrationMSSQL(t)
	ctx := t.Context()
	core := mssqlMigrationSchemaWithEarlyReference()

	initial, err := migration.BuildFromDatabase(ctx, database, core, migration.Options{Dialect: migration.MSSQL})
	if err != nil {
		t.Fatalf("build initial SQL Server migration: %v", err)
	}
	assertMSSQLMigrationChanges(t, initial.ToBeCreated, []string{"account", "earlyReference", "rateLimit", "session", "user", "verification"})
	if err := initial.Run(ctx, database); err != nil {
		t.Fatalf("run initial SQL Server migration: %v", err)
	}
	var referenceCount int64
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT_BIG(*)
		FROM sys.foreign_key_columns
		WHERE parent_object_id = OBJECT_ID(N'[earlyReference]', N'U')
		  AND referenced_object_id = OBJECT_ID(N'[user]', N'U')`).Scan(&referenceCount); err != nil {
		t.Fatalf("inspect SQL Server early foreign key: %v", err)
	}
	if referenceCount != 1 {
		t.Fatalf("SQL Server early foreign key count = %d, want 1", referenceCount)
	}

	catalog, err := migration.Inspect(ctx, database, migration.MSSQL)
	if err != nil {
		t.Fatalf("inspect migrated SQL Server database: %v", err)
	}
	assertMSSQLMigrationCatalog(t, catalog, []string{"account", "earlyReference", "rateLimit", "session", "user", "verification"})

	second, err := migration.BuildFromDatabase(ctx, database, core, migration.Options{Dialect: migration.MSSQL})
	if err != nil {
		t.Fatalf("build second SQL Server migration: %v", err)
	}
	assertMSSQLMigrationNoop(t, second)

	upgraded := core.Clone()
	user := upgraded.Models["user"]
	user.Fields["migrationTag"] = storage.FieldAttribute{
		Type:      storage.FieldString,
		FieldName: "migration_tag",
		Required:  storage.Bool(false),
		Index:     true,
	}
	upgraded.Models["user"] = user

	upgrade, err := migration.BuildFromDatabase(ctx, database, upgraded, migration.Options{Dialect: migration.MSSQL})
	if err != nil {
		t.Fatalf("build SQL Server upgrade migration: %v", err)
	}
	assertMSSQLMigrationUpgrade(t, upgrade)
	if err := upgrade.Run(ctx, database); err != nil {
		t.Fatalf("run SQL Server upgrade migration: %v", err)
	}

	upgradedCatalog, err := migration.Inspect(ctx, database, migration.MSSQL)
	if err != nil {
		t.Fatalf("inspect upgraded SQL Server database: %v", err)
	}
	if !mssqlMigrationCatalogHasColumn(upgradedCatalog, "user", "migration_tag") {
		t.Fatal("upgraded SQL Server user table does not contain migration_tag")
	}
	var indexCount int64
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT_BIG(*)
		FROM sys.indexes AS i
		JOIN sys.tables AS t ON t.object_id = i.object_id
		JOIN sys.schemas AS s ON s.schema_id = t.schema_id
		WHERE s.name = SCHEMA_NAME()
		  AND t.name = N'user'
		  AND i.name = N'single_user_migration_tag_idx'`).Scan(&indexCount); err != nil {
		t.Fatalf("inspect SQL Server migration index: %v", err)
	}
	if indexCount != 1 {
		t.Fatalf("SQL Server migration index count = %d, want 1", indexCount)
	}

	afterUpgrade, err := migration.BuildFromDatabase(ctx, database, upgraded, migration.Options{Dialect: migration.MSSQL})
	if err != nil {
		t.Fatalf("build post-upgrade SQL Server migration: %v", err)
	}
	assertMSSQLMigrationNoop(t, afterUpgrade)

	migrationcontract.Run(t, database, migration.MSSQL)
	migrationcontract.RunAdapterEnsureSchema(
		t,
		database,
		migration.MSSQL,
		func(schema storage.Schema) (storage.Adapter, error) {
			return mssqlstore.New(database, mssqlstore.Options{Schema: schema})
		},
	)
}

func TestMSSQLSerialIDForeignKeyMigrationAgainstRealServer(t *testing.T) {
	database := openMigrationMSSQL(t)
	ctx := t.Context()
	schema := mssqlMigrationSchemaWithEarlyReference()
	options := migration.Options{Dialect: migration.MSSQL, IDMode: migration.SerialID}

	initial, err := migration.BuildFromDatabase(ctx, database, schema, options)
	if err != nil {
		t.Fatalf("build SQL Server serial-ID migration: %v", err)
	}
	if err := initial.Run(ctx, database); err != nil {
		t.Fatalf("run SQL Server serial-ID migration: %v", err)
	}

	var parentType string
	var parentIdentity bool
	if err := database.QueryRowContext(ctx, `
		SELECT ty.name, c.is_identity
		FROM sys.tables AS t
		JOIN sys.schemas AS s ON s.schema_id = t.schema_id
		JOIN sys.columns AS c ON c.object_id = t.object_id
		JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
		WHERE s.name = SCHEMA_NAME()
		  AND t.name = N'user'
		  AND c.name = N'id'`).Scan(&parentType, &parentIdentity); err != nil {
		t.Fatalf("inspect SQL Server serial parent ID: %v", err)
	}
	var referenceType string
	var referenceIdentity bool
	if err := database.QueryRowContext(ctx, `
		SELECT ty.name, c.is_identity
		FROM sys.tables AS t
		JOIN sys.schemas AS s ON s.schema_id = t.schema_id
		JOIN sys.columns AS c ON c.object_id = t.object_id
		JOIN sys.types AS ty ON ty.user_type_id = c.user_type_id
		WHERE s.name = SCHEMA_NAME()
		  AND t.name = N'earlyReference'
		  AND c.name = N'userId'`).Scan(&referenceType, &referenceIdentity); err != nil {
		t.Fatalf("inspect SQL Server serial reference: %v", err)
	}
	if parentType != "int" || referenceType != parentType || !parentIdentity || referenceIdentity {
		t.Fatalf(
			"SQL Server serial metadata parent=(%q, identity=%t) reference=(%q, identity=%t), want int identity -> int",
			parentType,
			parentIdentity,
			referenceType,
			referenceIdentity,
		)
	}
	var referenceCount int64
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT_BIG(*)
		FROM sys.foreign_key_columns
		WHERE parent_object_id = OBJECT_ID(N'[earlyReference]', N'U')
		  AND referenced_object_id = OBJECT_ID(N'[user]', N'U')`).Scan(&referenceCount); err != nil {
		t.Fatalf("inspect SQL Server serial foreign key: %v", err)
	}
	if referenceCount != 1 {
		t.Fatalf("SQL Server serial foreign key count = %d, want 1", referenceCount)
	}

	second, err := migration.BuildFromDatabase(ctx, database, schema, options)
	if err != nil {
		t.Fatalf("build second SQL Server serial-ID migration: %v", err)
	}
	assertMSSQLMigrationNoop(t, second)
}

func mssqlMigrationSchemaWithEarlyReference() storage.Schema {
	schema := storage.CoreSchema()
	schema.Models["earlyReference"] = storage.ModelSchema{
		ModelName: "earlyReference",
		Order:     0,
		Fields: map[string]storage.FieldAttribute{
			"userId": {
				Type: storage.FieldString,
				References: &storage.Reference{
					Model:    "user",
					Field:    "id",
					OnDelete: storage.Cascade,
				},
			},
		},
	}
	return schema
}

func openMigrationMSSQL(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()
	container, err := tcmssql.Run(
		ctx,
		mssqlImage,
		tcmssql.WithAcceptEULA(),
		tcmssql.WithPassword("Strong@Passw0rd"),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required SQL Server migration container: %v", err)
		}
		t.Skipf("Docker cannot run the local SQL Server migration E2E image: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("SQL Server migration container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate SQL Server migration container: %v", terminateErr)
		}
	})

	adminDSN, err := container.ConnectionString(
		ctx,
		"database=master",
		"encrypt=false",
		"TrustServerCertificate=true",
	)
	if err != nil {
		t.Fatal(err)
	}
	adminDatabase, err := sql.Open("sqlserver", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := adminDatabase.Close(); closeErr != nil {
			t.Errorf("close SQL Server migration admin database: %v", closeErr)
		}
	})
	if err := adminDatabase.PingContext(ctx); err != nil {
		t.Fatalf("ping SQL Server migration admin database: %v", err)
	}
	if _, err := adminDatabase.ExecContext(ctx, `CREATE DATABASE [single_auth_migration]`); err != nil {
		t.Fatalf("create SQL Server migration database: %v", err)
	}

	dsn, err := container.ConnectionString(
		ctx,
		"database=single_auth_migration",
		"encrypt=false",
		"TrustServerCertificate=true",
	)
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlserver", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close SQL Server migration database: %v", closeErr)
		}
	})
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("ping SQL Server migration database: %v", err)
	}
	return database
}

func assertMSSQLMigrationChanges(t *testing.T, changes []migration.TableChange, expected []string) {
	t.Helper()
	actual := make([]string, len(changes))
	for index, change := range changes {
		actual[index] = change.Table
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !equalMSSQLMigrationStrings(actual, expected) {
		t.Fatalf("created SQL Server tables = %q, want %q", actual, expected)
	}
}

func assertMSSQLMigrationCatalog(t *testing.T, catalog migration.Catalog, expected []string) {
	t.Helper()
	actual := make([]string, len(catalog.Tables))
	for index, table := range catalog.Tables {
		actual[index] = table.Name
		if table.Database != catalog.Database || table.Schema != catalog.Schema {
			t.Fatalf(
				"table %q namespace = %q.%q, catalog namespace = %q.%q",
				table.Name,
				table.Database,
				table.Schema,
				catalog.Database,
				catalog.Schema,
			)
		}
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !equalMSSQLMigrationStrings(actual, expected) {
		t.Fatalf("inspected SQL Server tables = %q, want %q", actual, expected)
	}
}

func assertMSSQLMigrationNoop(t *testing.T, plan migration.Plan) {
	t.Helper()
	if len(plan.ToBeCreated) != 0 || len(plan.ToBeAdded) != 0 || len(plan.Statements) != 0 || plan.SQL() != ";" {
		t.Fatalf("SQL Server migration is not a no-op: %#v", plan)
	}
}

func assertMSSQLMigrationUpgrade(t *testing.T, plan migration.Plan) {
	t.Helper()
	if len(plan.ToBeCreated) != 0 || len(plan.ToBeAdded) != 1 || plan.ToBeAdded[0].Table != "user" {
		t.Fatalf("unexpected SQL Server upgrade plan: %#v", plan)
	}
	if _, exists := plan.ToBeAdded[0].Fields["migrationTag"]; !exists || len(plan.Statements) != 2 {
		t.Fatalf("SQL Server upgrade does not add indexed migrationTag: %#v", plan)
	}
}

func mssqlMigrationCatalogHasColumn(catalog migration.Catalog, tableName, columnName string) bool {
	for _, table := range catalog.Tables {
		if table.Name != tableName {
			continue
		}
		for _, column := range table.Columns {
			if column.Name == columnName {
				return true
			}
		}
	}
	return false
}

func equalMSSQLMigrationStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
