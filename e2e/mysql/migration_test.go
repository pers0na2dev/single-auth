package mysql_e2e_test

import (
	"context"
	"database/sql"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pers0na2dev/single-auth/e2e/internal/migrationcontract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
	mysqlstore "github.com/pers0na2dev/single-auth/storage/mysql"
)

func TestMySQLMigrationAgainstRealServer(t *testing.T) {
	database := openMigrationMySQL(t)
	ctx := t.Context()
	core := mysqlMigrationSchemaWithEarlyReference()

	initial, err := migration.BuildFromDatabase(ctx, database, core, migration.Options{Dialect: migration.MySQL})
	if err != nil {
		t.Fatalf("build initial MySQL migration: %v", err)
	}
	assertMySQLMigrationChanges(t, initial.ToBeCreated, []string{"account", "earlyReference", "rateLimit", "session", "user", "verification"})
	if err := initial.Run(ctx, database); err != nil {
		t.Fatalf("run initial MySQL migration: %v", err)
	}
	var referenceCount int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.key_column_usage
		WHERE constraint_schema = DATABASE()
		  AND table_name = 'earlyReference'
		  AND column_name = 'userId'
		  AND referenced_table_schema = DATABASE()
		  AND referenced_table_name = 'user'
		  AND referenced_column_name = 'id'`).Scan(&referenceCount); err != nil {
		t.Fatalf("inspect MySQL early foreign key: %v", err)
	}
	if referenceCount != 1 {
		t.Fatalf("MySQL early foreign key count = %d, want 1", referenceCount)
	}

	catalog, err := migration.Inspect(ctx, database, migration.MySQL)
	if err != nil {
		t.Fatalf("inspect migrated MySQL database: %v", err)
	}
	assertMySQLMigrationCatalog(t, catalog, []string{"account", "earlyReference", "rateLimit", "session", "user", "verification"})

	second, err := migration.BuildFromDatabase(ctx, database, core, migration.Options{Dialect: migration.MySQL})
	if err != nil {
		t.Fatalf("build second MySQL migration: %v", err)
	}
	assertMySQLMigrationNoop(t, second)

	upgraded := core.Clone()
	user := upgraded.Models["user"]
	user.Fields["migrationTag"] = storage.FieldAttribute{
		Type:      storage.FieldString,
		FieldName: "migration_tag",
		Required:  storage.Bool(false),
		Index:     true,
	}
	upgraded.Models["user"] = user

	upgrade, err := migration.BuildFromDatabase(ctx, database, upgraded, migration.Options{Dialect: migration.MySQL})
	if err != nil {
		t.Fatalf("build MySQL upgrade migration: %v", err)
	}
	assertMySQLMigrationUpgrade(t, upgrade)
	if err := upgrade.Run(ctx, database); err != nil {
		t.Fatalf("run MySQL upgrade migration: %v", err)
	}

	upgradedCatalog, err := migration.Inspect(ctx, database, migration.MySQL)
	if err != nil {
		t.Fatalf("inspect upgraded MySQL database: %v", err)
	}
	if !mysqlMigrationCatalogHasColumn(upgradedCatalog, "user", "migration_tag") {
		t.Fatal("upgraded MySQL user table does not contain migration_tag")
	}
	var indexCount int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.statistics
		WHERE table_schema = DATABASE()
		  AND table_name = 'user'
		  AND index_name = 'single_user_migration_tag_idx'`).Scan(&indexCount); err != nil {
		t.Fatalf("inspect MySQL migration index: %v", err)
	}
	if indexCount != 1 {
		t.Fatalf("MySQL migration index count = %d, want 1", indexCount)
	}

	afterUpgrade, err := migration.BuildFromDatabase(ctx, database, upgraded, migration.Options{Dialect: migration.MySQL})
	if err != nil {
		t.Fatalf("build post-upgrade MySQL migration: %v", err)
	}
	assertMySQLMigrationNoop(t, afterUpgrade)

	migrationcontract.Run(t, database, migration.MySQL)
	migrationcontract.RunAdapterEnsureSchema(
		t,
		database,
		migration.MySQL,
		func(schema storage.Schema) (storage.Adapter, error) {
			return mysqlstore.New(database, mysqlstore.Options{Schema: schema})
		},
	)
}

func TestMySQLSerialIDForeignKeyMigrationAgainstRealServer(t *testing.T) {
	database := openMigrationMySQL(t)
	ctx := t.Context()
	schema := mysqlMigrationSchemaWithEarlyReference()
	options := migration.Options{Dialect: migration.MySQL, IDMode: migration.SerialID}

	initial, err := migration.BuildFromDatabase(ctx, database, schema, options)
	if err != nil {
		t.Fatalf("build MySQL serial-ID migration: %v", err)
	}
	if err := initial.Run(ctx, database); err != nil {
		t.Fatalf("run MySQL serial-ID migration: %v", err)
	}

	var parentType, parentExtra string
	if err := database.QueryRowContext(ctx, `
		SELECT data_type, extra
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'user'
		  AND column_name = 'id'`).Scan(&parentType, &parentExtra); err != nil {
		t.Fatalf("inspect MySQL serial parent ID: %v", err)
	}
	var referenceType string
	if err := database.QueryRowContext(ctx, `
		SELECT data_type
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'earlyReference'
		  AND column_name = 'userId'`).Scan(&referenceType); err != nil {
		t.Fatalf("inspect MySQL serial reference: %v", err)
	}
	if parentType != "int" || referenceType != parentType || !strings.Contains(parentExtra, "auto_increment") {
		t.Fatalf(
			"MySQL serial metadata parent=(%q, %q) reference=%q, want int auto_increment -> int",
			parentType,
			parentExtra,
			referenceType,
		)
	}
	var referenceCount int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM information_schema.key_column_usage
		WHERE constraint_schema = DATABASE()
		  AND table_name = 'earlyReference'
		  AND column_name = 'userId'
		  AND referenced_table_schema = DATABASE()
		  AND referenced_table_name = 'user'
		  AND referenced_column_name = 'id'`).Scan(&referenceCount); err != nil {
		t.Fatalf("inspect MySQL serial foreign key: %v", err)
	}
	if referenceCount != 1 {
		t.Fatalf("MySQL serial foreign key count = %d, want 1", referenceCount)
	}

	second, err := migration.BuildFromDatabase(ctx, database, schema, options)
	if err != nil {
		t.Fatalf("build second MySQL serial-ID migration: %v", err)
	}
	assertMySQLMigrationNoop(t, second)
}

func mysqlMigrationSchemaWithEarlyReference() storage.Schema {
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

func openMigrationMySQL(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		mysqlImage,
		testcontainers.WithEnv(map[string]string{
			"MYSQL_DATABASE":      "single_auth_migration",
			"MYSQL_ROOT_PASSWORD": "single_auth_e2e",
		}),
		testcontainers.WithExposedPorts("3306/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306  MySQL Community Server - GPL.").
				WithOccurrence(1).
				WithStartupTimeout(90*time.Second),
		),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required MySQL migration container: %v", err)
		}
		t.Skipf("Docker is unavailable for MySQL migration E2E: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("MySQL migration container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate MySQL migration container: %v", terminateErr)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatal(err)
	}
	configuration := gomysql.Config{
		User:                 "root",
		Passwd:               "single_auth_e2e",
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(host, port.Port()),
		DBName:               "single_auth_migration",
		AllowNativePasswords: true,
		ParseTime:            true,
		Loc:                  time.UTC,
		InterpolateParams:    true,
	}
	database, err := sql.Open("mysql", configuration.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close MySQL migration database: %v", closeErr)
		}
	})
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("ping MySQL migration database: %v", err)
	}
	return database
}

func assertMySQLMigrationChanges(t *testing.T, changes []migration.TableChange, expected []string) {
	t.Helper()
	actual := make([]string, len(changes))
	for index, change := range changes {
		actual[index] = change.Table
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !equalMySQLMigrationStrings(actual, expected) {
		t.Fatalf("created MySQL tables = %q, want %q", actual, expected)
	}
}

func assertMySQLMigrationCatalog(t *testing.T, catalog migration.Catalog, expected []string) {
	t.Helper()
	actual := make([]string, len(catalog.Tables))
	for index, table := range catalog.Tables {
		actual[index] = table.Name
		if table.Database != catalog.Database {
			t.Fatalf("table %q database = %q, catalog database = %q", table.Name, table.Database, catalog.Database)
		}
	}
	sort.Strings(actual)
	sort.Strings(expected)
	if !equalMySQLMigrationStrings(actual, expected) {
		t.Fatalf("inspected MySQL tables = %q, want %q", actual, expected)
	}
}

func assertMySQLMigrationNoop(t *testing.T, plan migration.Plan) {
	t.Helper()
	if len(plan.ToBeCreated) != 0 || len(plan.ToBeAdded) != 0 || len(plan.Statements) != 0 || plan.SQL() != ";" {
		t.Fatalf("MySQL migration is not a no-op: %#v", plan)
	}
}

func assertMySQLMigrationUpgrade(t *testing.T, plan migration.Plan) {
	t.Helper()
	if len(plan.ToBeCreated) != 0 || len(plan.ToBeAdded) != 1 || plan.ToBeAdded[0].Table != "user" {
		t.Fatalf("unexpected MySQL upgrade plan: %#v", plan)
	}
	if _, exists := plan.ToBeAdded[0].Fields["migrationTag"]; !exists || len(plan.Statements) != 2 {
		t.Fatalf("MySQL upgrade does not add indexed migrationTag: %#v", plan)
	}
}

func mysqlMigrationCatalogHasColumn(catalog migration.Catalog, tableName, columnName string) bool {
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

func equalMySQLMigrationStrings(left, right []string) bool {
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
