package sqlite_e2e_test

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/pers0na2dev/single-auth/e2e/internal/migrationcontract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
	sqlitestore "github.com/pers0na2dev/single-auth/storage/sqlite"
)

func TestSQLiteRelationalMigrationContract(t *testing.T) {
	database, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close SQLite migration contract database: %v", err)
		}
	})
	if _, err := database.ExecContext(t.Context(), `PRAGMA foreign_keys = ON`); err != nil {
		t.Fatalf("enable SQLite foreign keys: %v", err)
	}

	migrationcontract.Run(t, database, migration.SQLite)
	migrationcontract.RunAdapterEnsureSchema(
		t,
		database,
		migration.SQLite,
		func(schema storage.Schema) (storage.Adapter, error) {
			return sqlitestore.New(database, sqlitestore.Options{Schema: schema})
		},
	)
}
