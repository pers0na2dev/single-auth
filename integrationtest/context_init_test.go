package singleauth_test

import (
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	_ "modernc.org/sqlite"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

var contextInitDatabaseSequence atomic.Uint64

func TestNewWithSQLiteDatabaseUsesNativeAdapter(t *testing.T) {
	database := openContextInitDatabase(t)
	auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
		BaseURL: "http://localhost:3000",
	}, database)
	if err != nil {
		t.Fatal(err)
	}

	context, err := auth.Context()
	if err != nil {
		t.Fatal(err)
	}
	if context.Adapter.ID() != "sqlite" {
		t.Fatalf("adapter ID = %q, want sqlite", context.Adapter.ID())
	}
	if context.DatabaseType != "sqlite" || context.AdapterOptions.Type != "sqlite" {
		t.Fatalf("database metadata = %#v, type=%q", context.AdapterOptions, context.DatabaseType)
	}
	config := context.AdapterOptions.AdapterConfig
	if config == nil || config.AdapterID != "sqlite" || config.AdapterName != "SQLite Adapter" {
		t.Fatalf("adapter config = %#v", config)
	}
}

func TestContextInitSQLiteMigrationCreatesSchema(t *testing.T) {
	database := openContextInitDatabase(t)
	auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
		BaseURL: "http://localhost:3000",
	}, database)
	if err != nil {
		t.Fatal(err)
	}
	context, err := auth.Context()
	if err != nil {
		t.Fatal(err)
	}
	if err := context.RunMigrationsContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	var tableCount int
	if err := database.QueryRowContext(
		t.Context(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('user', 'session', 'account', 'verification')`,
	).Scan(&tableCount); err != nil {
		t.Fatal(err)
	}
	if tableCount != 4 {
		t.Fatalf("migrated core table count = %d, want 4", tableCount)
	}
}

func TestNewWithSQLiteDatabaseRejectsInvalidBaseURL(t *testing.T) {
	for _, input := range []string{"localhost:6969", "ws://localhost:6969"} {
		t.Run(input, func(t *testing.T) {
			_, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{BaseURL: input}, openContextInitDatabase(t))
			if err == nil {
				t.Fatal("invalid base URL was accepted")
			}
			var upstreamError *singleauth.UpstreamError
			if !errors.As(err, &upstreamError) {
				t.Fatalf("error type = %T, want *singleauth.UpstreamError", err)
			}
		})
	}
}

func TestNewWithSQLiteDatabaseRejectsInvalidDatabaseConfiguration(t *testing.T) {
	if _, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{}, nil); err == nil {
		t.Fatal("nil SQLite database was accepted")
	}
	_, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
		Database: memory.MustNew(),
	}, openContextInitDatabase(t))
	if err == nil {
		t.Fatal("raw database and adapter were accepted together")
	}
}

func openContextInitDatabase(t *testing.T) *sql.DB {
	t.Helper()
	sequence := contextInitDatabaseSequence.Add(1)
	database, err := sql.Open(
		"sqlite",
		fmt.Sprintf("file:context_init_%d?mode=memory&cache=shared", sequence),
	)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close context init SQLite database: %v", err)
		}
	})
	return database
}
