package postgres_e2e_test

import (
	"context"
	"database/sql"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pers0na2dev/single-auth/e2e/internal/migrationcontract"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/migration"
	postgresstore "github.com/pers0na2dev/single-auth/storage/postgres"
)

// TestPostgresJSRunMigrationCreatesExactlyCoreTables is the executable Go
// counterpart of reference implementation 1.6.26's postgres-js browser-manifest case. It
// executes the single-auth migration against a real PostgreSQL process and
// verifies the exact four-table contract (rateLimit is not materialized when
// database-backed rate limiting is not selected).
func TestPostgresJSRunMigrationCreatesExactlyCoreTables(t *testing.T) {
	ctx := t.Context()
	database := openMigrationPostgres(t)

	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	adapter, err := postgresstore.New(database, postgresstore.Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(ctx); err != nil {
		t.Fatalf("run migration: %v", err)
	}

	rows, err := database.QueryContext(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public'
		  AND table_type = 'BASE TABLE'
		ORDER BY CASE table_name
			WHEN 'user' THEN 1
			WHEN 'session' THEN 2
			WHEN 'account' THEN 3
			WHEN 'verification' THEN 4
			ELSE 5
		END, table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	tableNames := make([]string, 0, 4)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tableNames = append(tableNames, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"user", "session", "account", "verification"}
	if !reflect.DeepEqual(tableNames, want) {
		t.Fatalf("tables=%q, want %q", tableNames, want)
	}
}

func TestPostgresRelationalMigrationContract(t *testing.T) {
	database := openMigrationPostgres(t)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	if _, err := database.ExecContext(t.Context(), `CREATE SCHEMA migration_contract`); err != nil {
		t.Fatalf("create PostgreSQL migration contract schema: %v", err)
	}
	if _, err := database.ExecContext(t.Context(), `SET search_path TO missing_contract_schema, migration_contract, public`); err != nil {
		t.Fatalf("set PostgreSQL migration contract search_path: %v", err)
	}
	catalog, err := migration.Inspect(t.Context(), database, migration.Postgres)
	if err != nil {
		t.Fatalf("inspect PostgreSQL migration contract namespace: %v", err)
	}
	if catalog.Schema != "migration_contract" {
		t.Fatalf("effective PostgreSQL schema = %q, want migration_contract", catalog.Schema)
	}
	migrationcontract.Run(t, database, migration.Postgres)
	migrationcontract.RunAdapterEnsureSchema(
		t,
		database,
		migration.Postgres,
		func(schema storage.Schema) (storage.Adapter, error) {
			return postgresstore.New(database, postgresstore.Options{
				Schema:         schema,
				DatabaseSchema: "migration_contract",
			})
		},
	)
}

func openMigrationPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		postgresImage,
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_DB":       "single_auth",
			"POSTGRES_USER":     "user",
			"POSTGRES_PASSWORD": "password",
		}),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required PostgreSQL container: %v", err)
		}
		t.Skipf("Docker is unavailable for PostgreSQL migration behavior: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("PostgreSQL container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate PostgreSQL container: %v", terminateErr)
		}
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}
	dsn := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword("user", "password"),
		Host:   net.JoinHostPort(host, port.Port()),
		Path:   "/single_auth",
	}
	query := dsn.Query()
	query.Set("sslmode", "disable")
	dsn.RawQuery = query.Encode()

	database, err := sql.Open("pgx", dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close PostgreSQL migration handle: %v", closeErr)
		}
	})
	if err := database.PingContext(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}
	return database
}
