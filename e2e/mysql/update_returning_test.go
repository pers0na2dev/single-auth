package mysql_e2e_test

import (
	"context"
	"database/sql"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pers0na2dev/single-auth/storage"
	mysqlstore "github.com/pers0na2dev/single-auth/storage/mysql"
)

func TestMySQLUpdateReturningRegressions(t *testing.T) {
	database := openUpdateRegressionMySQL(t)
	adapter, err := mysqlstore.New(database, mysqlstore.Options{Schema: updateRegressionSchema()})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("non-equality id predicate is not used for reselect", func(t *testing.T) {
		resetUpdateRegressionTable(t, database)
		insertUpdateRegressionTokens(t, database,
			updateRegressionToken{ID: "a", ClientID: "c1"},
			updateRegressionToken{ID: "b", ClientID: "c2"},
		)

		result, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "tokens",
			Where: []storage.Where{
				{Field: "clientId", Operator: storage.OpEq, Value: "c2"},
				{Field: "id", Operator: storage.OpNe, Value: "a"},
			},
			Update: storage.Record{"revoked": "2024-01-01T00:00:00.000Z"},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertUpdateRegressionRecord(t, result, storage.Record{
			"id": "b", "revoked": "2024-01-01T00:00:00.000Z", "clientId": "c2",
		})
		assertUpdateRegressionRecord(t, queryUpdateRegressionToken(t, database, "a"), storage.Record{
			"id": "a", "revoked": nil, "clientId": "c1",
		})
	})

	t.Run("id predicate need not be first", func(t *testing.T) {
		resetUpdateRegressionTable(t, database)
		insertUpdateRegressionTokens(t, database,
			updateRegressionToken{ID: "a", ClientID: "c1"},
			updateRegressionToken{ID: "b", ClientID: "c1"},
			updateRegressionToken{ID: "c", ClientID: "c1"},
		)

		result, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "tokens",
			Where: []storage.Where{
				{Field: "revoked", Operator: storage.OpEq, Value: nil},
				{Field: "id", Value: "b"},
			},
			Update: storage.Record{"clientId": "c2"},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertUpdateRegressionRecord(t, result, storage.Record{
			"id": "b", "revoked": nil, "clientId": "c2",
		})
		assertUpdateRegressionRecords(t, queryUpdateRegressionTokens(t, database, "a", "c"), []storage.Record{
			{"id": "a", "revoked": nil, "clientId": "c1"},
			{"id": "c", "revoked": nil, "clientId": "c1"},
		})
	})

	t.Run("no matching row returns nil", func(t *testing.T) {
		resetUpdateRegressionTable(t, database)
		insertUpdateRegressionTokens(t, database, updateRegressionToken{ID: "a", ClientID: "c1"})

		result, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model:  "tokens",
			Where:  []storage.Where{{Field: "id", Value: "does-not-exist"}},
			Update: storage.Record{"clientId": "c2"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Fatalf("no-match update returned %#v, want nil", result)
		}
		assertUpdateRegressionRecord(t, queryUpdateRegressionToken(t, database, "a"), storage.Record{
			"id": "a", "revoked": nil, "clientId": "c1",
		})
	})

	t.Run("empty where returns nil without mutation", func(t *testing.T) {
		resetUpdateRegressionTable(t, database)
		insertUpdateRegressionTokens(t, database,
			updateRegressionToken{ID: "a", ClientID: "c1"},
			updateRegressionToken{ID: "b", ClientID: "c1"},
		)

		result, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "tokens", Where: nil, Update: storage.Record{"clientId": "c2"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result != nil {
			t.Fatalf("empty-where update returned %#v, want nil", result)
		}
		assertUpdateRegressionRecords(t, queryUpdateRegressionTokens(t, database, "a", "b"), []storage.Record{
			{"id": "a", "revoked": nil, "clientId": "c1"},
			{"id": "b", "revoked": nil, "clientId": "c1"},
		})
	})

	t.Run("multi-predicate guard miss returns nil", func(t *testing.T) {
		resetUpdateRegressionTable(t, database)
		insertUpdateRegressionTokens(t, database, updateRegressionToken{ID: "a", ClientID: "c1"})
		guard := []storage.Where{
			{Field: "id", Value: "a"},
			{Field: "revoked", Operator: storage.OpEq, Value: nil},
		}

		winner, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "tokens", Where: guard, Update: storage.Record{"revoked": "2024-01-01T00:00:00.000Z"},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertUpdateRegressionRecord(t, winner, storage.Record{
			"id": "a", "revoked": "2024-01-01T00:00:00.000Z", "clientId": "c1",
		})

		loser, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "tokens", Where: guard, Update: storage.Record{"revoked": "2099-01-01T00:00:00.000Z"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if loser != nil {
			t.Fatalf("failed guard returned %#v, want nil", loser)
		}
		assertUpdateRegressionRecord(t, queryUpdateRegressionToken(t, database, "a"), storage.Record{
			"id": "a", "revoked": "2024-01-01T00:00:00.000Z", "clientId": "c1",
		})
	})

	t.Run("single predicate returns updated row", func(t *testing.T) {
		resetUpdateRegressionTable(t, database)
		insertUpdateRegressionTokens(t, database, updateRegressionToken{ID: "a", ClientID: "c1"})

		result, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "tokens", Where: []storage.Where{{Field: "id", Value: "a"}}, Update: storage.Record{"clientId": "c2"},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertUpdateRegressionRecord(t, result, storage.Record{
			"id": "a", "revoked": nil, "clientId": "c2",
		})
	})
}

func updateRegressionSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"tokens": {
			ModelName: "tokens",
			Fields: map[string]storage.FieldAttribute{
				"revoked":  {Type: storage.FieldString},
				"clientId": {Type: storage.FieldString},
			},
		},
	}}
}

func openUpdateRegressionMySQL(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		mysqlImage,
		testcontainers.WithEnv(map[string]string{
			"MYSQL_DATABASE":      "single_auth",
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
			t.Fatalf("start required MySQL container: %v", err)
		}
		t.Skipf("Docker is unavailable for MySQL update regression tests: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("MySQL container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate MySQL update regression container: %v", terminateErr)
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
	config := gomysql.Config{
		User:                 "root",
		Passwd:               "single_auth_e2e",
		Net:                  "tcp",
		Addr:                 net.JoinHostPort(host, port.Port()),
		DBName:               "single_auth",
		AllowNativePasswords: true,
		ParseTime:            true,
		Loc:                  time.UTC,
		InterpolateParams:    true,
	}
	database, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close MySQL update regression database: %v", closeErr)
		}
	})
	if err := database.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	return database
}

func resetUpdateRegressionTable(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(t.Context(), "DROP TABLE IF EXISTS tokens"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(
		t.Context(),
		"CREATE TABLE tokens (id VARCHAR(36) PRIMARY KEY, revoked TEXT NULL, clientId TEXT NULL, __single_present__revoked BOOLEAN NOT NULL DEFAULT TRUE, __single_present__clientId BOOLEAN NOT NULL DEFAULT TRUE)",
	); err != nil {
		t.Fatal(err)
	}
}

type updateRegressionToken struct {
	ID       string
	Revoked  *string
	ClientID string
}

func insertUpdateRegressionTokens(t *testing.T, database *sql.DB, tokens ...updateRegressionToken) {
	t.Helper()
	for _, token := range tokens {
		if _, err := database.ExecContext(
			t.Context(),
			"INSERT INTO tokens (id, revoked, clientId) VALUES (?, ?, ?)",
			token.ID,
			token.Revoked,
			token.ClientID,
		); err != nil {
			t.Fatal(err)
		}
	}
}

func queryUpdateRegressionToken(t *testing.T, database *sql.DB, id string) storage.Record {
	t.Helper()
	rows := queryUpdateRegressionTokens(t, database, id)
	if len(rows) != 1 {
		t.Fatalf("token %q row count = %d, want 1", id, len(rows))
	}
	return rows[0]
}

func queryUpdateRegressionTokens(t *testing.T, database *sql.DB, ids ...string) []storage.Record {
	t.Helper()
	query := "SELECT id, revoked, clientId FROM tokens"
	args := make([]any, 0, len(ids))
	if len(ids) > 0 {
		query += " WHERE id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
		for _, id := range ids {
			args = append(args, id)
		}
	}
	query += " ORDER BY id"

	rows, err := database.QueryContext(t.Context(), query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	result := make([]storage.Record, 0)
	for rows.Next() {
		var id, clientID string
		var revoked sql.NullString
		if err := rows.Scan(&id, &revoked, &clientID); err != nil {
			t.Fatal(err)
		}
		var revokedValue any
		if revoked.Valid {
			revokedValue = revoked.String
		}
		result = append(result, storage.Record{
			"id": id, "revoked": revokedValue, "clientId": clientID,
		})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertUpdateRegressionRecord(t *testing.T, actual, expected storage.Record) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("record = %#v, want %#v", actual, expected)
	}
}

func assertUpdateRegressionRecords(t *testing.T, actual, expected []storage.Record) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("records = %#v, want %#v", actual, expected)
	}
}
