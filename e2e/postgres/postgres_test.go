package postgres_e2e_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	postgresstore "github.com/pers0na2dev/single-auth/storage/postgres"
)

const postgresImage = "postgres:17.4-alpine@sha256:7062a2109c4b51f3c792c7ea01e83ed12ef9a980886e3b3d380a7d2e5f6ce3f5"

func TestPostgresAdapterContractAgainstRealServer(t *testing.T) {
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		postgresImage,
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_DB":       "single_auth",
			"POSTGRES_USER":     "single_auth",
			"POSTGRES_PASSWORD": "single_auth_e2e",
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
		t.Skipf("Docker is unavailable for local PostgreSQL E2E: %v", err)
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
	baseURL := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword("single_auth", "single_auth_e2e"),
		Host:   net.JoinHostPort(host, port.Port()),
		Path:   "/single_auth",
	}
	query := baseURL.Query()
	query.Set("sslmode", "disable")
	baseURL.RawQuery = query.Encode()

	adminDB, err := sql.Open("pgx", baseURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := adminDB.Close(); closeErr != nil {
			t.Errorf("close PostgreSQL admin handle: %v", closeErr)
		}
	})
	if err := adminDB.PingContext(ctx); err != nil {
		t.Fatalf("ping PostgreSQL: %v", err)
	}

	var sequence atomic.Uint64
	newAdapter := func(t *testing.T, schema storage.Schema, idType postgresstore.IDType) (*postgresstore.Adapter, string, error) {
		t.Helper()
		name := fmt.Sprintf("contract_%d", sequence.Add(1))
		if _, err := adminDB.ExecContext(t.Context(), `CREATE SCHEMA "`+name+`"`); err != nil {
			return nil, "", fmt.Errorf("create isolated schema %s: %w", name, err)
		}
		adapter, err := postgresstore.New(adminDB, postgresstore.Options{
			Schema: schema, IDType: idType, DatabaseSchema: name,
		})
		if err != nil {
			return nil, "", err
		}
		if err := adapter.EnsureSchema(t.Context()); err != nil {
			return nil, "", err
		}
		return adapter, name, nil
	}

	adaptertest.Run(t, func(t *testing.T, schema storage.Schema) (storage.Adapter, error) {
		adapter, _, err := newAdapter(t, schema, postgresstore.TextID)
		return adapter, err
	})

	t.Run("native-jsonb-arrays-ilike-serial-and-multi-query-joins", func(t *testing.T) {
		runPostgresNativeBlockers(t, adminDB, newAdapter)
	})
}

type postgresAdapterFactory func(*testing.T, storage.Schema, postgresstore.IDType) (*postgresstore.Adapter, string, error)

func runPostgresNativeBlockers(t *testing.T, database *sql.DB, factory postgresAdapterFactory) {
	t.Helper()
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"name": {Type: storage.FieldString},
		}},
		"session": {Fields: map[string]storage.FieldAttribute{
			"token": {Type: storage.FieldString},
			"userId": {
				Type:       storage.FieldString,
				References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
			},
		}},
		"account": {Fields: map[string]storage.FieldAttribute{
			"provider": {Type: storage.FieldString},
			"userId": {
				Type:       storage.FieldString,
				References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
			},
		}},
		"document": {Fields: map[string]storage.FieldAttribute{
			"name":    {Type: storage.FieldString},
			"payload": {Type: storage.FieldJSON, Required: storage.Bool(false)},
			"labels":  {Type: storage.FieldStringArray, Required: storage.Bool(false)},
			"scores":  {Type: storage.FieldNumberArray, Required: storage.Bool(false)},
		}},
	}}
	adapter, databaseSchema, err := factory(t, schema, postgresstore.SerialID)
	if err != nil {
		t.Fatal(err)
	}

	user, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user", Data: storage.Record{"name": "AdminOne"},
	})
	if err != nil {
		t.Fatal(err)
	}
	userID, ok := user["id"].(string)
	if !ok || userID == "" {
		t.Fatalf("serial user ID = %#v", user["id"])
	}
	session, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "session", Data: storage.Record{"token": "token-1", "userId": userID},
	})
	if err != nil {
		t.Fatal(err)
	}
	account, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "account", Data: storage.Record{"provider": "github", "userId": userID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session["userId"] != userID || account["userId"] != userID {
		t.Fatalf("serial references were not decoded as strings: session=%#v account=%#v", session["userId"], account["userId"])
	}

	joined, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
		Join: map[string]storage.JoinOption{"session": {}, "account": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, sessionsOK := joined["session"].([]storage.Record)
	accounts, accountsOK := joined["account"].([]storage.Record)
	if !sessionsOK || len(sessions) != 1 || sessions[0]["userId"] != userID ||
		!accountsOK || len(accounts) != 1 || accounts[0]["userId"] != userID {
		t.Fatalf("multiple query joins = %#v", joined)
	}

	for _, where := range []storage.Where{
		{Field: "name", Operator: storage.OpContains, Value: `MIN%`, Mode: storage.Insensitive},
		{Field: "name", Operator: storage.OpStartsWith, Value: `ad_in`, Mode: storage.Insensitive},
		{Field: "name", Operator: storage.OpEndsWith, Value: `_one`, Mode: storage.Insensitive},
	} {
		matched, findErr := adapter.FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{where}})
		if findErr != nil || matched == nil || matched["id"] != userID {
			t.Fatalf("ILIKE wildcard %s(%q) = %#v, %v", where.Operator, where.Value, matched, findErr)
		}
	}
	exact, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "name", Value: `admin%`, Mode: storage.Insensitive}},
	})
	if err != nil || exact != nil {
		t.Fatalf("insensitive equality treated %% as wildcard: %#v, %v", exact, err)
	}

	payload := map[string]any{
		"enabled": true,
		"nested":  map[string]any{"count": float64(2)},
	}
	document, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "document",
		Data: storage.Record{
			"name": "jsonb", "payload": payload,
			"labels": []string{"Admin", "member"}, "scores": []float64{1, 2.5},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPostgresJSONDocument(t, document, payload, []string{"Admin", "member"}, []float64{1, 2.5})

	filters := []storage.Where{
		{Field: "payload", Value: map[string]any{"nested": map[string]any{"count": 2}, "enabled": true}},
		{Field: "labels", Value: []string{"Admin", "member"}},
		{Field: "labels", Operator: storage.OpContains, Value: "ADMIN", Mode: storage.Insensitive},
		{Field: "scores", Operator: storage.OpContains, Value: 2.5},
	}
	for _, where := range filters {
		matched, findErr := adapter.FindOne(t.Context(), storage.FindOneParams{Model: "document", Where: []storage.Where{where}})
		if findErr != nil || matched == nil || matched["id"] != document["id"] {
			t.Fatalf("JSONB filter %s(%s) = %#v, %v", where.Field, where.Operator, matched, findErr)
		}
	}

	updatedPayload := map[string]any{"enabled": false, "items": []any{"one", float64(2)}}
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "document", Where: []storage.Where{{Field: "id", Value: document["id"]}},
		Update: storage.Record{
			"payload": updatedPayload, "labels": []string{"owner"}, "scores": []float64{3.5},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPostgresJSONDocument(t, updated, updatedPayload, []string{"owner"}, []float64{3.5})

	qualifiedSchema := databaseSchema + "_qualified"
	if _, err := database.ExecContext(t.Context(), `CREATE SCHEMA "`+qualifiedSchema+`"`); err != nil {
		t.Fatal(err)
	}
	qualifiedModels := storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {
			ModelName: qualifiedSchema + ".users",
			Fields:    map[string]storage.FieldAttribute{"name": {Type: storage.FieldString}},
		},
		"session": {
			ModelName: qualifiedSchema + ".sessions",
			Fields: map[string]storage.FieldAttribute{
				"token": {Type: storage.FieldString},
				"userId": {
					Type:       storage.FieldString,
					References: &storage.Reference{Model: "user", Field: "id", OnDelete: storage.Cascade},
				},
			},
		},
	}}
	qualifiedAdapter, err := postgresstore.New(database, postgresstore.Options{
		Schema: qualifiedModels, DatabaseSchema: "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := qualifiedAdapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := qualifiedAdapter.Create(t.Context(), storage.CreateParams{
		Model: "user", Data: storage.Record{"id": "qualified-user", "name": "Qualified"}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := qualifiedAdapter.Create(t.Context(), storage.CreateParams{
		Model: "session", Data: storage.Record{"id": "qualified-session", "token": "qualified", "userId": "qualified-user"}, ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	qualifiedUser, err := qualifiedAdapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "qualified-user"}},
		Join: map[string]storage.JoinOption{"session": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	qualifiedSessions, ok := qualifiedUser["session"].([]storage.Record)
	if !ok || len(qualifiedSessions) != 1 || qualifiedSessions[0]["id"] != "qualified-session" {
		t.Fatalf("schema-qualified model join = %#v", qualifiedUser)
	}
	var qualifiedTables int
	if err := database.QueryRowContext(t.Context(), `
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = $1 AND table_name IN ('users', 'sessions')`, qualifiedSchema).Scan(&qualifiedTables); err != nil {
		t.Fatal(err)
	}
	if qualifiedTables != 2 {
		t.Fatalf("schema-qualified model tables = %d, want 2", qualifiedTables)
	}

	var customTables int
	if err := database.QueryRowContext(t.Context(), `
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = $1 AND table_name IN ('user', 'session', 'account', 'document')`, databaseSchema).Scan(&customTables); err != nil {
		t.Fatal(err)
	}
	if customTables != 4 {
		t.Fatalf("qualified schema tables = %d, want 4", customTables)
	}
	var leakedPublicTables int
	if err := database.QueryRowContext(t.Context(), `
		SELECT COUNT(*)
		FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN ('user', 'session', 'account', 'document')`).Scan(&leakedPublicTables); err != nil {
		t.Fatal(err)
	}
	if leakedPublicTables != 0 {
		t.Fatalf("adapter leaked %d tables into public instead of %q", leakedPublicTables, databaseSchema)
	}
}

func assertPostgresJSONDocument(t *testing.T, document storage.Record, payload map[string]any, labels []string, scores []float64) {
	t.Helper()
	if !reflect.DeepEqual(document["payload"], payload) ||
		!reflect.DeepEqual(document["labels"], labels) ||
		!reflect.DeepEqual(document["scores"], scores) {
		t.Fatalf("JSONB document = %#v", document)
	}
}
