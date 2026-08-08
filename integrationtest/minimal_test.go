package singleauth_test

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	_ "modernc.org/sqlite"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

var _ http.Handler = (*singleauth.MinimalAuth)(nil)

func TestMinimalInitializesWithNativeAdapter(t *testing.T) {
	adapter := memory.MustNew()
	auth, err := singleauth.NewMinimal(singleauth.Options{
		BaseURL:  "http://localhost:3000",
		Database: adapter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Handler() == nil {
		t.Fatal("minimal handler is nil")
	}
	if reflect.ValueOf(auth.API()).IsZero() {
		t.Fatal("minimal direct API is zero")
	}

	context, err := auth.Context()
	if err != nil {
		t.Fatal(err)
	}
	if context.Adapter.ID() != "memory" {
		t.Fatalf("minimal adapter = %#v", context.Adapter)
	}
	if context.DatabaseType != "unknown" {
		t.Fatalf("database type = %q, want unknown", context.DatabaseType)
	}
}

func TestMinimalDefaultRuntimeIsUsable(t *testing.T) {
	auth, err := singleauth.NewMinimal(singleauth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if auth == nil || auth.Handler() == nil {
		t.Fatal("default minimal runtime is not initialized")
	}
	if _, err := auth.Context(); err != nil {
		t.Fatal(err)
	}
}

func TestMinimalRejectsMigrations(t *testing.T) {
	auth, err := singleauth.NewMinimal(singleauth.Options{
		BaseURL:  "http://localhost:3000",
		Database: memory.MustNew(),
	})
	if err != nil {
		t.Fatal(err)
	}
	context, err := auth.Context()
	if err != nil {
		t.Fatal(err)
	}

	for name, err := range map[string]error{
		"auth":    auth.RunMigrations(),
		"context": context.RunMigrations(),
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(err, singleauth.ErrMinimalMigrationsUnsupported) {
				t.Fatalf("migration error = %v", err)
			}
			var configurationError *singleauth.UpstreamError
			if !errors.As(err, &configurationError) {
				t.Fatalf("migration error type = %T", err)
			}
		})
	}
}

func TestMinimalHandlesRequestsThroughAdapter(t *testing.T) {
	auth, err := singleauth.NewMinimal(singleauth.Options{
		BaseURL:  "http://localhost:3000",
		Database: memory.MustNew(),
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://localhost:3000/api/auth/ok", nil)
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(body, map[string]any{"ok": true}) {
		t.Fatalf("body = %#v", body)
	}
}

func TestMinimalRejectsDirectSQLDatabase(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	_, err = singleauth.NewMinimalWithDatabase(singleauth.Options{
		BaseURL: "http://localhost:3000",
	}, database)
	if !errors.Is(err, singleauth.ErrMinimalDirectDatabaseUnsupported) {
		t.Fatalf("direct database error = %v", err)
	}
	if err.Error() != "direct database connections are unsupported; provide a storage.Adapter" {
		t.Fatalf("direct database error message = %q", err)
	}
}
