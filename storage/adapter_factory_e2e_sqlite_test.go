package storage_test

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"

	_ "modernc.org/sqlite"
)

// TestAdapterFactorySQLiteIntegration complements the exact
// adapter-factory call-shape vectors with real SQL persistence. The wrapper is
// deliberately thin: AdapterFactory owns reference implementation normalization, while the
// SQLite adapter owns durable encoding, querying, and decoding.
func TestAdapterFactorySQLiteIntegration(t *testing.T) {
	schema := storage.CoreSchema()
	user := schema.Models["user"]
	optional := storage.Bool(false)
	user.Fields["profile"] = storage.FieldAttribute{Type: storage.FieldJSON, Required: optional}
	user.Fields["tags"] = storage.FieldAttribute{Type: storage.FieldStringArray, Required: optional}
	user.Fields["scores"] = storage.FieldAttribute{Type: storage.FieldNumberArray, Required: optional}
	user.Fields["active"] = storage.FieldAttribute{Type: storage.FieldBoolean, DefaultValue: storage.StaticValue(true)}
	user.Fields["lastSeen"] = storage.FieldAttribute{Type: storage.FieldDate, Required: optional}
	schema.Models["user"] = user

	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Errorf("close SQLite: %v", err)
		}
	})

	fixed := time.Date(2026, time.August, 9, 12, 34, 56, 789_000_000, time.UTC)
	sqlite, err := sqliteadapter.New(database, sqliteadapter.Options{
		Schema: schema,
		Clock:  func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlite.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	driver := storage.CustomAdapter{
		Create: func(ctx context.Context, params storage.CreateParams) (storage.Record, error) {
			// A reference implementation low-level adapter must persist the ID already approved
			// by AdapterFactory; SQLite's public safety flag expresses that fact.
			params.ForceAllowID = true
			return sqlite.Create(ctx, params)
		},
		FindOne:    sqlite.FindOne,
		FindMany:   sqlite.FindMany,
		Count:      sqlite.Count,
		Update:     sqlite.Update,
		UpdateMany: sqlite.UpdateMany,
		Delete:     sqlite.Delete,
		DeleteMany: func(ctx context.Context, params storage.DeleteManyParams) (any, error) {
			return sqlite.DeleteMany(ctx, params)
		},
		ConsumeOne:   sqlite.ConsumeOne,
		IncrementOne: sqlite.IncrementOne,
	}
	capabilities := storage.NativeCapabilities()
	capabilities.Joins = false
	var userIDs atomic.Uint64
	var sessionIDs atomic.Uint64
	adapter, err := storage.NewAdapterFactory(storage.AdapterFactoryConfig{
		AdapterID:    "adapter-factory-sqlite",
		AdapterName:  "Adapter Factory SQLite Integration",
		Schema:       schema,
		Capabilities: &capabilities,
		Clock:        func() time.Time { return fixed },
		GenerateID: func(model string) (any, error) {
			switch model {
			case "user":
				return fmt.Sprintf("sqlite-user-%d", userIDs.Add(1)), nil
			case "session":
				return fmt.Sprintf("sqlite-session-%d", sessionIDs.Add(1)), nil
			default:
				return "sqlite-" + model + "-1", nil
			}
		},
	}, driver)
	if err != nil {
		t.Fatal(err)
	}

	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user",
		Data: storage.Record{
			"name": "Ada", "email": "ada@example.com",
			"profile":  map[string]any{"role": "admin", "level": float64(7)},
			"tags":     []string{"go", "auth"},
			"scores":   []float64{1.5, 2.5},
			"lastSeen": fixed.Add(-time.Hour),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	createdAt, createdAtOK := created["createdAt"].(time.Time)
	updatedAt, updatedAtOK := created["updatedAt"].(time.Time)
	if created["id"] != "sqlite-user-1" || created["active"] != true || created["emailVerified"] != false ||
		!createdAtOK || !updatedAtOK || !createdAt.Equal(fixed) || !updatedAt.Equal(fixed) ||
		!reflect.DeepEqual(created["profile"], map[string]any{"role": "admin", "level": float64(7)}) ||
		!reflect.DeepEqual(created["tags"], []string{"go", "auth"}) ||
		!reflect.DeepEqual(created["scores"], []float64{1.5, 2.5}) {
		t.Fatalf("SQLite create round-trip=%#v", created)
	}

	selected, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user",
		Where: []storage.Where{
			{Field: "email", Value: "ada@example.com"},
			{Field: "active", Value: true},
		},
		Select: []string{"id", "email", "profile"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(selected, storage.Record{
		"id": "sqlite-user-1", "email": "ada@example.com",
		"profile": map[string]any{"role": "admin", "level": float64(7)},
	}) {
		t.Fatalf("SQLite select/where round-trip=%#v", selected)
	}

	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model:  "user",
		Where:  []storage.Where{{Field: "id", Value: "sqlite-user-1"}},
		Update: storage.Record{"name": "Ada Lovelace", "tags": []string{"go", "auth", "sqlite"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated["id"] != "sqlite-user-1" || updated["name"] != "Ada Lovelace" ||
		!reflect.DeepEqual(updated["tags"], []string{"go", "auth", "sqlite"}) {
		t.Fatalf("SQLite update round-trip=%#v", updated)
	}

	session, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "session",
		Data: storage.Record{
			"userId": "sqlite-user-1", "token": "sqlite-token",
			"expiresAt": fixed.Add(time.Hour),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if session["id"] != "sqlite-session-1" || session["userId"] != "sqlite-user-1" {
		t.Fatalf("SQLite session round-trip=%#v", session)
	}

	joined, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "user",
		Where: []storage.Where{{Field: "id", Value: "sqlite-user-1"}},
		Join:  map[string]storage.JoinOption{"session": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(joined) != 1 {
		t.Fatalf("SQLite fallback join rows=%#v", joined)
	}
	sessions, ok := joined[0]["session"].([]storage.Record)
	if !ok || len(sessions) != 1 || sessions[0]["id"] != "sqlite-session-1" {
		t.Fatalf("SQLite fallback join=%#v", joined[0])
	}
}
