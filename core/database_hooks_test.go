package core

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDatabaseHooksPluginThenUserOrderAndEndpointContext(t *testing.T) {
	var lock sync.Mutex
	events := make([]string, 0, 4)
	appendEvent := func(event string) {
		lock.Lock()
		events = append(events, event)
		lock.Unlock()
	}
	pluginFactory := &testPluginFactory{id: "database-hook-plugin"}
	pluginFactory.build = func(host PluginHost) (engine.Plugin, error) {
		err := host.RegisterDatabaseHooks(DatabaseHooks{
			"user": {Create: DatabaseOperationHooks{
				Before: func(data storage.Record, ctx DatabaseHookContext) (DatabaseHookResult, error) {
					appendEvent("plugin-before")
					if ctx.Source != "plugin:database-hook-plugin" || ctx.Endpoint == nil || ctx.Endpoint.RoutePath() != "/sign-up/email" {
						t.Fatalf("plugin hook context = %#v", ctx)
					}
					if data["image"] != nil {
						t.Fatalf("unexpected initial plugin image = %#v", data["image"])
					}
					return DatabaseHookResult{Data: storage.Record{"image": "plugin-image"}}, nil
				},
				After: func(value any, ctx DatabaseHookContext) error {
					appendEvent("plugin-after")
					created, ok := value.(storage.Record)
					if !ok || created["image"] != "plugin-image" || created["name"] != "user-name" || ctx.Endpoint == nil {
						t.Fatalf("plugin after value=%#v context=%#v", value, ctx)
					}
					return nil
				},
			}},
		})
		return engine.Plugin{ID: "database-hook-plugin"}, err
	}

	auth := MustNew(Options{
		BaseURL:          "http://auth.test",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		PluginFactories:  []PluginFactory{pluginFactory},
		DatabaseHooks: DatabaseHooks{
			"user": {Create: DatabaseOperationHooks{
				Before: func(data storage.Record, ctx DatabaseHookContext) (DatabaseHookResult, error) {
					appendEvent("user-before")
					if ctx.Source != "user" || data["image"] != "plugin-image" {
						t.Fatalf("user before data=%#v context=%#v", data, ctx)
					}
					return DatabaseHookResult{Data: storage.Record{"name": "user-name"}}, nil
				},
				After: func(value any, _ DatabaseHookContext) error {
					appendEvent("user-after")
					return nil
				},
			}},
		},
	})
	request := httptest.NewRequest(
		http.MethodPost,
		"http://auth.test/api/auth/sign-up/email",
		bytes.NewBufferString(`{"name":"input-name","email":"hooks@example.com","password":"password123"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	lock.Lock()
	gotEvents := append([]string(nil), events...)
	lock.Unlock()
	wantEvents := []string{"plugin-before", "user-before", "plugin-after", "user-after"}
	if len(gotEvents) != len(wantEvents) {
		t.Fatalf("hook events = %#v", gotEvents)
	}
	for index := range wantEvents {
		if gotEvents[index] != wantEvents[index] {
			t.Fatalf("hook events = %#v, want %#v", gotEvents, wantEvents)
		}
	}
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "hooks@example.com"}},
	})
	if err != nil || user == nil || user["name"] != "user-name" || user["image"] != "plugin-image" {
		t.Fatalf("created user = %#v, %v", user, err)
	}
}

func TestDatabaseHooksCancelAndUpdatePatchSemantics(t *testing.T) {
	var afterCreate atomic.Int64
	cancelled := MustNew(Options{DatabaseHooks: DatabaseHooks{
		"user": {Create: DatabaseOperationHooks{
			Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
				return DatabaseHookResult{Cancel: true}, nil
			},
			After: func(any, DatabaseHookContext) error {
				afterCreate.Add(1)
				return nil
			},
		}},
	}})
	created, err := cancelled.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "user", Data: storage.Record{"name": "cancel", "email": "cancel@example.com"},
	})
	if err != nil || created != nil || afterCreate.Load() != 0 {
		t.Fatalf("cancelled create = %#v, err=%v, after=%d", created, err, afterCreate.Load())
	}
	count, err := cancelled.Adapter().Count(t.Context(), storage.CountParams{Model: "user"})
	if err != nil || count != 0 {
		t.Fatalf("cancelled user count = %d, %v", count, err)
	}

	plugin := &testPluginFactory{id: "update-patcher"}
	plugin.build = func(host PluginHost) (engine.Plugin, error) {
		return engine.Plugin{ID: "update-patcher"}, host.RegisterDatabaseHooks(DatabaseHooks{
			"user": {Update: DatabaseOperationHooks{Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
				return DatabaseHookResult{Data: storage.Record{"image": "plugin-image"}}, nil
			}}},
		})
	}
	var userSawPluginPatch atomic.Bool
	auth := MustNew(Options{
		PluginFactories: []PluginFactory{plugin},
		DatabaseHooks: DatabaseHooks{
			"user": {Update: DatabaseOperationHooks{Before: func(data storage.Record, _ DatabaseHookContext) (DatabaseHookResult, error) {
				if _, exists := data["image"]; exists {
					userSawPluginPatch.Store(true)
				}
				return DatabaseHookResult{Data: storage.Record{"name": "user-name"}}, nil
			}}},
		},
	})
	now := time.Now().UTC()
	seeded, err := auth.Adapter().Create(t.Context(), storage.CreateParams{Model: "user", Data: storage.Record{
		"name": "seed", "email": "update-hooks@example.com", "emailVerified": false,
		"createdAt": now, "updatedAt": now,
	}})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: seeded["id"]}},
		Update: storage.Record{"name": "input-name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if userSawPluginPatch.Load() {
		t.Fatal("user update hook observed the prior plugin patch; upstream passes the original update to each hook")
	}
	if updated["name"] != "user-name" || updated["image"] != "plugin-image" {
		t.Fatalf("updated user = %#v", updated)
	}
}

func TestDatabaseAfterHooksCommitRollbackAndAtomicConsume(t *testing.T) {
	var afterCreate atomic.Int64
	var afterDelete atomic.Int64
	auth := MustNew(Options{DatabaseHooks: DatabaseHooks{
		"verification": {
			Create: DatabaseOperationHooks{After: func(any, DatabaseHookContext) error {
				afterCreate.Add(1)
				return nil
			}},
			Delete: DatabaseOperationHooks{After: func(any, DatabaseHookContext) error {
				afterDelete.Add(1)
				return nil
			}},
		},
	}})
	now := time.Now().UTC()
	createVerification := func(tx storage.TransactionAdapter, identifier string) error {
		_, err := tx.Create(t.Context(), storage.CreateParams{Model: "verification", Data: storage.Record{
			"identifier": identifier, "value": "value", "expiresAt": now.Add(time.Hour),
			"createdAt": now, "updatedAt": now,
		}})
		return err
	}
	if err := auth.Adapter().Transaction(t.Context(), func(tx storage.TransactionAdapter) error {
		if err := createVerification(tx, "committed"); err != nil {
			return err
		}
		if afterCreate.Load() != 0 {
			t.Fatal("after hook ran before transaction commit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if afterCreate.Load() != 1 {
		t.Fatalf("committed after hooks = %d", afterCreate.Load())
	}

	rollback := errors.New("rollback")
	err := auth.Adapter().Transaction(t.Context(), func(tx storage.TransactionAdapter) error {
		if err := createVerification(tx, "rolled-back"); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) || afterCreate.Load() != 1 {
		t.Fatalf("rollback err=%v after=%d", err, afterCreate.Load())
	}
	rolledBack, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "rolled-back"}},
	})
	if err != nil || rolledBack != nil {
		t.Fatalf("rolled-back row = %#v, %v", rolledBack, err)
	}

	var winners atomic.Int64
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			consumed, consumeErr := auth.Adapter().ConsumeOne(t.Context(), storage.ConsumeOneParams{
				Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "committed"}},
			})
			if consumeErr != nil {
				t.Errorf("consume: %v", consumeErr)
				return
			}
			if consumed != nil {
				winners.Add(1)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 || afterDelete.Load() != 1 {
		t.Fatalf("consume winners=%d delete after hooks=%d", winners.Load(), afterDelete.Load())
	}
}

func TestDatabaseHooksOptionsSnapshotIsIndependent(t *testing.T) {
	hooks := DatabaseHooks{"user": {}}
	auth := MustNew(Options{DatabaseHooks: hooks})
	delete(hooks, "user")
	options := auth.Options()
	if _, exists := options.DatabaseHooks["user"]; !exists {
		t.Fatal("caller mutation changed database hooks snapshot")
	}
	delete(options.DatabaseHooks, "user")
	if _, exists := auth.Options().DatabaseHooks["user"]; !exists {
		t.Fatal("returned options mutation changed runtime database hooks")
	}
}

func TestDatabaseHooksMatchSecondaryOnlyVerificationLifecycle(t *testing.T) {
	secondary := &atomicSecondaryMemory{secondaryMemory: newSecondaryMemory()}
	var createBefore atomic.Int64
	var createAfter atomic.Int64
	var deleteBefore atomic.Int64
	var deleteAfter atomic.Int64
	auth := MustNew(Options{
		SecondaryStorage: secondary,
		DatabaseHooks: DatabaseHooks{"verification": {
			Create: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					createBefore.Add(1)
					return DatabaseHookResult{Data: storage.Record{"value": "hooked"}}, nil
				},
				After: func(value any, _ DatabaseHookContext) error {
					createAfter.Add(1)
					if record, ok := value.(storage.Record); !ok || record["value"] != "hooked" {
						t.Fatalf("secondary create after value = %#v", value)
					}
					return nil
				},
			},
			Delete: DatabaseOperationHooks{
				Before: func(record storage.Record, _ DatabaseHookContext) (DatabaseHookResult, error) {
					deleteBefore.Add(1)
					if record["value"] != "hooked" {
						t.Fatalf("secondary delete before record = %#v", record)
					}
					return DatabaseHookResult{}, nil
				},
				After: func(any, DatabaseHookContext) error {
					deleteAfter.Add(1)
					return nil
				},
			},
		}},
	})
	created, err := auth.createStoredVerification(t.Context(), "secondary-hook", "input", time.Now().Add(time.Hour))
	if err != nil || created["value"] != "hooked" || createBefore.Load() != 1 || createAfter.Load() != 1 {
		t.Fatalf("created=%#v err=%v before=%d after=%d", created, err, createBefore.Load(), createAfter.Load())
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("secondary-only database rows = %#v, %v", rows, err)
	}
	consumed, err := auth.consumeStoredVerification(t.Context(), "secondary-hook")
	if err != nil || consumed == nil || deleteBefore.Load() != 0 || deleteAfter.Load() != 0 {
		t.Fatalf("consumed=%#v err=%v before=%d after=%d", consumed, err, deleteBefore.Load(), deleteAfter.Load())
	}
}

func TestDatabaseHooksMatchSecondarySessionLifecycle(t *testing.T) {
	secondary := newSecondaryMemory()
	var createBefore atomic.Int64
	var createAfter atomic.Int64
	var updateBefore atomic.Int64
	var updateAfter atomic.Int64
	var deleteBefore atomic.Int64
	var deleteAfter atomic.Int64
	auth := MustNew(Options{
		SecondaryStorage: secondary,
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		DatabaseHooks: DatabaseHooks{"session": {
			Create: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					createBefore.Add(1)
					return DatabaseHookResult{Data: storage.Record{"userAgent": "create-hook"}}, nil
				},
				After: func(value any, _ DatabaseHookContext) error {
					createAfter.Add(1)
					if record, ok := value.(storage.Record); !ok || record["userAgent"] != "create-hook" {
						t.Fatalf("session create after value = %#v", value)
					}
					return nil
				},
			},
			Update: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					updateBefore.Add(1)
					return DatabaseHookResult{Data: storage.Record{"userAgent": "update-hook"}}, nil
				},
				After: func(value any, _ DatabaseHookContext) error {
					updateAfter.Add(1)
					if record, ok := value.(storage.Record); !ok || record["userAgent"] != "update-hook" {
						t.Fatalf("session update after value = %#v", value)
					}
					return nil
				},
			},
			Delete: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					deleteBefore.Add(1)
					return DatabaseHookResult{}, nil
				},
				After: func(any, DatabaseHookContext) error {
					deleteAfter.Add(1)
					return nil
				},
			},
		}},
	})
	_, token, _ := createSessionTestUser(t, auth, "secondary-session-hooks@example.com")
	if createBefore.Load() != 1 || createAfter.Load() != 1 {
		t.Fatalf("session create hooks before=%d after=%d", createBefore.Load(), createAfter.Load())
	}
	stored, err := auth.loadSecondarySession(t.Context(), token)
	if err != nil || stored == nil || stored.Session["userAgent"] != "create-hook" {
		t.Fatalf("secondary created session=%#v err=%v", stored, err)
	}
	updated, err := auth.updateStoredSession(t.Context(), token, storage.Record{"userAgent": "update-input"})
	if err != nil || updated == nil || updated["userAgent"] != "update-hook" || updateBefore.Load() != 1 || updateAfter.Load() != 1 {
		t.Fatalf("updated=%#v err=%v before=%d after=%d", updated, err, updateBefore.Load(), updateAfter.Load())
	}
	if err := auth.deleteStoredSession(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if deleteBefore.Load() != 0 || deleteAfter.Load() != 0 {
		t.Fatalf("secondary-only session delete hooks before=%d after=%d", deleteBefore.Load(), deleteAfter.Load())
	}
}

func TestDatabaseHooksMatchDualVerificationOrdering(t *testing.T) {
	secondary := newSecondaryMemory()
	var updateAfter atomic.Int64
	var deleteBefore atomic.Int64
	auth := MustNew(Options{
		SecondaryStorage: secondary,
		Verification:     VerificationOptions{StoreInDatabase: true},
		DatabaseHooks: DatabaseHooks{"verification": {
			Update: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					return DatabaseHookResult{Data: storage.Record{"value": "database-hook"}}, nil
				},
				After: func(value any, _ DatabaseHookContext) error {
					updateAfter.Add(1)
					if record, ok := value.(storage.Record); !ok || record["value"] != "database-hook" {
						t.Fatalf("verification update after value = %#v", value)
					}
					return nil
				},
			},
			Delete: DatabaseOperationHooks{Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
				deleteBefore.Add(1)
				return DatabaseHookResult{Cancel: true}, nil
			}},
		}},
	})
	if _, err := auth.createStoredVerification(t.Context(), "dual-hook", "initial", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := auth.updateStoredVerification(t.Context(), "dual-hook", storage.Record{"value": "secondary-input"}); err != nil {
		t.Fatal(err)
	}
	cached, err := auth.loadSecondaryVerification(t.Context(), "dual-hook")
	if err != nil || cached["value"] != "secondary-input" {
		t.Fatalf("secondary verification=%#v err=%v", cached, err)
	}
	database, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "dual-hook"}},
	})
	if err != nil || database["value"] != "database-hook" || updateAfter.Load() != 1 {
		t.Fatalf("database verification=%#v err=%v after=%d", database, err, updateAfter.Load())
	}
	if err := auth.deleteStoredVerification(t.Context(), "dual-hook"); err != nil {
		t.Fatal(err)
	}
	if secondary.value(verificationPrefix+"dual-hook") != "" || deleteBefore.Load() != 1 {
		t.Fatalf("delete secondary=%q before=%d", secondary.value(verificationPrefix+"dual-hook"), deleteBefore.Load())
	}
	database, err = auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "dual-hook"}},
	})
	if err != nil || database == nil {
		t.Fatalf("cancelled database delete row=%#v err=%v", database, err)
	}
}
