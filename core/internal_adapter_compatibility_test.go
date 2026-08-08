package core

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/engine"
	authlogger "github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

var internalAdapterEpoch = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

func durationMilliseconds(value int64) time.Duration {
	return time.Duration(value) * time.Millisecond
}

type countingDeleteAdapter struct {
	storage.Adapter
	deleteCalls atomic.Int64
}

func (adapter *countingDeleteAdapter) Delete(ctx context.Context, params storage.DeleteParams) error {
	adapter.deleteCalls.Add(1)
	return adapter.Adapter.Delete(ctx, params)
}

type delayedSecondaryMemory struct {
	*secondaryMemory
}

func (memory *delayedSecondaryMemory) Get(ctx context.Context, key string) (string, error) {
	time.Sleep(time.Millisecond)
	return memory.secondaryMemory.Get(ctx, key)
}

func TestInternalAdapterOAuthUserHooksAccountsAndAliasesBehavior(t *testing.T) {
	t.Run("oauth user uses generated ids and plugin plus user hooks", func(t *testing.T) {
		var generated atomic.Int64
		var pluginBefore, pluginAfter, userBefore, userAfter atomic.Int64
		var auth *Auth
		factory := &testPluginFactory{id: "internal-adapter-hooks"}
		factory.build = func(host PluginHost) (engine.Plugin, error) {
			err := host.RegisterDatabaseHooks(DatabaseHooks{
				"user": {Create: DatabaseOperationHooks{
					Before: func(data storage.Record, _ DatabaseHookContext) (DatabaseHookResult, error) {
						pluginBefore.Add(1)
						return DatabaseHookResult{Data: storage.Record{"name": data["name"]}}, nil
					},
					After: func(any, DatabaseHookContext) error {
						pluginAfter.Add(1)
						return nil
					},
				}},
			})
			return engine.Plugin{ID: "internal-adapter-hooks"}, err
		}
		auth = MustNew(Options{
			Clock:           func() time.Time { return internalAdapterEpoch },
			PluginFactories: []PluginFactory{factory},
			GenerateID: func(string, int) (string, bool, error) {
				return strings.TrimSpace(string(rune('0' + generated.Add(1)))), true, nil
			},
			DatabaseHooks: DatabaseHooks{
				"user": {Create: DatabaseOperationHooks{
					Before: func(data storage.Record, _ DatabaseHookContext) (DatabaseHookResult, error) {
						userBefore.Add(1)
						return DatabaseHookResult{Data: storage.Record{"emailVerified": false}}, nil
					},
					After: func(value any, _ DatabaseHookContext) error {
						userAfter.Add(1)
						created := value.(storage.Record)
						persisted, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
							Model: "user", Where: []storage.Where{{Field: "id", Value: created["id"]}},
						})
						if err != nil || persisted == nil || persisted["email"] != created["email"] {
							t.Fatalf("user after hook ran before persistence: value=%#v persisted=%#v err=%v", created, persisted, err)
						}
						return nil
					},
				}},
			},
		})

		result, err := auth.InternalAdapter().CreateOAuthUser(t.Context(), storage.Record{
			"name": "name", "email": "EMAIL@email.com", "emailVerified": false,
		}, storage.Record{
			"providerId": "provider", "accountId": "account",
			"accessTokenExpiresAt":  internalAdapterEpoch.Add(time.Hour),
			"refreshTokenExpiresAt": internalAdapterEpoch.Add(2 * time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.User["id"] != "1" || result.Account["id"] != "2" ||
			result.Account["userId"] != result.User["id"] || result.User["email"] != "email@email.com" ||
			result.User["image"] != nil || result.Account["accessToken"] != nil || result.Account["refreshToken"] != nil {
			t.Fatalf("oauth pair=%#v", result)
		}
		if pluginBefore.Load() != 1 || pluginAfter.Load() != 1 || userBefore.Load() != 1 || userAfter.Load() != 1 {
			t.Fatalf("hook counts plugin=%d/%d user=%d/%d", pluginBefore.Load(), pluginAfter.Load(), userBefore.Load(), userAfter.Load())
		}
	})

	t.Run("single and multiple account deletion", func(t *testing.T) {
		auth := MustNew(Options{Clock: func() time.Time { return internalAdapterEpoch }})
		adapter := auth.InternalAdapter()
		user, err := adapter.CreateUser(t.Context(), storage.Record{
			"name": "Accounts", "email": "accounts-delete@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		userID, _ := recordString(user, "id")
		first, err := adapter.CreateAccount(t.Context(), storage.Record{
			"userId": userID, "providerId": "provider-1", "accountId": "account-1",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.CreateAccount(t.Context(), storage.Record{
			"userId": userID, "providerId": "provider-2", "accountId": "account-2",
		}); err != nil {
			t.Fatal(err)
		}
		found, err := adapter.FindAccountByProviderID(t.Context(), "account-1", "provider-1")
		if err != nil || found == nil {
			t.Fatalf("find first account=%#v err=%v", found, err)
		}
		firstID, _ := recordString(first, "id")
		if err := adapter.DeleteAccount(t.Context(), firstID); err != nil {
			t.Fatal(err)
		}
		found, err = adapter.FindAccountByProviderID(t.Context(), "account-1", "provider-1")
		if err != nil || found != nil {
			t.Fatalf("deleted account=%#v err=%v", found, err)
		}
		accounts, err := adapter.FindAccounts(t.Context(), userID)
		if err != nil || len(accounts) != 1 {
			t.Fatalf("accounts after single delete=%#v err=%v", accounts, err)
		}
		if err := adapter.DeleteAccounts(t.Context(), userID); err != nil {
			t.Fatal(err)
		}
		accounts, err = adapter.FindAccounts(t.Context(), userID)
		if err != nil || len(accounts) != 0 {
			t.Fatalf("accounts after deleteMany=%#v err=%v", accounts, err)
		}
	})

	t.Run("session userId physical alias", func(t *testing.T) {
		schema := storage.CoreSchema()
		session := schema.Models["session"]
		userIDField := session.Fields["userId"]
		userIDField.FieldName = "user_id"
		session.Fields["userId"] = userIDField
		schema.Models["session"] = session
		auth := MustNew(Options{Schema: schema, Clock: func() time.Time { return internalAdapterEpoch }})
		adapter := auth.InternalAdapter()
		user, err := adapter.CreateUser(t.Context(), storage.Record{
			"name": "Alias", "email": "session-alias@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		userID, _ := recordString(user, "id")
		created, err := adapter.CreateSession(t.Context(), userID, InternalSessionCreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		token, _ := recordString(created, "token")
		found, err := adapter.FindSession(t.Context(), token)
		if err != nil || found == nil || found.Session["userId"] != userID || found.User["id"] != userID {
			t.Fatalf("aliased session=%#v err=%v", found, err)
		}
	})
}

func TestInternalAdapterVerificationLifecycleHooksBehavior(t *testing.T) {
	var deleteBefore, deleteAfter atomic.Int64
	auth := MustNew(Options{
		Clock: func() time.Time { return internalAdapterEpoch },
		DatabaseHooks: DatabaseHooks{"verification": {Delete: DatabaseOperationHooks{
			Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
				deleteBefore.Add(1)
				return DatabaseHookResult{}, nil
			},
			After: func(any, DatabaseHookContext) error {
				deleteAfter.Add(1)
				return nil
			},
		}}},
	})
	adapter := auth.InternalAdapter()

	expired, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "expired-find", Value: "expired", ExpiresAt: internalAdapterEpoch.Add(-time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := adapter.FindVerificationValue(t.Context(), "expired-find")
	if err != nil || first == nil || first["id"] != expired["id"] || deleteBefore.Load() != 1 || deleteAfter.Load() != 1 {
		t.Fatalf("expired first read=%#v err=%v hooks=%d/%d", first, err, deleteBefore.Load(), deleteAfter.Load())
	}
	second, err := adapter.FindVerificationValue(t.Context(), "expired-find")
	if err != nil || second != nil {
		t.Fatalf("expired second read=%#v err=%v", second, err)
	}

	deleteBefore.Store(0)
	deleteAfter.Store(0)
	for _, identifier := range []string{"delete-by-value", "delete-by-identifier"} {
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: identifier, Value: identifier, ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		if err := adapter.DeleteVerificationByIdentifier(t.Context(), identifier); err != nil {
			t.Fatal(err)
		}
	}
	if deleteBefore.Load() != 2 || deleteAfter.Load() != 2 {
		t.Fatalf("explicit delete hooks=%d/%d", deleteBefore.Load(), deleteAfter.Load())
	}

	base := memory.MustNew(memory.WithClock(func() time.Time { return internalAdapterEpoch }))
	spy := &countingDeleteAdapter{Adapter: base}
	missingAuth := MustNew(Options{
		Database: spy, Clock: func() time.Time { return internalAdapterEpoch },
	})
	missing := missingAuth.InternalAdapter()
	created, err := missing.CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "missing-entity-test", Value: "value", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base.DeleteMany(t.Context(), storage.DeleteManyParams{
		Model: "verification", Where: []storage.Where{{Field: "id", Value: created["id"]}},
	}); err != nil {
		t.Fatal(err)
	}
	spy.deleteCalls.Store(0)
	if err := missing.DeleteVerificationByIdentifier(t.Context(), "missing-entity-test"); err != nil {
		t.Fatal(err)
	}
	if spy.deleteCalls.Load() != 0 {
		t.Fatalf("missing verification called adapter.Delete %d times", spy.deleteCalls.Load())
	}
}

func TestInternalAdapterVerificationIdentifierBehavior(t *testing.T) {
	oracle := loadInternalAdapterFixture(t)
	hashed := MustNew(Options{
		Clock: func() time.Time { return internalAdapterEpoch },
		Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
			Strategy: VerificationIdentifierHashed,
		}},
	})
	created, err := hashed.InternalAdapter().CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: oracle.Fixtures.HashedIdentifier.Input,
		Value:      "user-id-123",
		ExpiresAt:  internalAdapterEpoch.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if created["identifier"] != oracle.Fixtures.HashedIdentifier.Stored || created["identifier"] == oracle.Fixtures.HashedIdentifier.Input {
		t.Fatalf("hashed identifier=%#v oracle=%#v", created["identifier"], oracle.Fixtures.HashedIdentifier)
	}
	found, err := hashed.InternalAdapter().FindVerificationValue(t.Context(), oracle.Fixtures.HashedIdentifier.Input)
	if err != nil || found == nil || found["value"] != "user-id-123" {
		t.Fatalf("find hashed=%#v err=%v", found, err)
	}
	if err := hashed.InternalAdapter().DeleteVerificationByIdentifier(t.Context(), oracle.Fixtures.HashedIdentifier.Input); err != nil {
		t.Fatal(err)
	}
	found, err = hashed.InternalAdapter().FindVerificationValue(t.Context(), oracle.Fixtures.HashedIdentifier.Input)
	if err != nil || found != nil {
		t.Fatalf("deleted hashed=%#v err=%v", found, err)
	}

	overrides := MustNew(Options{
		Clock: func() time.Time { return internalAdapterEpoch },
		Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
			Strategy: VerificationIdentifierPlain,
			Overrides: []VerificationIdentifierOverride{{
				Prefix: "reset-password", Strategy: VerificationIdentifierHashed,
			}},
		}},
	})
	reset, err := overrides.InternalAdapter().CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "reset-password:token-abc", Value: "user-1", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	magic, err := overrides.InternalAdapter().CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "magic-link:token-xyz", Value: "user-2", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
	})
	if err != nil || reset["identifier"] == "reset-password:token-abc" || magic["identifier"] != "magic-link:token-xyz" {
		t.Fatalf("override reset=%#v magic=%#v err=%v", reset, magic, err)
	}

	shared := memory.MustNew(memory.WithClock(func() time.Time { return internalAdapterEpoch }))
	plain := MustNew(Options{Database: shared, Clock: func() time.Time { return internalAdapterEpoch }})
	if _, err := plain.InternalAdapter().CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "old-token:abc123", Value: "old-value", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	migrated := MustNew(Options{
		Database: shared, Clock: func() time.Time { return internalAdapterEpoch },
		Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{Strategy: VerificationIdentifierHashed}},
	})
	legacy, err := migrated.InternalAdapter().FindVerificationValue(t.Context(), "old-token:abc123")
	if err != nil || legacy == nil || legacy["value"] != "old-value" {
		t.Fatalf("legacy plain fallback=%#v err=%v", legacy, err)
	}
}

func TestInternalAdapterSecondaryVerificationBehavior(t *testing.T) {
	secondary := newSecondaryMemory()
	auth := MustNew(Options{
		SecondaryStorage: secondary,
		Clock:            func() time.Time { return internalAdapterEpoch },
		Logger:           authlogger.Options{Disabled: true},
	})
	adapter := auth.InternalAdapter()
	created, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "secondary-only", Value: "secondary-value", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	key := verificationPrefix + "secondary-only"
	if secondary.value(key) == "" || secondary.ttl(key) != 60 {
		t.Fatalf("secondary verification value=%q ttl=%d", secondary.value(key), secondary.ttl(key))
	}
	found, err := adapter.FindVerificationValue(t.Context(), "secondary-only")
	if err != nil || found == nil || found["id"] != created["id"] || found["value"] != "secondary-value" {
		t.Fatalf("secondary find=%#v err=%v", found, err)
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("secondary-only database rows=%#v err=%v", rows, err)
	}
	if err := adapter.DeleteVerificationByIdentifier(t.Context(), "secondary-only"); err != nil {
		t.Fatal(err)
	}
	if secondary.value(key) != "" {
		t.Fatalf("secondary delete left %q", secondary.value(key))
	}

	ttlStore := newSecondaryMemory()
	ttlAuth := MustNew(Options{
		SecondaryStorage: ttlStore, Clock: func() time.Time { return internalAdapterEpoch },
	})
	if _, err := ttlAuth.InternalAdapter().CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "ttl-test", Value: "ttl", ExpiresAt: internalAdapterEpoch.Add(5 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if ttlStore.ttl(verificationPrefix+"ttl-test") != 300 {
		t.Fatalf("verification ttl=%d", ttlStore.ttl(verificationPrefix+"ttl-test"))
	}

	dualStore := newSecondaryMemory()
	dual := MustNew(Options{
		SecondaryStorage: dualStore, Clock: func() time.Time { return internalAdapterEpoch },
		Verification: VerificationOptions{StoreInDatabase: true},
	})
	if _, err := dual.InternalAdapter().CreateVerificationValue(t.Context(), VerificationValue{
		Identifier: "dual-storage", Value: "dual-value", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	rows, err = dual.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "dual-storage"}},
	})
	if err != nil || len(rows) != 1 || dualStore.value(verificationPrefix+"dual-storage") == "" {
		t.Fatalf("dual rows=%#v cached=%q err=%v", rows, dualStore.value(verificationPrefix+"dual-storage"), err)
	}
	dualStore.forceDelete(verificationPrefix + "dual-storage")
	found, err = dual.InternalAdapter().FindVerificationValue(t.Context(), "dual-storage")
	if err != nil || found == nil || found["value"] != "dual-value" {
		t.Fatalf("database fallback=%#v err=%v", found, err)
	}
}

func TestInternalAdapterSecondarySessionLifecycleBehavior(t *testing.T) {
	t.Run("create stores id payload index hook fields and floored ttl", func(t *testing.T) {
		secondary := newSecondaryMemory()
		auth := MustNew(Options{
			SecondaryStorage: secondary,
			Clock:            func() time.Time { return internalAdapterEpoch },
			DatabaseHooks: DatabaseHooks{"session": {Create: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					return DatabaseHookResult{Data: storage.Record{"activeOrganizationId": "1"}}, nil
				},
			}}},
		})
		adapter := auth.InternalAdapter()
		user, err := adapter.CreateUser(t.Context(), storage.Record{
			"name": "Secondary", "email": "secondary-create@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		userID, _ := recordString(user, "id")
		session, err := adapter.CreateSession(t.Context(), userID, InternalSessionCreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		id, idOK := recordString(session, "id")
		token, tokenOK := recordString(session, "token")
		if !idOK || id == "" || !tokenOK || token == "" || session["activeOrganizationId"] != "1" {
			t.Fatalf("created secondary session=%#v", session)
		}
		var active []activeSessionEntry
		if err := json.Unmarshal([]byte(secondary.value(activeSessionsPrefix+userID)), &active); err != nil ||
			len(active) != 1 || active[0].Token != token {
			t.Fatalf("active sessions=%#v err=%v", active, err)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(secondary.value(token)), &payload); err != nil {
			t.Fatal(err)
		}
		storedSession, _ := payload["session"].(map[string]any)
		storedUser, _ := payload["user"].(map[string]any)
		wantTTL := int64((7 * 24 * time.Hour) / time.Second)
		if storedSession["activeOrganizationId"] != "1" || storedUser["id"] != userID ||
			secondary.ttl(token) != wantTTL || secondary.ttl(activeSessionsPrefix+userID) != wantTTL {
			t.Fatalf("payload=%#v ttl token/list=%d/%d", payload, secondary.ttl(token), secondary.ttl(activeSessionsPrefix+userID))
		}
		rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "session"})
		if err != nil || len(rows) != 0 {
			t.Fatalf("secondary-only database sessions=%#v err=%v", rows, err)
		}
	})

	t.Run("user refresh writes exact floor including zero", func(t *testing.T) {
		secondary := newSecondaryMemory()
		auth := MustNew(Options{
			SecondaryStorage: secondary,
			Clock:            func() time.Time { return internalAdapterEpoch },
		})
		adapter := auth.InternalAdapter()
		user, err := adapter.CreateUser(t.Context(), storage.Record{
			"name": "TTL", "email": "secondary-ttl@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		userID, _ := recordString(user, "id")
		for index, fixture := range loadInternalAdapterFixture(t).Fixtures.TTLSeconds {
			token := "ttl-token-" + string(rune('a'+index))
			expiresAt := internalAdapterEpoch.Add(durationMilliseconds(fixture.Milliseconds))
			listRaw, _ := json.Marshal([]activeSessionEntry{{Token: token, ExpiresAt: expiresAt.UnixMilli()}})
			payloadRaw, _ := json.Marshal(secondarySessionPayload{
				Session: storage.Record{
					"id": token + "-id", "userId": userID, "token": token,
					"expiresAt": expiresAt, "createdAt": internalAdapterEpoch, "updatedAt": internalAdapterEpoch,
				},
				User: user,
			})
			if err := secondary.Set(t.Context(), activeSessionsPrefix+userID, string(listRaw), 0); err != nil {
				t.Fatal(err)
			}
			if err := secondary.Set(t.Context(), token, string(payloadRaw), 999); err != nil {
				t.Fatal(err)
			}
			updated, err := adapter.UpdateUser(t.Context(), userID, storage.Record{"name": "Updated"})
			if err != nil || updated == nil {
				t.Fatalf("update user=%#v err=%v", updated, err)
			}
			if got := secondary.ttl(token); got != fixture.Seconds {
				t.Fatalf("refresh ttl for %dms=%d, want %d", fixture.Milliseconds, got, fixture.Seconds)
			}
		}
	})

	t.Run("delete prunes expired list entries and recomputes ttl", func(t *testing.T) {
		secondary := newSecondaryMemory()
		auth := MustNew(Options{
			SecondaryStorage: secondary,
			Clock:            func() time.Time { return internalAdapterEpoch },
		})
		adapter := auth.InternalAdapter()
		user, err := adapter.CreateUser(t.Context(), storage.Record{
			"name": "Delete", "email": "secondary-delete@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		userID, _ := recordString(user, "id")
		futureTokens := make([]string, 0, 4)
		for day := -5; day < 5; day++ {
			expiresAt := internalAdapterEpoch.Add(time.Duration(day) * 24 * time.Hour)
			session, err := adapter.CreateSession(t.Context(), userID, InternalSessionCreateOptions{
				Override: storage.Record{"expiresAt": expiresAt}, OverrideAll: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if day <= 0 {
				if secondary.value(activeSessionsPrefix+userID) != "" {
					t.Fatalf("expired day %d created active list", day)
				}
				continue
			}
			token, _ := recordString(session, "token")
			futureTokens = append(futureTokens, token)
			if got, want := secondary.ttl(activeSessionsPrefix+userID), int64(day*24*60*60); got != want {
				t.Fatalf("day %d list ttl=%d, want %d", day, got, want)
			}
		}
		var before []activeSessionEntry
		if err := json.Unmarshal([]byte(secondary.value(activeSessionsPrefix+userID)), &before); err != nil || len(before) != 4 {
			t.Fatalf("before delete=%#v err=%v", before, err)
		}
		removed := futureTokens[len(futureTokens)-1]
		if err := adapter.DeleteSession(t.Context(), removed); err != nil {
			t.Fatal(err)
		}
		var after []activeSessionEntry
		if err := json.Unmarshal([]byte(secondary.value(activeSessionsPrefix+userID)), &after); err != nil || len(after) != 3 {
			t.Fatalf("after delete=%#v err=%v", after, err)
		}
		if secondary.value(removed) != "" || secondary.ttl(activeSessionsPrefix+userID) != 3*24*60*60 {
			t.Fatalf("removed cache=%q list ttl=%d", secondary.value(removed), secondary.ttl(activeSessionsPrefix+userID))
		}
	})

	t.Run("update rewrites payload active index and ttl", func(t *testing.T) {
		secondary := newSecondaryMemory()
		auth := MustNew(Options{
			SecondaryStorage: secondary,
			Clock:            func() time.Time { return internalAdapterEpoch },
		})
		adapter := auth.InternalAdapter()
		user, err := adapter.CreateUser(t.Context(), storage.Record{
			"name": "Update", "email": "secondary-update@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		userID, _ := recordString(user, "id")
		created, err := adapter.CreateSession(t.Context(), userID, InternalSessionCreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		token, _ := recordString(created, "token")
		newExpiry := internalAdapterEpoch.Add(8 * 24 * time.Hour)
		updated, err := adapter.UpdateSession(t.Context(), token, storage.Record{
			"ipAddress": "192.168.1.1", "expiresAt": newExpiry,
		})
		if err != nil || updated == nil || updated["ipAddress"] != "192.168.1.1" {
			t.Fatalf("updated session=%#v err=%v", updated, err)
		}
		loaded, err := adapter.FindSession(t.Context(), token)
		if err != nil || loaded == nil || loaded.Session["ipAddress"] != "192.168.1.1" || loaded.User["id"] != userID {
			t.Fatalf("loaded updated session=%#v err=%v", loaded, err)
		}
		var active []activeSessionEntry
		if err := json.Unmarshal([]byte(secondary.value(activeSessionsPrefix+userID)), &active); err != nil ||
			len(active) != 1 || active[0].Token != token || active[0].ExpiresAt != newExpiry.UnixMilli() {
			t.Fatalf("updated active list=%#v err=%v", active, err)
		}
		if secondary.ttl(token) != 8*24*60*60 || secondary.ttl(activeSessionsPrefix+userID) != 8*24*60*60 {
			t.Fatalf("updated ttl token/list=%d/%d", secondary.ttl(token), secondary.ttl(activeSessionsPrefix+userID))
		}
	})
}

type secondarySessionBehaviorFixture struct {
	auth      *Auth
	adapter   InternalAdapter
	secondary *secondaryMemory
	userID    string
	sessions  []storage.Record
}

func newSecondarySessionBehaviorFixture(t *testing.T, suffix string, count int) secondarySessionBehaviorFixture {
	t.Helper()
	secondary := newSecondaryMemory()
	auth := MustNew(Options{
		SecondaryStorage: secondary,
		Clock:            func() time.Time { return internalAdapterEpoch },
	})
	adapter := auth.InternalAdapter()
	user, err := adapter.CreateUser(t.Context(), storage.Record{
		"name": "Corrupt", "email": "secondary-corrupt-" + suffix + "@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := recordString(user, "id")
	sessions := make([]storage.Record, 0, count)
	for range count {
		session, err := adapter.CreateSession(t.Context(), userID, InternalSessionCreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
	}
	return secondarySessionBehaviorFixture{
		auth: auth, adapter: adapter, secondary: secondary, userID: userID, sessions: sessions,
	}
}

func behaviorSessionToken(t *testing.T, record storage.Record) string {
	t.Helper()
	token, ok := recordString(record, "token")
	if !ok || token == "" {
		t.Fatalf("session token missing in %#v", record)
	}
	return token
}

func behaviorSortedSessionTokens(t *testing.T, records []storage.Record) []string {
	t.Helper()
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, behaviorSessionToken(t, record))
	}
	sort.Strings(result)
	return result
}

func TestInternalAdapterSecondarySessionCorruptionBehavior(t *testing.T) {
	assertTwoSurvivors := func(t *testing.T, fixture secondarySessionBehaviorFixture) {
		t.Helper()
		got, err := fixture.adapter.ListSessions(t.Context(), fixture.userID, false)
		if err != nil {
			t.Fatal(err)
		}
		want := []storage.Record{fixture.sessions[0], fixture.sessions[2]}
		if strings.Join(behaviorSortedSessionTokens(t, got), ",") != strings.Join(behaviorSortedSessionTokens(t, want), ",") {
			t.Fatalf("surviving sessions=%#v want=%#v", got, want)
		}
	}

	t.Run("list skips a missing session", func(t *testing.T) {
		fixture := newSecondarySessionBehaviorFixture(t, "missing", 3)
		fixture.secondary.forceDelete(behaviorSessionToken(t, fixture.sessions[1]))
		assertTwoSurvivors(t, fixture)
	})
	t.Run("list skips valid json with wrong structure", func(t *testing.T) {
		fixture := newSecondarySessionBehaviorFixture(t, "structure", 3)
		if err := fixture.secondary.Set(t.Context(), behaviorSessionToken(t, fixture.sessions[1]), `{"session":null,"user":null}`, 60); err != nil {
			t.Fatal(err)
		}
		assertTwoSurvivors(t, fixture)
	})
	t.Run("list skips corrupt json", func(t *testing.T) {
		fixture := newSecondarySessionBehaviorFixture(t, "json", 3)
		if err := fixture.secondary.Set(t.Context(), behaviorSessionToken(t, fixture.sessions[1]), "invalid-json{{{", 60); err != nil {
			t.Fatal(err)
		}
		assertTwoSurvivors(t, fixture)
	})
	t.Run("list returns empty when every session is corrupt", func(t *testing.T) {
		fixture := newSecondarySessionBehaviorFixture(t, "all", 2)
		for index, session := range fixture.sessions {
			if err := fixture.secondary.Set(t.Context(), behaviorSessionToken(t, session), "invalid-json-"+string(rune('a'+index)), 60); err != nil {
				t.Fatal(err)
			}
		}
		got, err := fixture.adapter.ListSessions(t.Context(), fixture.userID, false)
		if err != nil || len(got) != 0 {
			t.Fatalf("all corrupt sessions=%#v err=%v", got, err)
		}
	})
	for _, scenario := range []struct {
		name, raw string
	}{
		{name: "malformed JSON sessions", raw: "invalid-json{{{"},
		{name: "JSON null sessions", raw: "null"},
	} {
		t.Run("findSessions skips "+scenario.name, func(t *testing.T) {
			fixture := newSecondarySessionBehaviorFixture(t, strings.ReplaceAll(scenario.name, " ", "-"), 3)
			middle := behaviorSessionToken(t, fixture.sessions[1])
			if err := fixture.secondary.Set(t.Context(), middle, scenario.raw, 60); err != nil {
				t.Fatal(err)
			}
			tokens := []string{
				behaviorSessionToken(t, fixture.sessions[0]), middle, behaviorSessionToken(t, fixture.sessions[2]),
			}
			found, err := fixture.adapter.FindSessions(t.Context(), tokens, false)
			if err != nil || len(found) != 2 || found[0].Session["token"] != tokens[0] || found[1].Session["token"] != tokens[2] {
				t.Fatalf("findSessions=%#v err=%v", found, err)
			}
		})
	}
	t.Run("list deduplicates active tokens", func(t *testing.T) {
		fixture := newSecondarySessionBehaviorFixture(t, "duplicates", 1)
		token := behaviorSessionToken(t, fixture.sessions[0])
		expiresAt, _ := recordTime(fixture.sessions[0], "expiresAt")
		entries := []activeSessionEntry{
			{Token: token, ExpiresAt: expiresAt.UnixMilli()},
			{Token: token, ExpiresAt: expiresAt.UnixMilli()},
			{Token: token, ExpiresAt: expiresAt.UnixMilli()},
		}
		raw, _ := json.Marshal(entries)
		if err := fixture.secondary.Set(t.Context(), activeSessionsPrefix+fixture.userID, string(raw), 60); err != nil {
			t.Fatal(err)
		}
		got, err := fixture.adapter.ListSessions(t.Context(), fixture.userID, false)
		if err != nil || len(got) != 1 || behaviorSessionToken(t, got[0]) != token {
			t.Fatalf("deduplicated sessions=%#v err=%v", got, err)
		}
	})
}

type internalVerificationOutcome struct {
	record storage.Record
	won    bool
	err    error
}

func consumeConcurrently(
	ctx context.Context,
	adapter InternalAdapter,
	identifier string,
	callers int,
) []internalVerificationOutcome {
	results := make(chan internalVerificationOutcome, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, err := adapter.ConsumeVerificationValue(ctx, identifier)
			results <- internalVerificationOutcome{record: record, won: record != nil, err: err}
		}()
	}
	wait.Wait()
	close(results)
	outcomes := make([]internalVerificationOutcome, 0, callers)
	for result := range results {
		outcomes = append(outcomes, result)
	}
	return outcomes
}

func assertConsumeWinners(t *testing.T, outcomes []internalVerificationOutcome, wantValue string) {
	t.Helper()
	winners := 0
	for _, outcome := range outcomes {
		if outcome.err != nil {
			t.Fatalf("concurrent consume error: %v", outcome.err)
		}
		if !outcome.won {
			continue
		}
		winners++
		if outcome.record["value"] != wantValue {
			t.Fatalf("winning value=%#v, want %q", outcome.record, wantValue)
		}
	}
	if winners != 1 {
		t.Fatalf("consume winners=%d, want 1; outcomes=%#v", winners, outcomes)
	}
}

func TestInternalAdapterConsumeVerificationBehavior(t *testing.T) {
	t.Run("first caller receives row and later reads return nil", func(t *testing.T) {
		auth := MustNew(Options{Clock: func() time.Time { return internalAdapterEpoch }})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:single", Value: "user-1", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		first, err := adapter.ConsumeVerificationValue(t.Context(), "consume:single")
		if err != nil || first == nil || first["value"] != "user-1" {
			t.Fatalf("first consume=%#v err=%v", first, err)
		}
		second, err := adapter.ConsumeVerificationValue(t.Context(), "consume:single")
		if err != nil || second != nil {
			t.Fatalf("second consume=%#v err=%v", second, err)
		}
		missing, err := adapter.ConsumeVerificationValue(t.Context(), "consume:missing")
		if err != nil || missing != nil {
			t.Fatalf("missing consume=%#v err=%v", missing, err)
		}
	})

	t.Run("database concurrent consume has exactly one winner", func(t *testing.T) {
		auth := MustNew(Options{Clock: func() time.Time { return internalAdapterEpoch }})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:race", Value: "user-2", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		assertConsumeWinners(t, consumeConcurrently(t.Context(), adapter, "consume:race", 64), "user-2")
	})

	t.Run("expired database row is invalidated", func(t *testing.T) {
		auth := MustNew(Options{Clock: func() time.Time { return internalAdapterEpoch }})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:expired", Value: "expired", ExpiresAt: internalAdapterEpoch.Add(-time.Second),
		}); err != nil {
			t.Fatal(err)
		}
		consumed, err := adapter.ConsumeVerificationValue(t.Context(), "consume:expired")
		if err != nil || consumed != nil {
			t.Fatalf("expired consume=%#v err=%v", consumed, err)
		}
		replay, err := adapter.FindVerificationValue(t.Context(), "consume:expired")
		if err != nil || replay != nil {
			t.Fatalf("expired replay=%#v err=%v", replay, err)
		}
	})

	t.Run("delete before veto preserves the row", func(t *testing.T) {
		var veto atomic.Int64
		auth := MustNew(Options{
			Clock: func() time.Time { return internalAdapterEpoch },
			DatabaseHooks: DatabaseHooks{"verification": {Delete: DatabaseOperationHooks{
				Before: func(storage.Record, DatabaseHookContext) (DatabaseHookResult, error) {
					veto.Add(1)
					return DatabaseHookResult{Cancel: true}, nil
				},
			}}},
		})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:veto", Value: "user-3", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		consumed, err := adapter.ConsumeVerificationValue(t.Context(), "consume:veto")
		if err != nil || consumed != nil || veto.Load() != 1 {
			t.Fatalf("veto consume=%#v err=%v calls=%d", consumed, err, veto.Load())
		}
		preserved, err := adapter.FindVerificationValue(t.Context(), "consume:veto")
		if err != nil || preserved == nil {
			t.Fatalf("veto preserved=%#v err=%v", preserved, err)
		}
	})

	t.Run("delete after fires only for winning racer", func(t *testing.T) {
		var after atomic.Int64
		auth := MustNew(Options{
			Clock: func() time.Time { return internalAdapterEpoch },
			DatabaseHooks: DatabaseHooks{"verification": {Delete: DatabaseOperationHooks{
				After: func(any, DatabaseHookContext) error {
					after.Add(1)
					return nil
				},
			}}},
		})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:after-once", Value: "user-4", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		assertConsumeWinners(t, consumeConcurrently(t.Context(), adapter, "consume:after-once", 32), "user-4")
		if after.Load() != 1 {
			t.Fatalf("delete after calls=%d", after.Load())
		}
	})

	t.Run("original identifier consumes hashed storage", func(t *testing.T) {
		auth := MustNew(Options{
			Clock: func() time.Time { return internalAdapterEpoch },
			Verification: VerificationOptions{StoreIdentifier: VerificationIdentifierStorage{
				Strategy: VerificationIdentifierHashed,
			}},
		})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:hashed", Value: "user-5", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		consumed, err := adapter.ConsumeVerificationValue(t.Context(), "consume:hashed")
		if err != nil || consumed == nil || consumed["value"] != "user-5" {
			t.Fatalf("hashed consume=%#v err=%v", consumed, err)
		}
		replay, err := adapter.ConsumeVerificationValue(t.Context(), "consume:hashed")
		if err != nil || replay != nil {
			t.Fatalf("hashed replay=%#v err=%v", replay, err)
		}
	})

	t.Run("latest row wins and stale rows are invalidated", func(t *testing.T) {
		clock := internalAdapterEpoch
		auth := MustNew(Options{Clock: func() time.Time { return clock }})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:multi", Value: "older", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(5 * time.Millisecond)
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:multi", Value: "newer", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		consumed, err := adapter.ConsumeVerificationValue(t.Context(), "consume:multi")
		if err != nil || consumed == nil || consumed["value"] != "newer" {
			t.Fatalf("latest consume=%#v err=%v", consumed, err)
		}
		leftover, err := adapter.FindVerificationValue(t.Context(), "consume:multi")
		if err != nil || leftover != nil {
			t.Fatalf("stale leftover=%#v err=%v", leftover, err)
		}
	})

	t.Run("secondary atomic getAndDelete has one winner", func(t *testing.T) {
		secondary := &atomicSecondaryMemory{secondaryMemory: newSecondaryMemory()}
		auth := MustNew(Options{
			SecondaryStorage: secondary, Clock: func() time.Time { return internalAdapterEpoch },
		})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:secondary", Value: "secondary-user", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		assertConsumeWinners(t, consumeConcurrently(t.Context(), adapter, "consume:secondary", 32), "secondary-user")
		if secondary.consumeCalls.Load() == 0 || secondary.value(verificationPrefix+"consume:secondary") != "" {
			t.Fatalf("getAndDelete calls=%d cached=%q", secondary.consumeCalls.Load(), secondary.value(verificationPrefix+"consume:secondary"))
		}
	})

	t.Run("secondary expired hydrate and invalid date", func(t *testing.T) {
		secondary := newSecondaryMemory()
		auth := MustNew(Options{
			SecondaryStorage: secondary, Clock: func() time.Time { return internalAdapterEpoch },
			Logger: authlogger.Options{Disabled: true},
		})
		adapter := auth.InternalAdapter()
		expiredRaw, _ := json.Marshal(storage.Record{
			"id": "expired-row", "identifier": "consume:secondary-expired", "value": "expired",
			"expiresAt": internalAdapterEpoch.Add(-time.Second), "createdAt": internalAdapterEpoch, "updatedAt": internalAdapterEpoch,
		})
		if err := secondary.Set(t.Context(), verificationPrefix+"consume:secondary-expired", string(expiredRaw), 60); err != nil {
			t.Fatal(err)
		}
		expired, err := adapter.ConsumeVerificationValue(t.Context(), "consume:secondary-expired")
		if err != nil || expired != nil || secondary.value(verificationPrefix+"consume:secondary-expired") != "" {
			t.Fatalf("expired secondary=%#v cached=%q err=%v", expired, secondary.value(verificationPrefix+"consume:secondary-expired"), err)
		}

		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:secondary-hydrate", Value: "hydrate-user", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		hydrated, err := adapter.ConsumeVerificationValue(t.Context(), "consume:secondary-hydrate")
		expiresAt, validDate := recordTime(hydrated, "expiresAt")
		if err != nil || hydrated == nil || hydrated["value"] != "hydrate-user" || !validDate || !expiresAt.After(internalAdapterEpoch) {
			t.Fatalf("hydrated consume=%#v expires=%v/%t err=%v", hydrated, expiresAt, validDate, err)
		}

		invalidRaw := `{"id":"bad-row","identifier":"consume:secondary-invalid-date","value":"bad","expiresAt":"not-a-date"}`
		if err := secondary.Set(t.Context(), verificationPrefix+"consume:secondary-invalid-date", invalidRaw, 60); err != nil {
			t.Fatal(err)
		}
		invalid, err := adapter.ConsumeVerificationValue(t.Context(), "consume:secondary-invalid-date")
		if err != nil || invalid != nil {
			t.Fatalf("invalid-date consume=%#v err=%v", invalid, err)
		}
	})

	t.Run("secondary compatibility fallback serializes and warns once", func(t *testing.T) {
		oracle := loadInternalAdapterFixture(t)
		var warnings atomic.Int64
		secondary := &delayedSecondaryMemory{secondaryMemory: newSecondaryMemory()}
		auth := MustNew(Options{
			SecondaryStorage: secondary, Clock: func() time.Time { return internalAdapterEpoch },
			Logger: authlogger.Options{Log: func(level authlogger.Level, message string, _ ...any) {
				if level == authlogger.Warn && strings.Contains(message, oracle.Fixtures.NonAtomicWarningIncludes) {
					warnings.Add(1)
				}
			}},
		})
		adapter := auth.InternalAdapter()
		if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
			Identifier: "consume:secondary-fallback", Value: "fallback-user", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
		}); err != nil {
			t.Fatal(err)
		}
		assertConsumeWinners(t, consumeConcurrently(t.Context(), adapter, "consume:secondary-fallback", 32), "fallback-user")
		for _, identifier := range []string{"consume:warn-1", "consume:warn-2"} {
			if _, err := adapter.CreateVerificationValue(t.Context(), VerificationValue{
				Identifier: identifier, Value: "user", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.ConsumeVerificationValue(t.Context(), identifier); err != nil {
				t.Fatal(err)
			}
		}
		if warnings.Load() != 1 || secondary.value(verificationPrefix+"consume:secondary-fallback") != "" {
			t.Fatalf("fallback warnings=%d cached=%q", warnings.Load(), secondary.value(verificationPrefix+"consume:secondary-fallback"))
		}
	})
}

type internalReserveOutcome struct {
	won bool
	err error
}

func reserveConcurrently(
	ctx context.Context,
	adapter InternalAdapter,
	value VerificationValue,
	callers int,
) []internalReserveOutcome {
	results := make(chan internalReserveOutcome, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			won, err := adapter.ReserveVerificationValue(ctx, value)
			results <- internalReserveOutcome{won: won, err: err}
		}()
	}
	wait.Wait()
	close(results)
	outcomes := make([]internalReserveOutcome, 0, callers)
	for result := range results {
		outcomes = append(outcomes, result)
	}
	return outcomes
}

func TestInternalAdapterReserveVerificationBehavior(t *testing.T) {
	auth := MustNew(Options{Clock: func() time.Time { return internalAdapterEpoch }})
	adapter := auth.InternalAdapter()
	oracle := loadInternalAdapterFixture(t)

	fresh := VerificationValue{
		Identifier: oracle.Fixtures.ReservationID.Identifier,
		Value:      "jti-1",
		ExpiresAt:  internalAdapterEpoch.Add(time.Minute),
	}
	reserved, err := adapter.ReserveVerificationValue(t.Context(), fresh)
	if err != nil || !reserved {
		t.Fatalf("fresh reserve=%t err=%v", reserved, err)
	}
	found, err := adapter.FindVerificationValue(t.Context(), fresh.Identifier)
	if err != nil || found == nil || found["value"] != "jti-1" || found["id"] != oracle.Fixtures.ReservationID.ID {
		t.Fatalf("reserved row=%#v err=%v", found, err)
	}
	replayed := fresh
	replayed.Value = "jti-replay"
	reserved, err = adapter.ReserveVerificationValue(t.Context(), replayed)
	if err != nil || reserved {
		t.Fatalf("replayed reserve=%t err=%v", reserved, err)
	}

	race := VerificationValue{
		Identifier: "reserve:race", Value: "jti-3", ExpiresAt: internalAdapterEpoch.Add(time.Minute),
	}
	outcomes := reserveConcurrently(t.Context(), adapter, race, 64)
	winners := 0
	for _, outcome := range outcomes {
		if outcome.err != nil {
			t.Fatalf("reserve race error: %v", outcome.err)
		}
		if outcome.won {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("reserve race winners=%d outcomes=%#v", winners, outcomes)
	}

	for _, value := range []VerificationValue{
		{Identifier: "reserve:independent-a", Value: "jti-a", ExpiresAt: internalAdapterEpoch.Add(time.Minute)},
		{Identifier: "reserve:independent-b", Value: "jti-b", ExpiresAt: internalAdapterEpoch.Add(time.Minute)},
	} {
		reserved, err := adapter.ReserveVerificationValue(t.Context(), value)
		if err != nil || !reserved {
			t.Fatalf("independent reserve %q=%t err=%v", value.Identifier, reserved, err)
		}
	}
}
