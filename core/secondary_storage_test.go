package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	authlogger "github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/storage"
)

type secondaryMemory struct {
	mu      sync.Mutex
	values  map[string]string
	ttls    map[string]int64
	deletes []string
}

func newSecondaryMemory() *secondaryMemory {
	return &secondaryMemory{values: map[string]string{}, ttls: map[string]int64{}}
}

func (memory *secondaryMemory) Get(_ context.Context, key string) (string, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	return memory.values[key], nil
}

func (memory *secondaryMemory) Set(_ context.Context, key, value string, ttl int64) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	memory.values[key] = value
	memory.ttls[key] = ttl
	return nil
}

func (memory *secondaryMemory) Delete(_ context.Context, key string) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	delete(memory.values, key)
	delete(memory.ttls, key)
	memory.deletes = append(memory.deletes, key)
	return nil
}

func (memory *secondaryMemory) value(key string) string {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	return memory.values[key]
}

func (memory *secondaryMemory) ttl(key string) int64 {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	return memory.ttls[key]
}

func (memory *secondaryMemory) forceDelete(key string) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	delete(memory.values, key)
}

type atomicSecondaryMemory struct {
	*secondaryMemory
	consumeCalls atomic.Int32
}

type parsedSecondaryMemory struct {
	mu      sync.Mutex
	values  map[string]any
	ttls    map[string]int64
	deletes []string
}

type atomicParsedSecondaryMemory struct {
	*parsedSecondaryMemory
	consumeCalls atomic.Int32
}

func (memory *atomicParsedSecondaryMemory) GetAndDeleteValue(
	_ context.Context,
	key string,
) (any, error) {
	memory.consumeCalls.Add(1)
	memory.mu.Lock()
	defer memory.mu.Unlock()
	value := memory.values[key]
	delete(memory.values, key)
	delete(memory.ttls, key)
	return value, nil
}

func newParsedSecondaryMemory() *parsedSecondaryMemory {
	return &parsedSecondaryMemory{values: map[string]any{}, ttls: map[string]int64{}}
}

func (memory *parsedSecondaryMemory) GetValue(_ context.Context, key string) (any, error) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	return memory.values[key], nil
}

func (memory *parsedSecondaryMemory) Set(
	_ context.Context,
	key, value string,
	ttl int64,
) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		return err
	}
	memory.values[key] = parsed
	memory.ttls[key] = ttl
	return nil
}

func (memory *parsedSecondaryMemory) Delete(_ context.Context, key string) error {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	delete(memory.values, key)
	delete(memory.ttls, key)
	memory.deletes = append(memory.deletes, key)
	return nil
}

func (memory *parsedSecondaryMemory) value(key string) any {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	return memory.values[key]
}

func (memory *atomicSecondaryMemory) GetAndDelete(_ context.Context, key string) (string, error) {
	memory.consumeCalls.Add(1)
	memory.mu.Lock()
	defer memory.mu.Unlock()
	value := memory.values[key]
	delete(memory.values, key)
	delete(memory.ttls, key)
	return value, nil
}

func TestSecondaryStorageIsAuthoritativeForSessionsByDefault(t *testing.T) {
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	secondary := newSecondaryMemory()
	disabled := false
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		SecondaryStorage: secondary,
		RateLimit:        RateLimitOptions{Enabled: &disabled},
		Clock:            func() time.Time { return now },
	})

	cookieOne, tokenOne, _ := createSessionTestUser(t, auth, "secondary@example.com")
	if secondary.value(tokenOne) == "" || secondary.ttl(tokenOne) != int64((7*24*time.Hour)/time.Second) {
		t.Fatalf("cached session token=%q ttl=%d", secondary.value(tokenOne), secondary.ttl(tokenOne))
	}
	var active []activeSessionEntry
	if err := json.Unmarshal([]byte(secondary.value(activeSessionsPrefix+mustUserID(t, auth, "secondary@example.com"))), &active); err != nil || len(active) != 1 || active[0].Token != tokenOne {
		t.Fatalf("active sessions = %#v, %v", active, err)
	}
	databaseRows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "session"})
	if err != nil || len(databaseRows) != 0 {
		t.Fatalf("secondary-only database sessions = %#v, %v", databaseRows, err)
	}

	cookieTwo, _, _ := signInSessionTestUser(t, auth, "secondary@example.com")
	status, _, value := sessionTestRequest(t, auth, http.MethodGet, "/list-sessions", cookieTwo, nil)
	if status != http.StatusOK || len(value.([]any)) != 2 {
		t.Fatalf("secondary list status=%d value=%#v", status, value)
	}

	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/update-user", cookieTwo, map[string]any{"name": "Cache Updated"})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("update user status=%d value=%#v", status, value)
	}
	cookieTwo = cookies.ApplySetCookies(cookieTwo, headers.Values("Set-Cookie"))
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieOne, nil)
	if status != http.StatusOK || objectString(t, objectValue(t, value.(map[string]any), "user"), "name") != "Cache Updated" {
		t.Fatalf("propagated cached user status=%d value=%#v", status, value)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/revoke-session", cookieTwo, map[string]any{"token": tokenOne})
	if status != http.StatusOK || secondary.value(tokenOne) != "" {
		t.Fatalf("revoke session status=%d value=%#v cached=%q", status, value, secondary.value(tokenOne))
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieOne, nil)
	if status != http.StatusOK || value != nil {
		t.Fatalf("revoked secondary session status=%d value=%#v", status, value)
	}
}

func TestSecondaryDatabaseFallbackAndPreserveSemantics(t *testing.T) {
	for _, test := range []struct {
		name     string
		email    string
		preserve bool
		wantLive bool
		wantDB   int
	}{
		{name: "fallback and delete", email: "fallback@example.com", wantLive: true, wantDB: 0},
		{name: "preserved audit row stays revoked", email: "preserved@example.com", preserve: true, wantLive: false, wantDB: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			secondary := newSecondaryMemory()
			disabled := false
			auth := MustNew(Options{
				Secret:           "0123456789abcdef0123456789abcdef",
				EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
				SecondaryStorage: secondary,
				Session: SessionOptions{
					StoreSessionInDatabase: true, PreserveSessionInDatabase: test.preserve,
				},
				RateLimit: RateLimitOptions{Enabled: &disabled},
			})
			cookieHeader, token, _ := createSessionTestUser(t, auth, test.email)
			rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "session"})
			if err != nil || len(rows) != 1 {
				t.Fatalf("initial database rows = %#v, %v", rows, err)
			}
			secondary.forceDelete(token)
			status, _, value := sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
			if test.wantLive {
				if status != http.StatusOK || value == nil {
					t.Fatalf("database fallback status=%d value=%#v", status, value)
				}
			} else if status != http.StatusOK || value != nil {
				t.Fatalf("preserved row restored revoked session: status=%d value=%#v", status, value)
			}

			// Put the cache entry back so sign-out exercises authoritative removal.
			stored := rows[0]
			userID, _ := recordString(stored, "userId")
			if err := auth.storeSecondarySession(t.Context(), auth.Adapter(), stored, userID); err != nil {
				t.Fatal(err)
			}
			status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/sign-out", cookieHeader, map[string]any{})
			if status != http.StatusOK {
				t.Fatalf("sign out status=%d value=%#v", status, value)
			}
			rows, err = auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "session"})
			if err != nil || len(rows) != test.wantDB {
				t.Fatalf("database rows after revoke = %#v, %v", rows, err)
			}
			status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
			if status != http.StatusOK || value != nil {
				t.Fatalf("revoked session restored: status=%d value=%#v", status, value)
			}
		})
	}
}

func TestSecondaryVerificationAtomicConsumeAndDatabaseStateDefault(t *testing.T) {
	now := time.Date(2026, 8, 8, 15, 0, 0, 0, time.UTC)
	secondary := &atomicSecondaryMemory{secondaryMemory: newSecondaryMemory()}
	var delivered PasswordResetMessage
	auth := MustNew(Options{
		BaseURL: "https://auth.example", Secret: "0123456789abcdef0123456789abcdef",
		SecondaryStorage: secondary,
		EmailAndPassword: EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(_ context.Context, message PasswordResetMessage) error {
				delivered = message
				return nil
			},
		},
		Clock: func() time.Time { return now },
	})
	if auth.Options().Account.StoreStateStrategy != "database" {
		t.Fatalf("secondary state strategy = %q", auth.Options().Account.StoreStateStrategy)
	}
	if _, err := auth.API().SignUpEmail(t.Context(), SignUpEmailInput{
		Name: "Atomic", Email: "atomic-secondary@example.com", Password: "password123",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().RequestPasswordReset(t.Context(), RequestPasswordResetInput{
		Email: "atomic-secondary@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	key := verificationPrefix + "reset-password:" + delivered.Token
	if secondary.value(key) == "" || secondary.ttl(key) != 3600 {
		t.Fatalf("cached verification value=%q ttl=%d", secondary.value(key), secondary.ttl(key))
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("secondary-only verification database rows=%#v, %v", rows, err)
	}
	result, err := auth.API().ResetPassword(t.Context(), ResetPasswordInput{
		NewPassword: "new-password123", Token: delivered.Token,
	})
	if err != nil || !result.Status || secondary.consumeCalls.Load() != 1 || secondary.value(key) != "" {
		t.Fatalf("atomic reset=%#v err=%v calls=%d cached=%q", result, err, secondary.consumeCalls.Load(), secondary.value(key))
	}
	if _, err := auth.API().ResetPassword(t.Context(), ResetPasswordInput{
		NewPassword: "another-password123", Token: delivered.Token,
	}); err == nil {
		t.Fatal("consumed verification token was replayed")
	}
}

func TestSecondaryVerificationFallbackIsProcessAtomicAndWarnsOnce(t *testing.T) {
	secondary := newSecondaryMemory()
	var delivered PasswordResetMessage
	var warningCount atomic.Int32
	auth := MustNew(Options{
		BaseURL: "https://auth.example", Secret: "0123456789abcdef0123456789abcdef",
		SecondaryStorage: secondary,
		Logger: authlogger.Options{Log: func(level authlogger.Level, message string, _ ...any) {
			if level == authlogger.Warn && strings.Contains(message, "getAndDelete") {
				warningCount.Add(1)
			}
		}},
		EmailAndPassword: EmailAndPasswordOptions{
			Enabled: true,
			SendResetPassword: func(_ context.Context, message PasswordResetMessage) error {
				delivered = message
				return nil
			},
		},
	})
	if _, err := auth.API().SignUpEmail(t.Context(), SignUpEmailInput{
		Name: "Race", Email: "race-secondary@example.com", Password: "password123",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.API().RequestPasswordReset(t.Context(), RequestPasswordResetInput{
		Email: "race-secondary@example.com",
	}); err != nil {
		t.Fatal(err)
	}

	const racers = 24
	var successes atomic.Int32
	var wait sync.WaitGroup
	wait.Add(racers)
	for range racers {
		go func() {
			defer wait.Done()
			result, err := auth.API().ResetPassword(context.Background(), ResetPasswordInput{
				NewPassword: "raced-password123", Token: delivered.Token,
			})
			if err == nil && result.Status {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || warningCount.Load() != 1 {
		t.Fatalf("successes=%d warnings=%d", successes.Load(), warningCount.Load())
	}
}

func TestSecondaryValueStorageRevivesVerificationDatesAcrossReads(t *testing.T) {
	now := time.Date(2026, 8, 9, 19, 0, 0, 0, time.UTC)
	secondary := newParsedSecondaryMemory()
	disabled := false
	auth := MustNew(Options{
		Secret:                "0123456789abcdef0123456789abcdef",
		SecondaryValueStorage: secondary,
		RateLimit:             RateLimitOptions{Enabled: &disabled},
		Clock:                 func() time.Time { return now },
	})
	expiresAt := now.Add(time.Minute)
	created, err := auth.createStoredVerification(
		t.Context(),
		"date-test",
		"test-value",
		expiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := created["expiresAt"].(time.Time); !ok {
		t.Fatalf("created expiresAt type = %T", created["expiresAt"])
	}

	stored, ok := secondary.value(verificationPrefix + "date-test").(map[string]any)
	if !ok {
		t.Fatalf("stored verification = %#v", secondary.value(verificationPrefix+"date-test"))
	}
	for _, field := range []string{"expiresAt", "createdAt", "updatedAt"} {
		if _, isString := stored[field].(string); !isString {
			t.Fatalf("stored %s type = %T, want pre-parsed ISO string", field, stored[field])
		}
	}

	first, err := auth.findStoredVerification(t.Context(), "date-test")
	if err != nil || first == nil {
		t.Fatalf("first read = %#v, %v", first, err)
	}
	second, err := auth.findStoredVerification(t.Context(), "date-test")
	if err != nil || second == nil {
		t.Fatalf("second read = %#v, %v", second, err)
	}
	for _, record := range []storage.Record{first, second} {
		for _, field := range []string{"expiresAt", "createdAt", "updatedAt"} {
			if _, isTime := record[field].(time.Time); !isTime {
				t.Fatalf("read %s type = %T, record=%#v", field, record[field], record)
			}
		}
	}
	firstExpiry := first["expiresAt"].(time.Time)
	secondExpiry := second["expiresAt"].(time.Time)
	if !firstExpiry.After(now) || !firstExpiry.Before(now.Add(2*time.Minute)) ||
		!firstExpiry.Equal(secondExpiry) {
		t.Fatalf("revived expiries first=%s second=%s", firstExpiry, secondExpiry)
	}
	// Decoding must not mutate object-valued storage; a later read must perform
	// the same date revival from the original ISO strings.
	stored = secondary.value(verificationPrefix + "date-test").(map[string]any)
	if _, remainsString := stored["expiresAt"].(string); !remainsString {
		t.Fatalf("stored object mutated after reads: %#v", stored)
	}
}

func TestSecondaryValueStoragePreservesNonDateStrings(t *testing.T) {
	now := time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC)
	secondary := newParsedSecondaryMemory()
	disabled := false
	auth := MustNew(Options{
		Secret:                "0123456789abcdef0123456789abcdef",
		SecondaryValueStorage: secondary,
		RateLimit:             RateLimitOptions{Enabled: &disabled},
		Clock:                 func() time.Time { return now },
	})
	if _, err := auth.createStoredVerification(
		t.Context(),
		"string-field-test",
		"my-token-value-123",
		now.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	found, err := auth.findStoredVerification(t.Context(), "string-field-test")
	if err != nil || found == nil {
		t.Fatalf("find = %#v, %v", found, err)
	}
	if identifier, ok := found["identifier"].(string); !ok || identifier != "string-field-test" {
		t.Fatalf("identifier = %#v (%T)", found["identifier"], found["identifier"])
	}
	if value, ok := found["value"].(string); !ok || value != "my-token-value-123" {
		t.Fatalf("value = %#v (%T)", found["value"], found["value"])
	}
	if _, ok := found["expiresAt"].(time.Time); !ok {
		t.Fatalf("expiresAt type = %T", found["expiresAt"])
	}
}

func TestSecondaryValueStorageSessionsRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 9, 21, 0, 0, 0, time.UTC)
	secondary := newParsedSecondaryMemory()
	disabled := false
	auth := MustNew(Options{
		Secret:                "0123456789abcdef0123456789abcdef",
		EmailAndPassword:      EmailAndPasswordOptions{Enabled: true},
		SecondaryValueStorage: secondary,
		RateLimit:             RateLimitOptions{Enabled: &disabled},
		Clock:                 func() time.Time { return now },
	})
	cookieHeader, token, _ := createSessionTestUser(t, auth, "parsed-session@example.com")
	raw, ok := secondary.value(token).(map[string]any)
	if !ok {
		t.Fatalf("stored session payload = %#v", secondary.value(token))
	}
	storedSession, ok := raw["session"].(map[string]any)
	if !ok {
		t.Fatalf("stored session = %#v", raw["session"])
	}
	if _, isString := storedSession["expiresAt"].(string); !isString {
		t.Fatalf("stored session expiry type = %T", storedSession["expiresAt"])
	}

	status, _, value := sessionTestRequest(
		t,
		auth,
		http.MethodGet,
		"/get-session",
		cookieHeader,
		nil,
	)
	if status != http.StatusOK || value == nil {
		t.Fatalf("get parsed session status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(
		t,
		auth,
		http.MethodGet,
		"/list-sessions",
		cookieHeader,
		nil,
	)
	if status != http.StatusOK || len(value.([]any)) != 1 {
		t.Fatalf("list parsed sessions status=%d value=%#v", status, value)
	}
	storedSession = secondary.value(token).(map[string]any)["session"].(map[string]any)
	if _, remainsString := storedSession["expiresAt"].(string); !remainsString {
		t.Fatalf("stored session mutated after reads: %#v", storedSession)
	}
}

func TestSecondaryValueStorageAtomicVerificationConsume(t *testing.T) {
	now := time.Date(2026, 8, 9, 22, 0, 0, 0, time.UTC)
	secondary := &atomicParsedSecondaryMemory{
		parsedSecondaryMemory: newParsedSecondaryMemory(),
	}
	disabled := false
	auth := MustNew(Options{
		Secret:                "0123456789abcdef0123456789abcdef",
		SecondaryValueStorage: secondary,
		RateLimit:             RateLimitOptions{Enabled: &disabled},
		Clock:                 func() time.Time { return now },
	})
	if _, err := auth.createStoredVerification(
		t.Context(),
		"parsed-atomic",
		"winner",
		now.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}

	const racers = 24
	var successes atomic.Int32
	var wait sync.WaitGroup
	wait.Add(racers)
	for range racers {
		go func() {
			defer wait.Done()
			value, err := auth.consumeStoredVerification(context.Background(), "parsed-atomic")
			if err == nil && value != nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || secondary.consumeCalls.Load() != racers {
		t.Fatalf(
			"atomic parsed successes=%d consume calls=%d",
			successes.Load(),
			secondary.consumeCalls.Load(),
		)
	}
}

func TestSecondaryStorageFormsAreMutuallyExclusive(t *testing.T) {
	_, err := New(Options{
		SecondaryStorage:      newSecondaryMemory(),
		SecondaryValueStorage: newParsedSecondaryMemory(),
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("mutually-exclusive stores error = %v", err)
	}
}

func mustUserID(t *testing.T, auth *Auth, email string) string {
	t.Helper()
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: email}},
	})
	if err != nil || user == nil {
		t.Fatalf("find user = %#v, %v", user, err)
	}
	userID, ok := recordString(user, "id")
	if !ok {
		t.Fatalf("user id = %#v", user)
	}
	return userID
}
