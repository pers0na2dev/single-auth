package magiclink

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const magicSecondarySecret = "0123456789abcdef0123456789abcdef"

type magicSecondaryStorage struct {
	mu     sync.Mutex
	values map[string]string
	ttls   map[string]int64
}

type magicParsedSecondaryStorage struct {
	mu     sync.Mutex
	values map[string]any
	ttls   map[string]int64
}

func newMagicParsedSecondaryStorage() *magicParsedSecondaryStorage {
	return &magicParsedSecondaryStorage{values: map[string]any{}, ttls: map[string]int64{}}
}

func (store *magicParsedSecondaryStorage) GetValue(_ context.Context, key string) (any, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *magicParsedSecondaryStorage) Set(
	_ context.Context,
	key, value string,
	ttl int64,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		return err
	}
	store.values[key] = parsed
	store.ttls[key] = ttl
	return nil
}

func (store *magicParsedSecondaryStorage) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.values, key)
	delete(store.ttls, key)
	return nil
}

func (store *magicParsedSecondaryStorage) verificationKeys() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []string
	for key := range store.values {
		if strings.HasPrefix(key, "verification:") {
			result = append(result, key)
		}
	}
	return result
}

func (store *magicParsedSecondaryStorage) value(key string) any {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key]
}

func newMagicSecondaryStorage() *magicSecondaryStorage {
	return &magicSecondaryStorage{values: map[string]string{}, ttls: map[string]int64{}}
}

func (store *magicSecondaryStorage) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *magicSecondaryStorage) Set(_ context.Context, key, value string, ttl int64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = value
	store.ttls[key] = ttl
	return nil
}

func (store *magicSecondaryStorage) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.values, key)
	delete(store.ttls, key)
	return nil
}

func (store *magicSecondaryStorage) GetAndDelete(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value := store.values[key]
	delete(store.values, key)
	delete(store.ttls, key)
	return value, nil
}

func (store *magicSecondaryStorage) verificationKeys() []string {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []string
	for key := range store.values {
		if strings.HasPrefix(key, "verification:") {
			result = append(result, key)
		}
	}
	return result
}

func TestMagicLinkSecondaryStorageSendVerifyAndSignUp(t *testing.T) {
	store := newMagicSecondaryStorage()
	now := time.Date(2026, 8, 9, 16, 0, 0, 0, time.UTC)
	auth, delivered := newSecondaryMagicAuth(t, store, &now, 5*time.Minute)

	send := secondaryMagicRequest(t, auth, http.MethodPost, "/api/auth/sign-in/magic-link", map[string]any{
		"email": "new-secondary-user@test.com", "name": "New User",
	})
	if send.Code != http.StatusOK || delivered.Email != "new-secondary-user@test.com" ||
		!strings.Contains(delivered.URL, "http://localhost:3000/api/auth/magic-link/verify") {
		t.Fatalf("send status=%d body=%s delivered=%#v", send.Code, send.Body.String(), *delivered)
	}
	keys := store.verificationKeys()
	if len(keys) != 1 {
		t.Fatalf("verification keys=%#v", keys)
	}
	store.mu.Lock()
	verificationTTL := store.ttls[keys[0]]
	store.mu.Unlock()
	if verificationTTL != 300 {
		t.Fatalf("verification TTL=%d", verificationTTL)
	}

	verify := secondaryMagicRequest(t, auth, http.MethodGet, "/api/auth/magic-link/verify?token="+delivered.Token, nil)
	if verify.Code != http.StatusOK || len(verify.Header().Values("Set-Cookie")) == 0 {
		t.Fatalf("verify status=%d body=%s cookies=%#v", verify.Code, verify.Body.String(), verify.Header().Values("Set-Cookie"))
	}
	var response map[string]any
	if err := json.Unmarshal(verify.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["token"] == "" {
		t.Fatalf("verify response=%#v", response)
	}
	user, ok := response["user"].(map[string]any)
	if !ok || user["name"] != "New User" || user["email"] != "new-secondary-user@test.com" || user["emailVerified"] != true {
		t.Fatalf("created user=%#v", response["user"])
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 0 || len(store.verificationKeys()) != 0 {
		t.Fatalf("database verification rows=%#v store keys=%#v err=%v", rows, store.verificationKeys(), err)
	}
}

func TestMagicLinkSecondaryStorageConsumesOnceAndRejectsReplay(t *testing.T) {
	store := newMagicSecondaryStorage()
	now := time.Date(2026, 8, 9, 17, 0, 0, 0, time.UTC)
	auth, delivered := newSecondaryMagicAuth(t, store, &now, 5*time.Minute)
	if response := secondaryMagicRequest(t, auth, http.MethodPost, "/api/auth/sign-in/magic-link", map[string]any{
		"email": "atomic-secondary@test.com",
	}); response.Code != http.StatusOK {
		t.Fatalf("send status=%d body=%s", response.Code, response.Body.String())
	}
	path := "/api/auth/magic-link/verify?token=" + delivered.Token
	first := secondaryMagicRequest(t, auth, http.MethodGet, path, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	for attempt := 0; attempt < 3; attempt++ {
		replay := secondaryMagicRequest(t, auth, http.MethodGet, path, nil)
		if replay.Code != http.StatusFound || !strings.Contains(replay.Header().Get("Location"), "error=INVALID_TOKEN") {
			t.Fatalf("replay %d status=%d location=%q body=%s", attempt, replay.Code, replay.Header().Get("Location"), replay.Body.String())
		}
	}
}

func TestMagicLinkSecondaryStorageDeletesExpiredVerification(t *testing.T) {
	store := newMagicSecondaryStorage()
	now := time.Date(2026, 8, 9, 18, 0, 0, 0, time.UTC)
	auth, delivered := newSecondaryMagicAuth(t, store, &now, time.Second)
	if response := secondaryMagicRequest(t, auth, http.MethodPost, "/api/auth/sign-in/magic-link", map[string]any{
		"email": "expired-secondary@test.com",
	}); response.Code != http.StatusOK {
		t.Fatalf("send status=%d body=%s", response.Code, response.Body.String())
	}
	if len(store.verificationKeys()) != 1 {
		t.Fatalf("verification keys=%#v", store.verificationKeys())
	}
	now = now.Add(2 * time.Second)
	verify := secondaryMagicRequest(t, auth, http.MethodGet, "/api/auth/magic-link/verify?token="+delivered.Token, nil)
	if verify.Code != http.StatusFound || !strings.Contains(verify.Header().Get("Location"), "error=INVALID_TOKEN") {
		t.Fatalf("expired status=%d location=%q body=%s", verify.Code, verify.Header().Get("Location"), verify.Body.String())
	}
	if len(store.verificationKeys()) != 0 {
		t.Fatalf("expired verification remains: %#v", store.verificationKeys())
	}
}

func TestMagicLinkPreParsedSecondaryStorageSendAndVerify(t *testing.T) {
	store := newMagicParsedSecondaryStorage()
	now := time.Date(2026, 8, 9, 19, 0, 0, 0, time.UTC)
	auth, delivered := newValueSecondaryMagicAuth(t, store, &now, 5*time.Minute)

	send := secondaryMagicRequest(t, auth, http.MethodPost, "/api/auth/sign-in/magic-link", map[string]any{
		"email": "pre-parsed-secondary@test.com", "name": "Parsed User",
	})
	if send.Code != http.StatusOK || delivered.Email != "pre-parsed-secondary@test.com" {
		t.Fatalf("send status=%d body=%s delivered=%#v", send.Code, send.Body.String(), *delivered)
	}
	keys := store.verificationKeys()
	if len(keys) != 1 {
		t.Fatalf("verification keys=%#v", keys)
	}
	raw, ok := store.value(keys[0]).(map[string]any)
	if !ok {
		t.Fatalf("pre-parsed verification=%#v", store.value(keys[0]))
	}
	if _, isString := raw["expiresAt"].(string); !isString {
		t.Fatalf("stored expiresAt type=%T, value=%#v", raw["expiresAt"], raw["expiresAt"])
	}

	verify := secondaryMagicRequest(
		t,
		auth,
		http.MethodGet,
		"/api/auth/magic-link/verify?token="+delivered.Token,
		nil,
	)
	if verify.Code != http.StatusOK || len(verify.Header().Values("Set-Cookie")) == 0 {
		t.Fatalf(
			"verify status=%d body=%s cookies=%#v",
			verify.Code,
			verify.Body.String(),
			verify.Header().Values("Set-Cookie"),
		)
	}
	var response map[string]any
	if err := json.Unmarshal(verify.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["token"] == "" || len(store.verificationKeys()) != 0 {
		t.Fatalf("verify response=%#v remaining=%#v", response, store.verificationKeys())
	}
}

func TestMagicLinkPreParsedSecondaryStorageConsumesOnceAndRejectsReplay(t *testing.T) {
	store := newMagicParsedSecondaryStorage()
	now := time.Date(2026, 8, 9, 20, 0, 0, 0, time.UTC)
	auth, delivered := newValueSecondaryMagicAuth(t, store, &now, 5*time.Minute)
	if response := secondaryMagicRequest(t, auth, http.MethodPost, "/api/auth/sign-in/magic-link", map[string]any{
		"email": "pre-parsed-replay@test.com",
	}); response.Code != http.StatusOK {
		t.Fatalf("send status=%d body=%s", response.Code, response.Body.String())
	}
	path := "/api/auth/magic-link/verify?token=" + delivered.Token
	first := secondaryMagicRequest(t, auth, http.MethodGet, path, nil)
	if first.Code != http.StatusOK || len(first.Header().Values("Set-Cookie")) == 0 {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	for attempt := 0; attempt < 2; attempt++ {
		replay := secondaryMagicRequest(t, auth, http.MethodGet, path, nil)
		if replay.Code != http.StatusFound ||
			!strings.Contains(replay.Header().Get("Location"), "error=INVALID_TOKEN") {
			t.Fatalf(
				"replay %d status=%d location=%q body=%s",
				attempt,
				replay.Code,
				replay.Header().Get("Location"),
				replay.Body.String(),
			)
		}
	}
}

func newSecondaryMagicAuth(
	t *testing.T,
	store singleauth.SecondaryStorage,
	now *time.Time,
	expiresIn time.Duration,
) (*singleauth.Auth, *MagicLinkMessage) {
	return newSecondaryMagicAuthWithOptions(t, singleauth.Options{
		SecondaryStorage: store,
	}, now, expiresIn)
}

func newValueSecondaryMagicAuth(
	t *testing.T,
	store singleauth.SecondaryValueStorage,
	now *time.Time,
	expiresIn time.Duration,
) (*singleauth.Auth, *MagicLinkMessage) {
	return newSecondaryMagicAuthWithOptions(t, singleauth.Options{
		SecondaryValueStorage: store,
	}, now, expiresIn)
}

func newSecondaryMagicAuthWithOptions(
	t *testing.T,
	authOptions singleauth.Options,
	now *time.Time,
	expiresIn time.Duration,
) (*singleauth.Auth, *MagicLinkMessage) {
	t.Helper()
	disabled := false
	delivered := &MagicLinkMessage{}
	authOptions.BaseURL = "http://localhost:3000"
	authOptions.Secret = magicSecondarySecret
	authOptions.Clock = func() time.Time { return *now }
	authOptions.RateLimit = singleauth.RateLimitOptions{Enabled: &disabled}
	authOptions.PluginFactories = []singleauth.PluginFactory{NewFactory(Options{
		ExpiresIn: expiresIn,
		SendMagicLink: func(_ context.Context, message MagicLinkMessage, _ *engine.Context) error {
			*delivered = message
			return nil
		},
	})}
	auth, err := singleauth.New(authOptions)
	if err != nil {
		t.Fatal(err)
	}
	return auth, delivered
}

func secondaryMagicRequest(
	t *testing.T,
	auth *singleauth.Auth,
	method, path string,
	body map[string]any,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "http://localhost:3000"+path, bytes.NewReader(encoded))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		request.Header.Set("Origin", "http://localhost:3000")
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	return recorder
}
