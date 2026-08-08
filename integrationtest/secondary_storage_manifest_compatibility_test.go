package singleauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	adminplugin "github.com/pers0na2dev/single-auth/plugins/admin"
	anonymousplugin "github.com/pers0na2dev/single-auth/plugins/anonymous"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	secondaryStorageManifestBaseURL = "http://auth.example.test"
	secondaryStorageManifestSecret  = "0123456789abcdef0123456789abcdef"
)

type secondaryStorageCase struct {
	Suite       string
	Title       string
	Observation map[string]any
}

type secondaryStorageManifestStore struct {
	mu     sync.Mutex
	values map[string]string
	ttls   map[string]int64
}

func newSecondaryStorageManifestStore() *secondaryStorageManifestStore {
	return &secondaryStorageManifestStore{
		values: make(map[string]string),
		ttls:   make(map[string]int64),
	}
}

func (store *secondaryStorageManifestStore) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *secondaryStorageManifestStore) Set(
	_ context.Context,
	key string,
	value string,
	ttl int64,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = value
	store.ttls[key] = ttl
	return nil
}

func (store *secondaryStorageManifestStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.values, key)
	delete(store.ttls, key)
	return nil
}

func (store *secondaryStorageManifestStore) Clear() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values = make(map[string]string)
	store.ttls = make(map[string]int64)
}

func (store *secondaryStorageManifestStore) Has(key string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, ok := store.values[key]
	return ok
}

func (store *secondaryStorageManifestStore) Size() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.values)
}

type secondaryStorageManifestValueStore struct {
	mu     sync.Mutex
	values map[string]any
	ttls   map[string]int64
}

func newSecondaryStorageManifestValueStore() *secondaryStorageManifestValueStore {
	return &secondaryStorageManifestValueStore{
		values: make(map[string]any),
		ttls:   make(map[string]int64),
	}
}

func (store *secondaryStorageManifestValueStore) GetValue(_ context.Context, key string) (any, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *secondaryStorageManifestValueStore) Set(
	_ context.Context,
	key string,
	value string,
	ttl int64,
) error {
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.UseNumber()
	var parsed any
	if err := decoder.Decode(&parsed); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values[key] = parsed
	store.ttls[key] = ttl
	return nil
}

func (store *secondaryStorageManifestValueStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.values, key)
	delete(store.ttls, key)
	return nil
}

func (store *secondaryStorageManifestValueStore) Clear() {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.values = make(map[string]any)
	store.ttls = make(map[string]int64)
}

func (store *secondaryStorageManifestValueStore) Value(key string) any {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key]
}

var _ singleauth.SecondaryStorage = (*secondaryStorageManifestStore)(nil)
var _ singleauth.SecondaryValueStorage = (*secondaryStorageManifestValueStore)(nil)

type secondaryStorageManifestIdentity struct {
	Cookie string
	Body   map[string]any
}

func TestSecondaryStorageBehavior(t *testing.T) {
	for _, vector := range secondaryStorageCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			actual := runSecondaryStorageManifestVector(t, vector.Title)
			assertSecondaryStorageObservation(t, vector.Observation, actual)
		})
	}
}

func runSecondaryStorageManifestVector(t *testing.T, title string) map[string]any {
	t.Helper()
	switch title {
	case "should work end-to-end with string return":
		return runSecondaryStorageStringVector(t)
	case "should work end-to-end with object return":
		return runSecondaryStorageObjectVector(t)
	case "should not return a revoked session when it is deleted from both storages":
		return runSecondaryStoragePreserveVector(t, false)
	case "should not return a revoked session even if it exists in database":
		return runSecondaryStoragePreserveVector(t, true)
	case "deletes user sessions from secondary storage and database":
		return runSecondaryStorageDeleteUserVector(t)
	case "should clear secondary storage sessions when removing a user via admin":
		return runSecondaryStorageAdminRemoveVector(t)
	case "should clear secondary storage sessions when an anonymous user calls /delete-anonymous-user":
		return runSecondaryStorageAnonymousDeleteVector(t)
	default:
		t.Fatalf("unknown secondary-storage scenario %q", title)
		return nil
	}
}

func runSecondaryStorageStringVector(t *testing.T) map[string]any {
	store := newSecondaryStorageManifestStore()
	auth := newSecondaryStorageManifestAuth(t, singleauth.Options{SecondaryStorage: store})
	secondaryStorageManifestSignUp(t, auth, "test user", "test@test.com")
	store.Clear()
	initialStoreSize := store.Size()
	identity := secondaryStorageManifestSignIn(t, auth, "test@test.com")
	afterSignInStoreSize := store.Size()
	status, _, sessionValue := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", identity.Cookie, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("get session status = %d, body = %#v", status, sessionValue)
	}
	sessionResponse := secondaryStorageManifestObject(t, sessionValue)
	session := secondaryStorageManifestObjectField(t, sessionResponse, "session")
	user := secondaryStorageManifestObjectField(t, sessionResponse, "user")
	status, _, listValue := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/list-sessions", identity.Cookie, nil,
	)
	list, ok := listValue.([]any)
	if status != http.StatusOK || !ok {
		t.Fatalf("list sessions status = %d, body = %#v", status, listValue)
	}
	token, tokenIsString := session["token"].(string)
	status, _, revokeValue := secondaryStorageManifestExchange(
		t, auth, http.MethodPost, "/revoke-session", identity.Cookie, map[string]any{"token": token},
	)
	revoke := secondaryStorageManifestObject(t, revokeValue)
	if status != http.StatusOK {
		t.Fatalf("revoke status = %d, body = %#v", status, revoke)
	}
	status, _, after := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", identity.Cookie, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("get revoked session status = %d, body = %#v", status, after)
	}
	_, expiryIsDate := secondaryStorageManifestDate(session["expiresAt"])
	return map[string]any{
		"initialStoreSize":     initialStoreSize,
		"afterSignInStoreSize": afterSignInStoreSize,
		"sessionPresent":       sessionValue != nil,
		"sessionTokenString":   tokenIsString,
		"sessionExpiresAtDate": expiryIsDate,
		"userName":             user["name"],
		"userEmail":            user["email"],
		"listCount":            len(list),
		"revokeStatus":         revoke["status"],
		"afterSessionNull":     after == nil,
		"finalStoreSize":       store.Size(),
	}
}

func runSecondaryStorageObjectVector(t *testing.T) map[string]any {
	store := newSecondaryStorageManifestValueStore()
	auth := newSecondaryStorageManifestAuth(t, singleauth.Options{SecondaryValueStorage: store})
	secondaryStorageManifestSignUp(t, auth, "test user", "test@test.com")
	store.Clear()
	identity := secondaryStorageManifestSignIn(t, auth, "test@test.com")
	status, _, sessionValue := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", identity.Cookie, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("get object session status = %d, body = %#v", status, sessionValue)
	}
	sessionResponse := secondaryStorageManifestObject(t, sessionValue)
	session := secondaryStorageManifestObjectField(t, sessionResponse, "session")
	userID, _ := session["userId"].(string)
	activeList, activeIsArray := store.Value("active-sessions-" + userID).([]any)
	status, _, listValue := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/list-sessions", identity.Cookie, nil,
	)
	list, ok := listValue.([]any)
	if status != http.StatusOK || !ok {
		t.Fatalf("list object sessions status = %d, body = %#v", status, listValue)
	}
	token, _ := session["token"].(string)
	status, _, revokeValue := secondaryStorageManifestExchange(
		t, auth, http.MethodPost, "/revoke-session", identity.Cookie, map[string]any{"token": token},
	)
	revoke := secondaryStorageManifestObject(t, revokeValue)
	if status != http.StatusOK {
		t.Fatalf("revoke object status = %d, body = %#v", status, revoke)
	}
	status, _, after := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", identity.Cookie, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("get revoked object session status = %d, body = %#v", status, after)
	}
	return map[string]any{
		"sessionPresent":   sessionValue != nil,
		"activeListArray":  activeIsArray,
		"activeListCount":  len(activeList),
		"listCount":        len(list),
		"revokeStatus":     revoke["status"],
		"afterSessionNull": after == nil,
		"activeAfterNull":  store.Value("active-sessions-"+userID) == nil,
	}
}

func runSecondaryStoragePreserveVector(t *testing.T, preserve bool) map[string]any {
	store := newSecondaryStorageManifestStore()
	auth := newSecondaryStorageManifestAuth(t, singleauth.Options{
		SecondaryStorage: store,
		Session: singleauth.SessionOptions{
			StoreSessionInDatabase:    true,
			PreserveSessionInDatabase: preserve,
		},
	})
	secondaryStorageManifestSignUp(t, auth, "test user", "test@test.com")
	store.Clear()
	identity := secondaryStorageManifestSignIn(t, auth, "test@test.com")
	status, _, sessionValue := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", identity.Cookie, nil,
	)
	if status != http.StatusOK || sessionValue == nil {
		t.Fatalf("get preserve session status = %d, body = %#v", status, sessionValue)
	}
	session := secondaryStorageManifestObjectField(
		t, secondaryStorageManifestObject(t, sessionValue), "session",
	)
	token, _ := session["token"].(string)
	cachedBefore := store.Has(token)
	status, _, revokeValue := secondaryStorageManifestExchange(
		t, auth, http.MethodPost, "/revoke-session", identity.Cookie, map[string]any{"token": token},
	)
	revoke := secondaryStorageManifestObject(t, revokeValue)
	if status != http.StatusOK {
		t.Fatalf("revoke preserve status = %d, body = %#v", status, revoke)
	}
	databaseRows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _, after := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", identity.Cookie, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("get preserve revoked session status = %d, body = %#v", status, after)
	}
	return map[string]any{
		"sessionPresent":    sessionValue != nil,
		"cachedBefore":      cachedBefore,
		"revokeStatus":      revoke["status"],
		"cachedAfter":       store.Has(token),
		"databaseRowsAfter": len(databaseRows),
		"afterSessionNull":  after == nil,
	}
}

func runSecondaryStorageDeleteUserVector(t *testing.T) map[string]any {
	store := newSecondaryStorageManifestStore()
	auth := newSecondaryStorageManifestAuth(t, singleauth.Options{
		SecondaryStorage: store,
		Session: singleauth.SessionOptions{
			StoreSessionInDatabase:    true,
			PreserveSessionInDatabase: true,
		},
	})
	internal := auth.InternalAdapter()
	user, err := internal.CreateUser(t.Context(), storage.Record{
		"name": "Deleted User", "email": "deleted-user@test.com",
		"emailVerified": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	userID, _ := user["id"].(string)
	session, err := internal.CreateSession(
		t.Context(), userID, singleauth.InternalSessionCreateOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := session["token"].(string)
	activeKey := "active-sessions-" + userID
	databaseRowsBefore := secondaryStorageManifestDatabaseSessions(t, auth, userID)
	tokenBefore := store.Has(token)
	activeBefore := store.Has(activeKey)
	if err := internal.DeleteUser(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	databaseRowsAfter := secondaryStorageManifestDatabaseSessions(t, auth, userID)
	return map[string]any{
		"tokenBefore":        tokenBefore,
		"activeBefore":       activeBefore,
		"databaseRowsBefore": len(databaseRowsBefore),
		"tokenAfter":         store.Has(token),
		"activeAfter":        store.Has(activeKey),
		"databaseRowsAfter":  len(databaseRowsAfter),
	}
}

func runSecondaryStorageAdminRemoveVector(t *testing.T) map[string]any {
	store := newSecondaryStorageManifestStore()
	auth := newSecondaryStorageManifestAuth(t, singleauth.Options{
		SecondaryStorage: store,
		PluginFactories: []singleauth.PluginFactory{
			adminplugin.NewFactory(adminplugin.Options{}),
		},
		DatabaseHooks: singleauth.DatabaseHooks{
			"user": {
				Create: singleauth.DatabaseOperationHooks{
					Before: func(data storage.Record, _ singleauth.DatabaseHookContext) (singleauth.DatabaseHookResult, error) {
						if data["email"] == "admin@test.com" {
							return singleauth.DatabaseHookResult{Data: storage.Record{
								"role": "admin", "emailVerified": true,
							}}, nil
						}
						return singleauth.DatabaseHookResult{}, nil
					},
				},
			},
		},
	})
	secondaryStorageManifestSignUp(t, auth, "Admin", "admin@test.com")
	adminIdentity := secondaryStorageManifestSignIn(t, auth, "admin@test.com")
	secondaryStorageManifestSignUp(t, auth, "Victim", "victim@test.com")
	victimIdentity := secondaryStorageManifestSignIn(t, auth, "victim@test.com")
	status, _, victimSessionValue := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", victimIdentity.Cookie, nil,
	)
	if status != http.StatusOK || victimSessionValue == nil {
		t.Fatalf("victim get session status = %d, body = %#v", status, victimSessionValue)
	}
	victimSession := secondaryStorageManifestObject(t, victimSessionValue)
	victimUser := secondaryStorageManifestObjectField(t, victimSession, "user")
	victimSessionRecord := secondaryStorageManifestObjectField(t, victimSession, "session")
	victimID, _ := victimUser["id"].(string)
	victimToken, _ := victimSessionRecord["token"].(string)
	activeKey := "active-sessions-" + victimID
	tokenBefore := store.Has(victimToken)
	activeBefore := store.Has(activeKey)
	status, _, removeValue := secondaryStorageManifestExchange(
		t,
		auth,
		http.MethodPost,
		"/admin/remove-user",
		adminIdentity.Cookie,
		map[string]any{"userId": victimID},
	)
	remove := secondaryStorageManifestObject(t, removeValue)
	if status != http.StatusOK {
		t.Fatalf("admin remove status = %d, body = %#v", status, remove)
	}
	status, _, after := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", victimIdentity.Cookie, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("victim session after remove status = %d, body = %#v", status, after)
	}
	return map[string]any{
		"tokenBefore":      tokenBefore,
		"activeBefore":     activeBefore,
		"removeSuccess":    remove["success"],
		"tokenAfter":       store.Has(victimToken),
		"activeAfter":      store.Has(activeKey),
		"afterSessionNull": after == nil,
	}
}

func runSecondaryStorageAnonymousDeleteVector(t *testing.T) map[string]any {
	store := newSecondaryStorageManifestStore()
	auth := newSecondaryStorageManifestAuth(t, singleauth.Options{
		SecondaryStorage: store,
		PluginFactories: []singleauth.PluginFactory{
			anonymousplugin.NewFactory(anonymousplugin.Options{}),
		},
	})
	status, headers, signInValue := secondaryStorageManifestExchange(
		t, auth, http.MethodPost, "/sign-in/anonymous", "", nil,
	)
	signedIn := secondaryStorageManifestObject(t, signInValue)
	if status != http.StatusOK {
		t.Fatalf("anonymous sign in status = %d, body = %#v", status, signedIn)
	}
	cookie := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	token, _ := signedIn["token"].(string)
	user := secondaryStorageManifestObjectField(t, signedIn, "user")
	userID, _ := user["id"].(string)
	activeKey := "active-sessions-" + userID
	tokenBefore := store.Has(token)
	activeBefore := store.Has(activeKey)
	status, _, deleteValue := secondaryStorageManifestExchange(
		t, auth, http.MethodPost, "/delete-anonymous-user", cookie, nil,
	)
	deleted := secondaryStorageManifestObject(t, deleteValue)
	if status != http.StatusOK {
		t.Fatalf("anonymous delete status = %d, body = %#v", status, deleted)
	}
	status, _, after := secondaryStorageManifestExchange(
		t, auth, http.MethodGet, "/get-session", cookie, nil,
	)
	if status != http.StatusOK {
		t.Fatalf("anonymous session after delete status = %d, body = %#v", status, after)
	}
	return map[string]any{
		"tokenBefore":      tokenBefore,
		"activeBefore":     activeBefore,
		"deleteSuccess":    deleted["success"],
		"tokenAfter":       store.Has(token),
		"activeAfter":      store.Has(activeKey),
		"afterSessionNull": after == nil,
	}
}

func newSecondaryStorageManifestAuth(t *testing.T, overrides singleauth.Options) *singleauth.Auth {
	t.Helper()
	disabled := false
	options := overrides
	options.BaseURL = secondaryStorageManifestBaseURL
	options.Secret = secondaryStorageManifestSecret
	options.Clock = func() time.Time {
		return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	}
	options.RateLimit = singleauth.RateLimitOptions{Enabled: &disabled}
	options.EmailAndPassword = singleauth.EmailAndPasswordOptions{
		Enabled: true,
		Password: singleauth.PasswordOptions{
			Hash:   func(value string) (string, error) { return "hashed:" + value, nil },
			Verify: func(hash, value string) bool { return hash == "hashed:"+value },
		},
	}
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func secondaryStorageManifestSignUp(
	t *testing.T,
	auth *singleauth.Auth,
	name string,
	email string,
) secondaryStorageManifestIdentity {
	t.Helper()
	status, headers, value := secondaryStorageManifestExchange(
		t,
		auth,
		http.MethodPost,
		"/sign-up/email",
		"",
		map[string]any{"name": name, "email": email, "password": "password123"},
	)
	body := secondaryStorageManifestObject(t, value)
	if status != http.StatusOK {
		t.Fatalf("sign up %s status = %d, body = %#v", email, status, body)
	}
	return secondaryStorageManifestIdentity{
		Cookie: cookies.ApplySetCookies("", headers.Values("Set-Cookie")),
		Body:   body,
	}
}

func secondaryStorageManifestSignIn(
	t *testing.T,
	auth *singleauth.Auth,
	email string,
) secondaryStorageManifestIdentity {
	t.Helper()
	status, headers, value := secondaryStorageManifestExchange(
		t,
		auth,
		http.MethodPost,
		"/sign-in/email",
		"",
		map[string]any{"email": email, "password": "password123"},
	)
	body := secondaryStorageManifestObject(t, value)
	if status != http.StatusOK {
		t.Fatalf("sign in %s status = %d, body = %#v", email, status, body)
	}
	return secondaryStorageManifestIdentity{
		Cookie: cookies.ApplySetCookies("", headers.Values("Set-Cookie")),
		Body:   body,
	}
}

func secondaryStorageManifestExchange(
	t *testing.T,
	auth *singleauth.Auth,
	method string,
	path string,
	cookie string,
	body any,
) (int, http.Header, any) {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method,
		secondaryStorageManifestBaseURL+"/api/auth"+path,
		bytes.NewReader(encoded),
	)
	request.Header.Set("Origin", secondaryStorageManifestBaseURL)
	request.Header.Set("User-Agent", "single-auth-secondary-storage-behavior")
	request.Header.Set("X-Forwarded-For", "203.0.113.10")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	response := recorder.Result()
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return response.StatusCode, response.Header.Clone(), nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s %s response %q: %v", method, path, raw, err)
	}
	return response.StatusCode, response.Header.Clone(), value
}

func secondaryStorageManifestObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v (%T), want object", value, value)
	}
	return object
}

func secondaryStorageManifestObjectField(
	t *testing.T,
	object map[string]any,
	field string,
) map[string]any {
	t.Helper()
	return secondaryStorageManifestObject(t, object[field])
}

func secondaryStorageManifestDate(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, true
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed, err == nil
	default:
		return time.Time{}, false
	}
}

func secondaryStorageManifestDatabaseSessions(
	t *testing.T,
	auth *singleauth.Auth,
	userID string,
) []storage.Record {
	t.Helper()
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "session", Where: []storage.Where{{Field: "userId", Value: userID}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func assertSecondaryStorageObservation(
	t *testing.T,
	expected map[string]any,
	actual map[string]any,
) {
	t.Helper()
	expectedEncoded, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	var want any
	if err := json.Unmarshal(expectedEncoded, &want); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var got any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("secondary-storage observation = %#v, want %#v", got, want)
	}
}

func TestSecondaryStorageScenarioDefinitions(t *testing.T) {
	cases := secondaryStorageCases()
	if len(cases) != 7 {
		t.Fatalf("secondary-storage scenarios=%d, want 7", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, scenario := range cases {
		if scenario.Suite == "" || scenario.Title == "" || len(scenario.Observation) == 0 {
			t.Fatalf("invalid secondary-storage scenario: %#v", scenario)
		}
		if _, duplicate := seen[scenario.Title]; duplicate {
			t.Fatalf("duplicate secondary-storage scenario %q", scenario.Title)
		}
		seen[scenario.Title] = struct{}{}
	}
}

func secondaryStorageCases() []secondaryStorageCase {
	return []secondaryStorageCase{
		{
			Suite:       "secondary storage - anonymous user deletion",
			Title:       "should clear secondary storage sessions when an anonymous user calls /delete-anonymous-user",
			Observation: map[string]any{"tokenBefore": true, "activeBefore": true, "deleteSuccess": true, "tokenAfter": false, "activeAfter": false, "afterSessionNull": true},
		},
		{
			Suite:       "secondary storage - admin user removal",
			Title:       "should clear secondary storage sessions when removing a user via admin",
			Observation: map[string]any{"tokenBefore": true, "activeBefore": true, "removeSuccess": true, "tokenAfter": false, "activeAfter": false, "afterSessionNull": true},
		},
		{
			Suite:       "secondary storage - user deletion",
			Title:       "deletes user sessions from secondary storage and database",
			Observation: map[string]any{"tokenBefore": true, "activeBefore": true, "databaseRowsBefore": 1, "tokenAfter": false, "activeAfter": false, "databaseRowsAfter": 0},
		},
		{
			Suite:       "secondary storage - string values",
			Title:       "should work end-to-end with string return",
			Observation: map[string]any{"initialStoreSize": 0, "afterSignInStoreSize": 2, "sessionPresent": true, "sessionTokenString": true, "sessionExpiresAtDate": true, "userName": "test user", "userEmail": "test@test.com", "listCount": 1, "revokeStatus": true, "afterSessionNull": true, "finalStoreSize": 0},
		},
		{
			Suite:       "secondary storage - object values",
			Title:       "should work end-to-end with object return",
			Observation: map[string]any{"sessionPresent": true, "activeListArray": true, "activeListCount": 1, "listCount": 1, "revokeStatus": true, "afterSessionNull": true, "activeAfterNull": true},
		},
		{
			Suite:       "secondary storage - non-preserved database session",
			Title:       "should not return a revoked session when it is deleted from both storages",
			Observation: map[string]any{"sessionPresent": true, "cachedBefore": true, "revokeStatus": true, "cachedAfter": false, "databaseRowsAfter": 0, "afterSessionNull": true},
		},
		{
			Suite:       "secondary storage - preserved database session",
			Title:       "should not return a revoked session even if it exists in database",
			Observation: map[string]any{"sessionPresent": true, "cachedBefore": true, "revokeStatus": true, "cachedAfter": false, "databaseRowsAfter": 1, "afterSessionNull": true},
		},
	}
}
