package multisession_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/plugins/multisession"
)

const (
	testBaseURL = "http://auth.example.test"
	testSecret  = "0123456789abcdef0123456789abcdef"
)

type httpResult struct {
	status  int
	headers http.Header
	value   any
}

func newAuth(t *testing.T, maximum *int, mutate func(*singleauth.Options)) *singleauth.Auth {
	t.Helper()
	options := singleauth.Options{
		BaseURL: testBaseURL,
		Secret:  testSecret,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash: func(password string) (string, error) { return "test:" + password, nil },
				Verify: func(hash, password string) bool {
					return hash == "test:"+password
				},
			},
		},
		PluginFactories: []singleauth.PluginFactory{
			multisession.NewFactory(multisession.Options{MaximumSessions: maximum}),
		},
	}
	if mutate != nil {
		mutate(&options)
	}
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func exchange(
	t *testing.T,
	handler http.Handler,
	method, path, cookie string,
	body any,
) httpResult {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(raw))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
		request.Header.Set("Origin", testBaseURL)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var value any
	if err := json.Unmarshal(recorder.Body.Bytes(), &value); err != nil {
		t.Fatalf("decode status=%d body=%q: %v", recorder.Code, recorder.Body.String(), err)
	}
	return httpResult{status: recorder.Code, headers: recorder.Header(), value: value}
}

func signUp(t *testing.T, auth *singleauth.Auth, cookie, email string) (httpResult, string, string) {
	t.Helper()
	result := exchange(t, auth.Handler(), http.MethodPost, "/sign-up/email", cookie, map[string]any{
		"name": "Test User", "email": email, "password": "password123",
	})
	if result.status != http.StatusOK {
		t.Fatalf("sign-up %s status=%d body=%#v", email, result.status, result.value)
	}
	active := responseCookieBySuffix(result.headers.Values("Set-Cookie"), ".session_token")
	if active == nil {
		t.Fatalf("sign-up %s active cookie missing: %#v", email, result.headers.Values("Set-Cookie"))
	}
	token := unsignedCookieToken(active.Attributes.Value)
	return result, cookies.ApplySetCookies(cookie, result.headers.Values("Set-Cookie")), token
}

func signIn(t *testing.T, auth *singleauth.Auth, cookie, email string) (httpResult, string, string) {
	t.Helper()
	result := exchange(t, auth.Handler(), http.MethodPost, "/sign-in/email", cookie, map[string]any{
		"email": email, "password": "password123",
	})
	if result.status != http.StatusOK {
		t.Fatalf("sign-in %s status=%d body=%#v", email, result.status, result.value)
	}
	active := responseCookieBySuffix(result.headers.Values("Set-Cookie"), ".session_token")
	if active == nil {
		t.Fatalf("sign-in %s active cookie missing: %#v", email, result.headers.Values("Set-Cookie"))
	}
	return result, cookies.ApplySetCookies(cookie, result.headers.Values("Set-Cookie")), unsignedCookieToken(active.Attributes.Value)
}

func responseCookieBySuffix(lines []string, suffix string) *cookies.SetCookie {
	for _, line := range lines {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if len(parsed.Name) >= len(suffix) && parsed.Name[len(parsed.Name)-len(suffix):] == suffix {
				value := parsed
				return &value
			}
		}
	}
	return nil
}

func responseCookie(lines []string, name string) *cookies.SetCookie {
	for _, line := range lines {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == name {
				value := parsed
				return &value
			}
		}
	}
	return nil
}

func unsignedCookieToken(signed string) string {
	for index := len(signed) - 1; index >= 0; index-- {
		if signed[index] == '.' {
			return signed[:index]
		}
	}
	return ""
}

func valueObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want object", value)
	}
	return object
}

func valueArray(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("value = %#v, want array", value)
	}
	return array
}

func directRequest(method, path, cookie string, body any) contract.Request {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	headers := contract.Headers{}
	if cookie != "" {
		headers.Set("Cookie", cookie)
		headers.Set("Origin", testBaseURL)
	}
	return contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Scheme: "http", Host: "auth.example.test", Headers: headers, Body: raw,
	})
}

type secondaryStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newSecondaryStore() *secondaryStore {
	return &secondaryStore{values: make(map[string]string)}
}

func (store *secondaryStore) Get(_ context.Context, key string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.values[key], nil
}

func (store *secondaryStore) Set(_ context.Context, key, value string, _ int64) error {
	store.mu.Lock()
	store.values[key] = value
	store.mu.Unlock()
	return nil
}

func (store *secondaryStore) Delete(_ context.Context, key string) error {
	store.mu.Lock()
	delete(store.values, key)
	store.mu.Unlock()
	return nil
}

func (store *secondaryStore) has(key string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	_, exists := store.values[key]
	return exists
}
