package core

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestGetSessionCacheHeadersAndDeferredRefresh(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	zero := time.Duration(0)
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Session: SessionOptions{
			UpdateAge:           &zero,
			DeferSessionRefresh: true,
		},
		Clock: func() time.Time { return now },
	})

	cookieHeader, _, initial := createSessionTestUser(t, auth, "defer@example.com")
	initialExpiry := objectString(t, objectValue(t, initial, "session"), "expiresAt")
	now = now.Add(time.Minute)

	status, headers, value := sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /get-session status = %d, body = %#v", status, value)
	}
	if headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %#v", headers)
	}
	object := value.(map[string]any)
	if object["needsRefresh"] != true {
		t.Fatalf("needsRefresh = %#v", object["needsRefresh"])
	}
	if got := objectString(t, objectValue(t, object, "session"), "expiresAt"); got != initialExpiry {
		t.Fatalf("read-only GET changed expiry: %s != %s", got, initialExpiry)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/get-session", cookieHeader, map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("POST /get-session status = %d, body = %#v", status, value)
	}
	refreshed := objectString(t, objectValue(t, value.(map[string]any), "session"), "expiresAt")
	if refreshed == initialExpiry {
		t.Fatal("deferred POST did not refresh session")
	}

	plain := MustNew(Options{Secret: "0123456789abcdef0123456789abcdef"})
	status, headers, value = sessionTestRequest(t, plain, http.MethodPost, "/get-session", "", map[string]any{})
	if status != http.StatusMethodNotAllowed {
		t.Fatalf("POST without defer status = %d, body = %#v", status, value)
	}
	errorObject := value.(map[string]any)
	if errorObject["code"] != string(ErrorMethodNeedsDeferredSession) {
		t.Fatalf("POST without defer code = %#v", errorObject["code"])
	}
	if headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache" {
		t.Fatalf("method error cache headers = %#v", headers)
	}
}

func TestListAndRevokeSessionBehavior(t *testing.T) {
	now := time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Clock:            func() time.Time { return now },
	})

	cookieOne, tokenOne, _ := createSessionTestUser(t, auth, "sessions@example.com")
	cookieTwo, _, _ := signInSessionTestUser(t, auth, "sessions@example.com")

	status, _, value := sessionTestRequest(t, auth, http.MethodGet, "/list-sessions", cookieTwo, nil)
	list, ok := value.([]any)
	if status != http.StatusOK || !ok || len(list) != 2 {
		t.Fatalf("list sessions status=%d value=%#v", status, value)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/revoke-session", cookieTwo, map[string]any{"token": tokenOne})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("revoke session status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieOne, nil)
	if status != http.StatusOK || value != nil {
		t.Fatalf("revoked session remains valid: status=%d value=%#v", status, value)
	}

	_, _, _ = signInSessionTestUser(t, auth, "sessions@example.com")
	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/revoke-other-sessions", cookieTwo, map[string]any{})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("revoke other sessions status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/list-sessions", cookieTwo, nil)
	list, ok = value.([]any)
	if status != http.StatusOK || !ok || len(list) != 1 {
		t.Fatalf("list after revoke others status=%d value=%#v", status, value)
	}

	status, _, value = sessionTestRequest(t, auth, http.MethodPost, "/revoke-sessions", cookieTwo, map[string]any{})
	if status != http.StatusOK || value.(map[string]any)["status"] != true {
		t.Fatalf("revoke all sessions status=%d value=%#v", status, value)
	}
	status, _, value = sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieTwo, nil)
	if status != http.StatusOK || value != nil {
		t.Fatalf("revoke all left current session: status=%d value=%#v", status, value)
	}
}

func TestSessionFreshnessAndAuthoritativeRevoke(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	freshAge := time.Minute
	auth := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Session:          SessionOptions{FreshAge: &freshAge},
		Clock:            func() time.Time { return now },
	})
	cookieHeader, _, _ := createSessionTestUser(t, auth, "fresh@example.com")
	now = now.Add(2 * time.Minute)
	status, _, value := sessionTestRequest(t, auth, http.MethodGet, "/list-sessions", cookieHeader, nil)
	if status != http.StatusForbidden || value.(map[string]any)["code"] != string(ErrorSessionNotFresh) {
		t.Fatalf("stale session status=%d value=%#v", status, value)
	}

	now = time.Date(2026, 8, 8, 11, 0, 0, 0, time.UTC)
	zero := time.Duration(0)
	longExpiry := 3 * 365 * 24 * time.Hour
	alwaysFresh := MustNew(Options{
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: EmailAndPasswordOptions{Enabled: true},
		Session: SessionOptions{
			ExpiresIn: longExpiry,
			FreshAge:  &zero,
			CookieCache: CookieCacheOptions{
				Enabled: true,
				MaxAge:  2 * 365 * 24 * time.Hour,
			},
		},
		Clock: func() time.Time { return now },
	})
	cachedCookies, token, _ := createSessionTestUser(t, alwaysFresh, "cache@example.com")
	now = now.Add(365 * 24 * time.Hour)
	status, _, value = sessionTestRequest(t, alwaysFresh, http.MethodGet, "/list-sessions", cachedCookies, nil)
	if status != http.StatusOK {
		t.Fatalf("freshAge=0 status=%d value=%#v", status, value)
	}

	if err := alwaysFresh.Adapter().Delete(t.Context(), storage.DeleteParams{
		Model: "session", Where: []storage.Where{{Field: "token", Value: token}},
	}); err != nil {
		t.Fatal(err)
	}
	status, _, value = sessionTestRequest(t, alwaysFresh, http.MethodPost, "/revoke-sessions", cachedCookies, map[string]any{})
	if status != http.StatusUnauthorized || value.(map[string]any)["code"] != "UNAUTHORIZED" {
		t.Fatalf("stale cache authorized sensitive revoke: status=%d value=%#v", status, value)
	}
}

func createSessionTestUser(t *testing.T, auth *Auth, email string) (string, string, map[string]any) {
	t.Helper()
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Session User", "email": email, "password": "password123",
	})
	if status != http.StatusOK {
		t.Fatalf("sign up status=%d value=%#v", status, value)
	}
	result := value.(map[string]any)
	token := objectString(t, result, "token")
	cookieHeader := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	status, _, sessionValue := sessionTestRequest(t, auth, http.MethodGet, "/get-session", cookieHeader, nil)
	if status != http.StatusOK || sessionValue == nil {
		t.Fatalf("initial session status=%d value=%#v", status, sessionValue)
	}
	return cookieHeader, token, sessionValue.(map[string]any)
}

func signInSessionTestUser(t *testing.T, auth *Auth, email string) (string, string, map[string]any) {
	t.Helper()
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": email, "password": "password123",
	})
	if status != http.StatusOK {
		t.Fatalf("sign in status=%d value=%#v", status, value)
	}
	result := value.(map[string]any)
	return cookies.ApplySetCookies("", headers.Values("Set-Cookie")), objectString(t, result, "token"), result
}

func sessionTestRequest(
	t *testing.T,
	auth *Auth,
	method, path, cookieHeader string,
	body map[string]any,
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
	request := httptest.NewRequest(method, "http://auth.test/api/auth"+path, bytes.NewReader(encoded))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookieHeader != "" {
		request.Header.Set("Cookie", cookieHeader)
		if method != http.MethodGet && method != http.MethodHead {
			request.Header.Set("Origin", "http://auth.test")
		}
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	var value any
	if strings.TrimSpace(recorder.Body.String()) != "" {
		decoder := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes()))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatalf("decode response %s: %v", recorder.Body.String(), err)
		}
	}
	return recorder.Code, recorder.Header().Clone(), value
}

func objectValue(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not object: %#v", key, object[key])
	}
	return value
}

func objectString(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("%s is not string: %#v", key, object[key])
	}
	return value
}
