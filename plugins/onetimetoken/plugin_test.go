package onetimetoken_test

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
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/onetimetoken"
	"github.com/pers0na2dev/single-auth/storage"
)

const testSecret = "0123456789abcdef0123456789abcdef"

type response struct {
	status  int
	headers http.Header
	value   any
}

func TestOneTimeTokenGenerateVerifyReplayAndConcurrency(t *testing.T) {
	auth := newAuth(t, onetimetoken.Options{}, nil)
	cookie := signUp(t, auth, "ott-basic@example.com")
	token := generate(t, auth, cookie)
	verified := call(t, auth, http.MethodPost, "/one-time-token/verify", "", map[string]any{"token": token})
	if verified.status != http.StatusOK {
		t.Fatalf("verify status=%d value=%#v", verified.status, verified.value)
	}
	object := verified.value.(map[string]any)
	if object["session"] == nil || object["user"] == nil || len(verified.headers.Values("Set-Cookie")) == 0 {
		t.Fatalf("verify response=%#v headers=%v", object, verified.headers)
	}
	replayed := call(t, auth, http.MethodPost, "/one-time-token/verify", "", map[string]any{"token": token})
	assertError(t, replayed, http.StatusBadRequest, "BAD_REQUEST", "Invalid token")

	concurrentToken := generate(t, auth, cookie)
	statuses := make(chan int, 16)
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- callRaw(auth, http.MethodPost, "/one-time-token/verify", "", map[string]any{
				"token": concurrentToken,
			}).status
		}()
	}
	wait.Wait()
	close(statuses)
	successes := 0
	failures := 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
			failures++
		default:
			t.Fatalf("concurrent verify status=%d", status)
		}
	}
	if successes != 1 || failures != 15 {
		t.Fatalf("concurrent successes=%d failures=%d", successes, failures)
	}
}

func TestOneTimeTokenExpiryAndUnderlyingSessionExpiry(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	short := time.Minute
	auth := newAuth(t, onetimetoken.Options{ExpiresIn: &short}, func() time.Time { return now })
	cookie := signUp(t, auth, "ott-expiry@example.com")
	token := generate(t, auth, cookie)
	now = now.Add(2 * time.Minute)
	expired := call(t, auth, http.MethodPost, "/one-time-token/verify", "", map[string]any{"token": token})
	assertError(t, expired, http.StatusBadRequest, "BAD_REQUEST", "Invalid token")

	now = time.Date(2026, 8, 8, 13, 0, 0, 0, time.UTC)
	long := 10 * time.Minute
	auth = newAuthWithSessionExpiry(t, onetimetoken.Options{ExpiresIn: &long}, func() time.Time { return now }, time.Minute)
	cookie = signUp(t, auth, "ott-session-expiry@example.com")
	token = generate(t, auth, cookie)
	now = now.Add(2 * time.Minute)
	sessionExpired := call(t, auth, http.MethodPost, "/one-time-token/verify", "", map[string]any{"token": token})
	assertError(t, sessionExpired, http.StatusBadRequest, "BAD_REQUEST", "Session expired")
	if len(sessionExpired.headers.Values("Set-Cookie")) == 0 {
		t.Fatal("upstream sets the session cookie before checking the underlying session expiry")
	}
}

func TestOneTimeTokenStorageModes(t *testing.T) {
	tests := []struct {
		name       string
		storage    onetimetoken.TokenStorage
		identifier string
	}{
		{
			name:       "hashed",
			storage:    onetimetoken.TokenStorage{Mode: onetimetoken.StoreHashed},
			identifier: "one-time-token:jZae727K08KaOmKSgOaGzww_XVqGr_PKEgIMkjrcbJI",
		},
		{
			name: "custom",
			storage: onetimetoken.TokenStorage{
				Mode:       onetimetoken.StoreCustom,
				CustomHash: func(_ context.Context, token string) (string, error) { return token + "hashed", nil },
			},
			identifier: "one-time-token:123456hashed",
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := newAuth(t, onetimetoken.Options{
				Storage: test.storage,
				GenerateToken: func(*engine.Context, onetimetoken.SessionState) (string, error) {
					return "123456", nil
				},
			}, nil)
			cookie := signUp(t, auth, "ott-storage-"+string(rune('a'+index))+"@example.com")
			if got := generate(t, auth, cookie); got != "123456" {
				t.Fatalf("generated token=%q", got)
			}
			stored, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
				Model: "verification", Where: []storage.Where{{Field: "identifier", Value: test.identifier}},
			})
			if err != nil || stored == nil {
				t.Fatalf("stored verification=%#v err=%v", stored, err)
			}
			verified := call(t, auth, http.MethodPost, "/one-time-token/verify", "", map[string]any{"token": "123456"})
			if verified.status != http.StatusOK {
				t.Fatalf("verify status=%d value=%#v", verified.status, verified.value)
			}
		})
	}
}

func TestOneTimeTokenClientCookieAndHeaderOptions(t *testing.T) {
	disabled := newAuth(t, onetimetoken.Options{DisableClientRequest: true}, nil)
	cookie := signUp(t, disabled, "ott-disabled-client@example.com")
	httpResult := call(t, disabled, http.MethodGet, "/one-time-token/generate", cookie, nil)
	assertError(t, httpResult, http.StatusBadRequest, "BAD_REQUEST", "Client requests are disabled")
	directHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie})
	direct, err := disabled.API().Call(t.Context(), "generateOneTimeToken", singleauth.DirectCallInput{
		Method: http.MethodGet, Headers: directHeaders,
	})
	if err != nil || direct.Response.Status() != http.StatusOK || direct.Value.(map[string]any)["token"] == nil {
		t.Fatalf("direct result=%#v err=%v", direct, err)
	}

	withoutCookie := newAuth(t, onetimetoken.Options{DisableSetSessionCookie: true}, nil)
	cookie = signUp(t, withoutCookie, "ott-no-cookie@example.com")
	token := generate(t, withoutCookie, cookie)
	verified := call(t, withoutCookie, http.MethodPost, "/one-time-token/verify", "", map[string]any{"token": token})
	if verified.status != http.StatusOK || len(verified.headers.Values("Set-Cookie")) != 0 {
		t.Fatalf("disabled cookie status=%d headers=%v", verified.status, verified.headers)
	}

	headerAuth := newAuth(t, onetimetoken.Options{SetOTTHeaderOnNewSession: true}, nil)
	signedUp := call(t, headerAuth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "OTT Header", "email": "ott-header@example.com", "password": "password123",
	})
	headerToken := signedUp.headers.Get("Set-Ott")
	if signedUp.status != http.StatusOK || len(headerToken) != 32 ||
		!strings.Contains(signedUp.headers.Get("Access-Control-Expose-Headers"), "set-ott") {
		t.Fatalf("header sign-up status=%d token=%q headers=%v", signedUp.status, headerToken, signedUp.headers)
	}
	headerVerified := call(t, headerAuth, http.MethodPost, "/one-time-token/verify", "", map[string]any{"token": headerToken})
	if headerVerified.status != http.StatusOK {
		t.Fatalf("header token verify status=%d value=%#v", headerVerified.status, headerVerified.value)
	}

	defaultAuth := newAuth(t, onetimetoken.Options{}, nil)
	defaultSignUp := call(t, defaultAuth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "No Header", "email": "ott-no-header@example.com", "password": "password123",
	})
	if defaultSignUp.headers.Get("Set-Ott") != "" {
		t.Fatalf("unexpected default OTT header=%q", defaultSignUp.headers.Get("Set-Ott"))
	}
}

func TestOneTimeTokenValidation(t *testing.T) {
	auth := newAuth(t, onetimetoken.Options{}, nil)
	for _, body := range []any{map[string]any{}, map[string]any{"token": 42}, nil} {
		result := call(t, auth, http.MethodPost, "/one-time-token/verify", "", body)
		if result.status != http.StatusBadRequest {
			t.Fatalf("body=%#v status=%d value=%#v", body, result.status, result.value)
		}
	}
}

func newAuth(t *testing.T, options onetimetoken.Options, clock func() time.Time) *singleauth.Auth {
	t.Helper()
	return newAuthWithSessionExpiry(t, options, clock, 0)
}

func newAuthWithSessionExpiry(
	t *testing.T,
	options onetimetoken.Options,
	clock func() time.Time,
	sessionExpiry time.Duration,
) *singleauth.Auth {
	t.Helper()
	disabled := false
	return singleauth.MustNew(singleauth.Options{
		Secret:           testSecret,
		BaseURL:          "http://auth.test",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Session:          singleauth.SessionOptions{ExpiresIn: sessionExpiry},
		Clock:            clock,
		RateLimit:        singleauth.RateLimitOptions{Enabled: &disabled},
		PluginFactories:  []singleauth.PluginFactory{onetimetoken.NewFactory(options)},
	})
}

func signUp(t *testing.T, auth *singleauth.Auth, email string) string {
	t.Helper()
	result := call(t, auth, http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "OTT User", "email": email, "password": "password123",
	})
	if result.status != http.StatusOK {
		t.Fatalf("sign up status=%d value=%#v", result.status, result.value)
	}
	return cookies.ApplySetCookies("", result.headers.Values("Set-Cookie"))
}

func generate(t *testing.T, auth *singleauth.Auth, cookie string) string {
	t.Helper()
	result := call(t, auth, http.MethodGet, "/one-time-token/generate", cookie, nil)
	if result.status != http.StatusOK {
		t.Fatalf("generate status=%d value=%#v", result.status, result.value)
	}
	token, _ := result.value.(map[string]any)["token"].(string)
	if token == "" {
		t.Fatalf("generate value=%#v", result.value)
	}
	return token
}

func call(
	t *testing.T,
	auth *singleauth.Auth,
	method, path, cookie string,
	body any,
) response {
	t.Helper()
	result := callRaw(auth, method, path, cookie, body)
	if result.value == nil && result.status != http.StatusNoContent {
		t.Fatalf("empty response status=%d", result.status)
	}
	return result
}

func callRaw(auth *singleauth.Auth, method, path, cookie string, body any) response {
	var encoded []byte
	if body != nil {
		encoded, _ = json.Marshal(body)
	}
	request := httptest.NewRequest(method, "http://auth.test/api/auth"+path, bytes.NewReader(encoded))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	var value any
	if recorder.Body.Len() > 0 {
		decoder := json.NewDecoder(recorder.Body)
		decoder.UseNumber()
		_ = decoder.Decode(&value)
	}
	return response{status: recorder.Code, headers: recorder.Header().Clone(), value: value}
}

func assertError(t *testing.T, result response, status int, code, message string) {
	t.Helper()
	object, _ := result.value.(map[string]any)
	if result.status != status || object["code"] != code || object["message"] != message {
		t.Fatalf("error status=%d value=%#v", result.status, result.value)
	}
}
