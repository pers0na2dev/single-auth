package redis_e2e_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "modernc.org/sqlite"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	redisstore "github.com/pers0na2dev/single-auth/storage/secondary/redis"
)

type redisSmokeScenario struct {
	Title    string
	Expected any
}

type redisSmokeSessionObservation struct {
	TokenPresent          bool `json:"tokenPresent"`
	KeyCount              int  `json:"keyCount"`
	ActiveSessionKeyCount int  `json:"activeSessionKeyCount"`
	SessionValuePresent   bool `json:"sessionValuePresent"`
	UserIDPresent         bool `json:"userIDPresent"`
	SessionIDPresent      bool `json:"sessionIDPresent"`
}

type redisSmokeOAuthObservation struct {
	SignInStatus                     int    `json:"signInStatus"`
	AuthorizationURLPresent          bool   `json:"authorizationURLPresent"`
	AuthorizationURLIncludesGoogle   bool   `json:"authorizationURLIncludesGoogle"`
	StatePresent                     bool   `json:"statePresent"`
	StateCookiePresent               bool   `json:"stateCookiePresent"`
	CallbackStatus                   int    `json:"callbackStatus"`
	CallbackLocationPresent          bool   `json:"callbackLocationPresent"`
	CallbackLocationIncludesCallback bool   `json:"callbackLocationIncludesCallback"`
	KeyCount                         int    `json:"keyCount"`
	ActiveSessionKeyCount            int    `json:"activeSessionKeyCount"`
	SessionValuePresent              bool   `json:"sessionValuePresent"`
	UserIDPresent                    bool   `json:"userIDPresent"`
	SessionIDPresent                 bool   `json:"sessionIDPresent"`
	UserEmail                        string `json:"userEmail"`
}

type redisSmokeCustomEndpointObservation struct {
	Status                        int  `json:"status"`
	URLPresent                    bool `json:"urlPresent"`
	IncludesCustomEndpoint        bool `json:"includesCustomEndpoint"`
	ExcludesDefaultGoogleEndpoint bool `json:"excludesDefaultGoogleEndpoint"`
	IncludesLocalhost8080         bool `json:"includesLocalhost8080"`
}

func TestRedisSecondaryStorageSmokeBehavior(t *testing.T) {
	if len(redisSmokeScenarios) != 4 {
		t.Fatalf("Redis smoke scenarios=%d, want 4", len(redisSmokeScenarios))
	}
	client := startRedisSmokeServer(t)
	prefix := "single-auth:single-auth-1.6.26:redis-smoke|"
	store, err := redisstore.New(commander{client: client}, redisstore.Options{
		KeyPrefix: redisstore.Prefix(prefix),
		IsNotFound: func(err error) bool {
			return errors.Is(err, goredis.Nil)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for index, scenario := range redisSmokeScenarios {
		index, scenario := index, scenario
		t.Run(scenario.Title, func(t *testing.T) {
			if err := client.FlushAll(t.Context()).Err(); err != nil {
				t.Fatalf("flush Redis before nested smoke scenario: %v", err)
			}
			var actual any
			switch index {
			case 0:
				actual = observeRedisSmokeEmailSignup(t, store, false)
			case 1:
				actual = observeRedisSmokeEmailSignup(t, store, true)
			case 2:
				actual = observeRedisSmokeStatelessGoogleOAuth(t, store)
			case 3:
				actual = observeRedisSmokeCustomGoogleEndpoint(t, store)
			default:
				t.Fatalf("unexpected Redis smoke nested scenario %d", index)
			}
			assertRedisSmokeObservation(t, actual, scenario.Expected)
		})
	}
}

func observeRedisSmokeEmailSignup(
	t *testing.T,
	store *redisstore.Store,
	storeSessionInDatabase bool,
) redisSmokeSessionObservation {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+strings.ReplaceAll(t.Name(), "/", "-")+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Errorf("close SQLite: %v", closeErr)
		}
	})
	auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
		BaseURL:          "http://localhost:3000",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		SecondaryStorage: store,
		Session: singleauth.SessionOptions{
			StoreSessionInDatabase: storeSessionInDatabase,
		},
	}, database)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.RunMigrationsContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	result, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Email: "himself65@outlook.com", Password: "123456789", Name: "Alex Yang",
	})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return observeRedisSmokeSession(t, store, keys, result.Token != nil && *result.Token != "")
}

func observeRedisSmokeStatelessGoogleOAuth(
	t *testing.T,
	store *redisstore.Store,
) redisSmokeOAuthObservation {
	t.Helper()
	provider, err := providers.Google(providers.Options{
		ClientID: "demo", ClientSecret: "demo-secret",
		HTTPClient: &http.Client{Transport: redisSmokeGoogleTokenTransport(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	storeAccountCookie := true
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000",
		Secret:  "single-auth-secret-123456789",
		Session: singleauth.SessionOptions{
			Stateless: true,
			CookieCache: singleauth.CookieCacheOptions{
				Enabled: true, MaxAge: 7 * 24 * time.Hour, Strategy: "jwe",
			},
		},
		Account: singleauth.AccountOptions{
			StoreStateStrategy: "cookie", StoreAccountCookie: &storeAccountCookie,
		},
		SocialProviders:  map[string]*providers.Provider{"google": provider},
		SecondaryStorage: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	signInStatus, authorizationURL, signInHeaders := redisSmokeSocialSignIn(
		t, auth, "/callback",
	)
	urlPresent := authorizationURL != ""
	state := ""
	if urlPresent {
		parsed, parseErr := http.NewRequest(http.MethodGet, authorizationURL, nil)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		state = parsed.URL.Query().Get("state")
	}
	setCookies := signInHeaders.Values("Set-Cookie")
	cookieHeader := cookies.ApplySetCookies("", setCookies)
	callbackURL := "http://localhost:3000/api/auth/callback/google?state=" + state + "&code=test-authorization-code"
	request := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	if cookieHeader != "" {
		request.Header.Set("Cookie", cookieHeader)
	}
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, request)
	keys, err := store.ListKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	session := observeRedisSmokeSession(t, store, keys, false)
	userEmail := ""
	if sessionKey := redisSmokeSessionKey(keys); sessionKey != "" {
		value, getErr := store.Get(t.Context(), sessionKey)
		if getErr != nil {
			t.Fatal(getErr)
		}
		var payload struct {
			User struct {
				Email string `json:"email"`
			} `json:"user"`
		}
		if value != "" {
			if err := json.Unmarshal([]byte(value), &payload); err != nil {
				t.Fatal(err)
			}
			userEmail = payload.User.Email
		}
	}
	location := recorder.Header().Get("Location")
	return redisSmokeOAuthObservation{
		SignInStatus:                     signInStatus,
		AuthorizationURLPresent:          urlPresent && authorizationURL != "",
		AuthorizationURLIncludesGoogle:   strings.Contains(authorizationURL, "google.com"),
		StatePresent:                     state != "",
		StateCookiePresent:               len(setCookies) != 0,
		CallbackStatus:                   recorder.Code,
		CallbackLocationPresent:          location != "",
		CallbackLocationIncludesCallback: strings.Contains(location, "/callback"),
		KeyCount:                         session.KeyCount,
		ActiveSessionKeyCount:            session.ActiveSessionKeyCount,
		SessionValuePresent:              session.SessionValuePresent,
		UserIDPresent:                    session.UserIDPresent,
		SessionIDPresent:                 session.SessionIDPresent,
		UserEmail:                        userEmail,
	}
}

func observeRedisSmokeCustomGoogleEndpoint(
	t *testing.T,
	store *redisstore.Store,
) redisSmokeCustomEndpointObservation {
	t.Helper()
	const endpoint = "http://localhost:8080/custom-oauth/authorize"
	provider, err := providers.Google(providers.Options{
		ClientID: "test-client-id", ClientSecret: "test-client-secret",
		AuthorizationEndpoint: endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "http://localhost:3000",
		Secret:           "single-auth-secret-123456789",
		Session:          singleauth.SessionOptions{Stateless: true},
		SocialProviders:  map[string]*providers.Provider{"google": provider},
		SecondaryStorage: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	status, value, _ := redisSmokeSocialSignIn(t, auth, "/dashboard")
	return redisSmokeCustomEndpointObservation{
		Status:                        status,
		URLPresent:                    value != "",
		IncludesCustomEndpoint:        strings.Contains(value, endpoint),
		ExcludesDefaultGoogleEndpoint: !strings.Contains(value, "accounts.google.com"),
		IncludesLocalhost8080:         strings.Contains(value, "localhost:8080"),
	}
}

func redisSmokeSocialSignIn(
	t *testing.T,
	auth *singleauth.Auth,
	callbackURL string,
) (int, string, http.Header) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider": "google", "callbackURL": callbackURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"http://localhost:3000/api/auth/sign-in/social",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	auth.Handler().ServeHTTP(recorder, request)
	var response struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode social sign-in status=%d body=%s: %v", recorder.Code, recorder.Body.Bytes(), err)
	}
	return recorder.Code, response.URL, recorder.Header().Clone()
}

func observeRedisSmokeSession(
	t *testing.T,
	store *redisstore.Store,
	keys []string,
	tokenPresent bool,
) redisSmokeSessionObservation {
	t.Helper()
	sessionKey := redisSmokeSessionKey(keys)
	value := ""
	if sessionKey != "" {
		var err error
		value, err = store.Get(t.Context(), sessionKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	var payload struct {
		User    map[string]any `json:"user"`
		Session map[string]any `json:"session"`
	}
	if value != "" {
		if err := json.Unmarshal([]byte(value), &payload); err != nil {
			t.Fatal(err)
		}
	}
	activeCount := 0
	for _, key := range keys {
		if strings.HasPrefix(key, "active-sessions") {
			activeCount++
		}
	}
	userID, _ := payload.User["id"].(string)
	sessionID, _ := payload.Session["id"].(string)
	return redisSmokeSessionObservation{
		TokenPresent: tokenPresent, KeyCount: len(keys), ActiveSessionKeyCount: activeCount,
		SessionValuePresent: value != "", UserIDPresent: userID != "", SessionIDPresent: sessionID != "",
	}
}

func redisSmokeSessionKey(keys []string) string {
	for _, key := range keys {
		if !strings.HasPrefix(key, "active-sessions") {
			return key
		}
	}
	return ""
}

func redisSmokeGoogleTokenTransport(t *testing.T) http.RoundTripper {
	t.Helper()
	token, err := baCrypto.SignJWT(map[string]any{
		"email": "google-user@example.com", "email_verified": true,
		"name": "Google Test User", "picture": "https://lh3.googleusercontent.com/a-/test",
		"sub": "google-1234567890", "aud": "test", "azp": "test", "iss": "test",
	}, "single-auth-secret-123456789", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://oauth2.googleapis.com/token" {
			return nil, fmt.Errorf("unexpected Google smoke request %s", request.URL)
		}
		body, err := json.Marshal(map[string]any{
			"access_token": "test-access-token", "refresh_token": "test-refresh-token",
			"id_token": token, "token_type": "Bearer", "expires_in": 3600,
		})
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(bytes.NewReader(body)), Request: request,
		}, nil
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func assertRedisSmokeObservation(t *testing.T, actual, expected any) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Redis smoke observation=%#v want=%#v", actual, expected)
	}
}

func startRedisSmokeServer(t *testing.T) *goredis.Client {
	t.Helper()
	ctx := t.Context()
	container, err := testcontainers.Run(
		ctx,
		redisImage,
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithOccurrence(1).
				WithStartupTimeout(45*time.Second),
		),
	)
	if err != nil {
		if os.Getenv("SINGLE_AUTH_E2E_REQUIRED") == "1" {
			t.Fatalf("start required Redis smoke container: %v", err)
		}
		t.Skipf("Docker is unavailable for reference implementation Redis smoke behavior: %v", err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			logs, logErr := container.Logs(context.Background())
			if logErr == nil {
				defer logs.Close()
				if output, readErr := io.ReadAll(logs); readErr == nil {
					t.Logf("Redis smoke container logs:\n%s", output)
				}
			}
		}
		if terminateErr := testcontainers.TerminateContainer(container); terminateErr != nil {
			t.Errorf("terminate Redis smoke container: %v", terminateErr)
		}
	})
	host, err := container.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	port, err := container.MappedPort(ctx, "6379/tcp")
	if err != nil {
		t.Fatal(err)
	}
	client := goredis.NewClient(&goredis.Options{Addr: net.JoinHostPort(host, port.Port())})
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("close Redis smoke client: %v", closeErr)
		}
	})
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping Redis smoke server: %v", err)
	}
	return client
}
