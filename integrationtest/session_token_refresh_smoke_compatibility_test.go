package singleauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

type sessionTokenRefreshObservation struct {
	ExpiresIn                     int    `json:"expiresIn"`
	CookieCacheMaxAge             int    `json:"cookieCacheMaxAge"`
	DefaultRefreshUpdateAge       int    `json:"defaultRefreshUpdateAge"`
	AdvancedSeconds               int    `json:"advancedSeconds"`
	SignInStatus                  int    `json:"signInStatus"`
	AuthorizationURLPresent       bool   `json:"authorizationURLPresent"`
	StatePresent                  bool   `json:"statePresent"`
	CallbackStatus                int    `json:"callbackStatus"`
	CallbackSessionTokenPresent   bool   `json:"callbackSessionTokenPresent"`
	FirstSessionStatus            int    `json:"firstSessionStatus"`
	FirstSessionPresent           bool   `json:"firstSessionPresent"`
	FirstSessionEmail             string `json:"firstSessionEmail"`
	RefreshStatus                 int    `json:"refreshStatus"`
	RefreshSessionPresent         bool   `json:"refreshSessionPresent"`
	RefreshSessionEmail           string `json:"refreshSessionEmail"`
	RefreshedSessionTokenPresent  bool   `json:"refreshedSessionTokenPresent"`
	RefreshedSessionTokenMaxAge   int    `json:"refreshedSessionTokenMaxAge"`
	SessionTokenUnchanged         bool   `json:"sessionTokenUnchanged"`
	LogicalSessionExpiryUnchanged bool   `json:"logicalSessionExpiryUnchanged"`
	TokenEndpointCalls            int    `json:"tokenEndpointCalls"`
}

func TestSessionTokenRefreshSmokeBehavior(t *testing.T) {
	want := sessionTokenRefreshExpected()
	transports := []struct {
		name     string
		exchange string
	}{
		{name: "net/http", exchange: "net-http"},
		{name: "fasthttp", exchange: "fasthttp"},
		{name: "fiber", exchange: "fiber"},
	}
	for _, transport := range transports {
		transport := transport
		t.Run(transport.name, func(t *testing.T) {
			actual := observeGoSessionTokenRefresh(t, transport.exchange, want)
			if !reflect.DeepEqual(actual, want) {
				t.Fatalf(
					"%s session-token refresh observation = %#v, want %#v",
					transport.name,
					actual,
					want,
				)
			}
		})
	}
}

func observeGoSessionTokenRefresh(
	t *testing.T,
	transport string,
	want sessionTokenRefreshObservation,
) sessionTokenRefreshObservation {
	t.Helper()
	now := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	tokenEndpointCalls := 0
	idToken, err := baCrypto.SignJWTAt(map[string]any{
		"email": "google-user@example.com", "email_verified": true,
		"name": "Google Test User", "picture": "https://lh3.googleusercontent.com/a-/test",
		"sub": "google-1234567890", "aud": "test", "azp": "test",
		"iss": "test", "locale": "en", "jti": "test",
		"given_name": "Google Test", "family_name": "User",
	}, "single-auth-secret-123456789", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := providers.Google(providers.Options{
		ClientID: "demo", ClientSecret: "demo-secret",
		HTTPClient: &http.Client{Transport: sessionTokenRefreshRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != "https://oauth2.googleapis.com/token" || request.Method != http.MethodPost {
				t.Fatalf("unexpected Google token request %s %s", request.Method, request.URL)
			}
			tokenEndpointCalls++
			body, marshalErr := json.Marshal(map[string]any{
				"access_token": "test-access-token", "refresh_token": "test-refresh-token",
				"id_token": idToken, "token_type": "Bearer", "expires_in": 3600,
			})
			if marshalErr != nil {
				return nil, marshalErr
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)),
				Request:    request,
			}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	storeAccountCookie := true
	updateAge := 2 * time.Minute
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000",
		Secret:  "single-auth-secret-123456789",
		Session: singleauth.SessionOptions{
			Stateless: true,
			ExpiresIn: time.Duration(want.ExpiresIn) * time.Second,
			UpdateAge: &updateAge,
			CookieCache: singleauth.CookieCacheOptions{
				Enabled: true, MaxAge: time.Duration(want.CookieCacheMaxAge) * time.Second,
				Strategy: "jwe", RefreshCache: true,
			},
		},
		Account: singleauth.AccountOptions{
			StoreStateStrategy: "cookie", StoreAccountCookie: &storeAccountCookie,
		},
		SocialProviders: map[string]*providers.Provider{"google": provider},
		Clock:           func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange := newOAuthStateExchange(t, transport, auth)

	signInBody, err := json.Marshal(map[string]any{
		"provider": "google", "callbackURL": "/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	signInStatus, signInHeaders, encodedSignIn, err := exchange(
		http.MethodPost,
		"/api/auth/sign-in/social",
		http.Header{
			"Content-Type": {"application/json"},
			"Origin":       {"http://localhost:3000"},
		},
		signInBody,
	)
	if err != nil {
		t.Fatal(err)
	}
	var signIn struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(encodedSignIn, &signIn); err != nil {
		t.Fatalf("decode sign-in status=%d body=%s: %v", signInStatus, encodedSignIn, err)
	}
	authorizationURL, err := url.Parse(signIn.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := authorizationURL.Query().Get("state")
	stateCookieHeader := cookies.ApplySetCookies("", signInHeaders.Values("Set-Cookie"))

	callbackStatus, callbackHeaders, callbackBody, err := exchange(
		http.MethodGet,
		"/api/auth/callback/google?state="+url.QueryEscape(state)+"&code=test-code",
		http.Header{"Cookie": {stateCookieHeader}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(callbackBody) != 0 {
		t.Fatalf("callback body = %s, want empty redirect body", callbackBody)
	}
	sessionCookieHeader := cookies.ApplySetCookies(
		stateCookieHeader,
		callbackHeaders.Values("Set-Cookie"),
	)
	initialSessionToken, initialSessionTokenPresent := cookies.Parse(sessionCookieHeader).Get(
		"single-auth.session_token",
	)

	firstStatus, firstHeaders, firstBody, err := exchange(
		http.MethodGet,
		"/api/auth/get-session",
		http.Header{"Cookie": {sessionCookieHeader}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var firstSession struct {
		Session *struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expiresAt"`
		} `json:"session"`
		User *struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(firstBody, &firstSession); err != nil {
		t.Fatalf("decode first get-session status=%d body=%s: %v", firstStatus, firstBody, err)
	}
	sessionCookieHeader = cookies.ApplySetCookies(
		sessionCookieHeader,
		firstHeaders.Values("Set-Cookie"),
	)

	now = now.Add(time.Duration(want.AdvancedSeconds) * time.Second)
	refreshStatus, refreshHeaders, refreshBody, err := exchange(
		http.MethodGet,
		"/api/auth/get-session",
		http.Header{"Cookie": {sessionCookieHeader}},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	var refreshedSession struct {
		Session *struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expiresAt"`
		} `json:"session"`
		User *struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(refreshBody, &refreshedSession); err != nil {
		t.Fatalf("decode refreshed get-session status=%d body=%s: %v", refreshStatus, refreshBody, err)
	}
	refreshedCookie, refreshedCookiePresent := findSessionTokenRefreshSetCookie(
		refreshHeaders.Values("Set-Cookie"),
		"single-auth.session_token",
	)

	actual := sessionTokenRefreshObservation{
		ExpiresIn:                    int(auth.Options().Session.ExpiresIn / time.Second),
		CookieCacheMaxAge:            int(auth.Options().Session.CookieCache.MaxAge / time.Second),
		DefaultRefreshUpdateAge:      int(auth.Options().Session.CookieCache.MaxAge/time.Second) / 5,
		AdvancedSeconds:              want.AdvancedSeconds,
		SignInStatus:                 signInStatus,
		AuthorizationURLPresent:      signIn.URL != "",
		StatePresent:                 state != "",
		CallbackStatus:               callbackStatus,
		CallbackSessionTokenPresent:  initialSessionTokenPresent && initialSessionToken != "",
		FirstSessionStatus:           firstStatus,
		FirstSessionPresent:          firstSession.Session != nil,
		RefreshStatus:                refreshStatus,
		RefreshSessionPresent:        refreshedSession.Session != nil,
		RefreshedSessionTokenPresent: refreshedCookiePresent,
		SessionTokenUnchanged:        refreshedCookiePresent && refreshedCookie.Attributes.Value == initialSessionToken,
		TokenEndpointCalls:           tokenEndpointCalls,
	}
	if firstSession.User != nil {
		actual.FirstSessionEmail = firstSession.User.Email
	}
	if refreshedSession.User != nil {
		actual.RefreshSessionEmail = refreshedSession.User.Email
	}
	if refreshedCookie.Attributes.MaxAge != nil {
		actual.RefreshedSessionTokenMaxAge = *refreshedCookie.Attributes.MaxAge
	}
	if firstSession.Session != nil && refreshedSession.Session != nil {
		actual.LogicalSessionExpiryUnchanged =
			firstSession.Session.ExpiresAt == refreshedSession.Session.ExpiresAt
	}
	return actual
}

type sessionTokenRefreshRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn sessionTokenRefreshRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func findSessionTokenRefreshSetCookie(
	headers []string,
	name string,
) (cookies.SetCookie, bool) {
	for _, header := range headers {
		for _, parsed := range cookies.ParseSetCookieHeader(header) {
			if parsed.Name == name {
				return parsed, true
			}
		}
	}
	return cookies.SetCookie{}, false
}

func TestSessionTokenRefreshScenarioDefinition(t *testing.T) {
	want := sessionTokenRefreshExpected()
	if want.ExpiresIn <= 0 || want.CookieCacheMaxAge <= 0 || want.AdvancedSeconds <= 0 ||
		want.SignInStatus != http.StatusOK || want.CallbackStatus != http.StatusFound ||
		want.RefreshStatus != http.StatusOK || !want.RefreshedSessionTokenPresent {
		t.Fatalf("invalid session-token refresh scenario: %#v", want)
	}
}

func sessionTokenRefreshExpected() sessionTokenRefreshObservation {
	return sessionTokenRefreshObservation{
		ExpiresIn:                     300,
		CookieCacheMaxAge:             300,
		DefaultRefreshUpdateAge:       60,
		AdvancedSeconds:               241,
		SignInStatus:                  http.StatusOK,
		AuthorizationURLPresent:       true,
		StatePresent:                  true,
		CallbackStatus:                http.StatusFound,
		CallbackSessionTokenPresent:   true,
		FirstSessionStatus:            http.StatusOK,
		FirstSessionPresent:           true,
		FirstSessionEmail:             "google-user@example.com",
		RefreshStatus:                 http.StatusOK,
		RefreshSessionPresent:         true,
		RefreshSessionEmail:           "google-user@example.com",
		RefreshedSessionTokenPresent:  true,
		RefreshedSessionTokenMaxAge:   300,
		SessionTokenUnchanged:         true,
		LogicalSessionExpiryUnchanged: true,
		TokenEndpointCalls:            1,
	}
}
