package genericoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

const statelessAccountBaseURL = "http://localhost:3000"

type statelessAccountExchange func(
	method, target string,
	headers http.Header,
	body []byte,
) (int, http.Header, []byte, error)

type statelessAccountTransport struct {
	name string
	bind func(*testing.T, *singleauth.Auth) statelessAccountExchange
}

type statelessAccountScenario struct {
	expected      statelessAccountResolution
	transport     statelessAccountTransport
	server        *genericOAuthServer
	mixed         map[string]string
	sessionUserID string
	accountUserID string
	accountCookie string
	now           time.Time
}

func TestStatelessMismatchedAccountCookieGetAccessTokenAcrossTransports(t *testing.T) {
	runStatelessAccountResolutionAcrossTransports(t, func(t *testing.T, scenario statelessAccountScenario) {
		auth := newStatelessAccountResolutionAuth(t, scenario.server, scenario.expected, scenario.now)
		exchange := scenario.transport.bind(t, auth)
		response := statelessAccountRequest(
			t, exchange, scenario.mixed, http.MethodPost,
			"/api/auth/get-access-token",
			map[string]any{
				"providerId": scenario.expected.ProviderID,
				"userId":     scenario.sessionUserID,
			},
		)
		if response.Status != http.StatusOK {
			t.Fatalf("get-access-token status=%d body=%s", response.Status, response.Body)
		}
		payload := decodeStatelessAccountJSON(t, response.Body)
		if payload["accessToken"] != scenario.expected.AccessToken {
			t.Fatalf("get-access-token payload=%#v", payload)
		}
	})
}

func TestStatelessMismatchedAccountCookieAccountInfoAcrossTransports(t *testing.T) {
	runStatelessAccountResolutionAcrossTransports(t, func(t *testing.T, scenario statelessAccountScenario) {
		auth := newStatelessAccountResolutionAuth(t, scenario.server, scenario.expected, scenario.now)
		exchange := scenario.transport.bind(t, auth)
		query := url.Values{
			"providerId": {scenario.expected.ProviderID},
			"userId":     {scenario.sessionUserID},
		}
		response := statelessAccountRequest(
			t, exchange, scenario.mixed, http.MethodGet,
			"/api/auth/account-info?"+query.Encode(), nil,
		)
		if response.Status != http.StatusOK {
			t.Fatalf("account-info status=%d body=%s", response.Status, response.Body)
		}
		payload := decodeStatelessAccountJSON(t, response.Body)
		user, userOK := payload["user"].(map[string]any)
		data, dataOK := payload["data"].(map[string]any)
		if !userOK || !dataOK || user["id"] != scenario.expected.AccountID ||
			data["accessTokenSeen"] != scenario.expected.AccessToken {
			t.Fatalf("account-info payload=%#v", payload)
		}
	})
}

func TestStatelessMismatchedAccountCookieRefreshTokenAcrossTransports(t *testing.T) {
	runStatelessAccountResolutionAcrossTransports(t, func(t *testing.T, scenario statelessAccountScenario) {
		auth := newStatelessAccountResolutionAuth(t, scenario.server, scenario.expected, scenario.now)
		exchange := scenario.transport.bind(t, auth)
		response := statelessAccountRequest(
			t, exchange, scenario.mixed, http.MethodPost,
			"/api/auth/refresh-token",
			map[string]any{
				"providerId": scenario.expected.ProviderID,
				"userId":     scenario.sessionUserID,
			},
		)
		if response.Status != http.StatusOK {
			t.Fatalf("refresh-token status=%d body=%s", response.Status, response.Body)
		}
		payload := decodeStatelessAccountJSON(t, response.Body)
		if payload["accessToken"] != scenario.expected.RefreshedAccessToken ||
			payload["refreshToken"] != scenario.expected.RotatedRefreshToken {
			t.Fatalf("refresh-token payload=%#v", payload)
		}
	})
}

func TestStatelessMismatchedAccountCookieSurvivesSessionRefreshAcrossTransports(t *testing.T) {
	runStatelessAccountResolutionAcrossTransports(t, func(t *testing.T, scenario statelessAccountScenario) {
		auth := newStatelessAccountResolutionAuth(t, scenario.server, scenario.expected, scenario.now)
		exchange := scenario.transport.bind(t, auth)
		response := statelessAccountRequest(
			t, exchange, scenario.mixed, http.MethodGet,
			"/api/auth/get-session", nil,
		)
		if response.Status != http.StatusOK {
			t.Fatalf("get-session status=%d body=%s", response.Status, response.Body)
		}

		var accountCookie *cookies.SetCookie
		for _, line := range response.Header.Values("Set-Cookie") {
			for _, parsed := range cookies.ParseSetCookieHeader(line) {
				if parsed.Name == scenario.accountCookie {
					copy := parsed
					accountCookie = &copy
				}
			}
		}
		if accountCookie == nil || accountCookie.Attributes.Value == "" ||
			(accountCookie.Attributes.MaxAge != nil && *accountCookie.Attributes.MaxAge == 0) {
			t.Fatalf("session refresh account cookie=%#v set-cookie=%#v", accountCookie, response.Header.Values("Set-Cookie"))
		}
		claims, err := baCrypto.DecodeJWEAt(
			accountCookie.Attributes.Value,
			scenario.expected.Secret,
			"single-auth-account",
			scenario.now,
		)
		if err != nil {
			t.Fatal(err)
		}
		if claims["accountId"] != scenario.expected.AccountID ||
			claims["providerId"] != scenario.expected.ProviderID ||
			claims["userId"] != scenario.accountUserID ||
			claims["userId"] == scenario.sessionUserID {
			t.Fatalf("reissued mismatched account claims=%#v", claims)
		}
	})
}

func runStatelessAccountResolutionAcrossTransports(
	t *testing.T,
	run func(*testing.T, statelessAccountScenario),
) {
	t.Helper()
	expected := statelessAccountCases.Resolution
	for _, transport := range statelessAccountTransports() {
		transport := transport
		t.Run(transport.name, func(t *testing.T) {
			run(t, prepareStatelessAccountScenario(t, transport, expected))
		})
	}
}

func prepareStatelessAccountScenario(
	t *testing.T,
	transport statelessAccountTransport,
	expected statelessAccountResolution,
) statelessAccountScenario {
	t.Helper()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	server := newGenericOAuthServer(t, nil)
	server.setTokenResponses(
		expected.AccessToken,
		expected.RefreshToken,
		expected.RefreshedAccessToken,
		expected.RotatedRefreshToken,
	)

	authA := newStatelessAccountResolutionAuth(t, server, expected, now)
	authB := newStatelessAccountResolutionAuth(t, server, expected, now)
	a := signInStatelessAccount(t, transport.bind(t, authA), expected.ProviderID)
	b := signInStatelessAccount(t, transport.bind(t, authB), expected.ProviderID)
	if a.userID == b.userID {
		t.Fatalf("independent stateless users unexpectedly match: %q", a.userID)
	}

	accountCookie := statelessAccountCookieBase(t, b.jar)
	mixed := cloneStatelessAccountJar(a.jar)
	for name := range mixed {
		if name == accountCookie || strings.HasPrefix(name, accountCookie+".") {
			delete(mixed, name)
		}
	}
	for name, value := range b.jar {
		if name == accountCookie || strings.HasPrefix(name, accountCookie+".") {
			mixed[name] = value
		}
	}
	if _, exists := mixed[accountCookie]; !exists {
		t.Fatalf("mixed jar omitted %q: %#v", accountCookie, mixed)
	}

	return statelessAccountScenario{
		expected: expected, transport: transport, server: server, mixed: mixed,
		sessionUserID: a.userID, accountUserID: b.userID,
		accountCookie: accountCookie, now: now,
	}
}

func newStatelessAccountResolutionAuth(
	t *testing.T,
	server *genericOAuthServer,
	expected statelessAccountResolution,
	now time.Time,
) *singleauth.Auth {
	t.Helper()
	config := server.config(expected.ProviderID)
	config.GetUserInfo = func(_ context.Context, tokens oauth2.Tokens) (Profile, error) {
		return Profile{
			"id": expected.AccountID, "email": "user@stateless.test",
			"name": "Stateless User", "emailVerified": true,
			"accessTokenSeen": tokens.AccessToken,
		}, nil
	}
	refreshUpdateAge := time.Duration(expected.SessionCacheRefreshUpdateAgeSeconds) * time.Second
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: statelessAccountBaseURL,
		Secret:  expected.Secret,
		Clock:   func() time.Time { return now },
		TrustedOrigins: []string{
			statelessAccountBaseURL,
		},
		Session: singleauth.SessionOptions{
			Stateless: true,
			CookieCache: singleauth.CookieCacheOptions{
				Enabled:               true,
				Strategy:              expected.SessionCacheStrategy,
				MaxAge:                time.Duration(expected.SessionCacheMaxAgeSeconds) * time.Second,
				RefreshCacheUpdateAge: &refreshUpdateAge,
			},
		},
		Account: singleauth.AccountOptions{
			StoreStateStrategy: "cookie",
			StoreAccountCookie: storage.Bool(true),
		},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Config: []Config{config},
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if auth.Options().Database != nil {
		t.Fatal("stateless account-resolution auth unexpectedly configured a database")
	}
	return auth
}

type statelessAccountSignIn struct {
	jar    map[string]string
	userID string
}

func signInStatelessAccount(
	t *testing.T,
	exchange statelessAccountExchange,
	providerID string,
) statelessAccountSignIn {
	t.Helper()
	jar := make(map[string]string)
	response := statelessAccountRequest(
		t, exchange, jar, http.MethodPost,
		"/api/auth/sign-in/oauth2",
		map[string]any{"providerId": providerID, "callbackURL": "/"},
	)
	if response.Status != http.StatusOK {
		t.Fatalf("sign-in/oauth2 status=%d body=%s", response.Status, response.Body)
	}
	payload := decodeStatelessAccountJSON(t, response.Body)
	authorizationURL, ok := payload["url"].(string)
	if !ok {
		t.Fatalf("sign-in/oauth2 payload=%#v", payload)
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("authorization URL has no state: %s", parsed)
	}
	callbackQuery := url.Values{"code": {"test-code"}, "state": {state}}
	response = statelessAccountRequest(
		t, exchange, jar, http.MethodGet,
		"/api/auth/oauth2/callback/"+url.PathEscape(providerID)+"?"+callbackQuery.Encode(), nil,
	)
	if response.Status != http.StatusFound {
		t.Fatalf("oauth2 callback status=%d body=%s", response.Status, response.Body)
	}
	response = statelessAccountRequest(
		t, exchange, jar, http.MethodGet, "/api/auth/get-session", nil,
	)
	if response.Status != http.StatusOK {
		t.Fatalf("get-session status=%d body=%s", response.Status, response.Body)
	}
	payload = decodeStatelessAccountJSON(t, response.Body)
	user, ok := payload["user"].(map[string]any)
	userID, okID := user["id"].(string)
	if !ok || !okID || userID == "" {
		t.Fatalf("get-session payload=%#v", payload)
	}
	return statelessAccountSignIn{jar: jar, userID: userID}
}

func statelessAccountRequest(
	t *testing.T,
	exchange statelessAccountExchange,
	jar map[string]string,
	method, target string,
	body any,
) genericResponse {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	headers := make(http.Header)
	if body != nil {
		headers.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost {
		headers.Set("Origin", statelessAccountBaseURL)
	}
	if cookieHeader := statelessAccountCookieHeader(jar); cookieHeader != "" {
		headers.Set("Cookie", cookieHeader)
	}
	status, responseHeaders, responseBody, err := exchange(method, target, headers, encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range responseHeaders.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Attributes.MaxAge != nil && *parsed.Attributes.MaxAge == 0 {
				delete(jar, parsed.Name)
			} else {
				jar[parsed.Name] = parsed.Attributes.Value
			}
		}
	}
	return genericResponse{Status: status, Header: responseHeaders, Body: responseBody}
}

func statelessAccountTransports() []statelessAccountTransport {
	return []statelessAccountTransport{
		{name: "net-http", bind: bindStatelessAccountNetHTTP},
		{name: "fasthttp", bind: bindStatelessAccountFastHTTP},
		{name: "fiber", bind: bindStatelessAccountFiber},
	}
}

func bindStatelessAccountNetHTTP(t *testing.T, auth *singleauth.Auth) statelessAccountExchange {
	t.Helper()
	handler := nethttptransport.NewHandler(auth.Dispatcher())
	return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		request := httptest.NewRequest(method, statelessAccountBaseURL+target, bytes.NewReader(body))
		request.Header = headers.Clone()
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		response := recorder.Result()
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		return response.StatusCode, response.Header.Clone(), encoded, err
	}
}

func bindStatelessAccountFastHTTP(t *testing.T, auth *singleauth.Auth) statelessAccountExchange {
	t.Helper()
	handler := fasthttptransport.NewHandler(auth.Dispatcher())
	return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.SetRequestURI(statelessAccountBaseURL + target)
		request.Header.SetHost("localhost:3000")
		for name, values := range headers {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
		request.SetBody(body)
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(
			&request,
			&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
			nil,
		)
		handler(&requestContext)
		responseHeaders := make(http.Header)
		requestContext.Response.Header.VisitAll(func(name, value []byte) {
			responseHeaders.Add(string(name), string(value))
		})
		return requestContext.Response.StatusCode(), responseHeaders,
			append([]byte(nil), requestContext.Response.Body()...), nil
	}
}

func bindStatelessAccountFiber(t *testing.T, auth *singleauth.Auth) statelessAccountExchange {
	t.Helper()
	app := fiberframework.New()
	app.Use(fibertransport.NewHandler(auth.Dispatcher()))
	return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
		request, err := http.NewRequest(method, statelessAccountBaseURL+target, bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, err
		}
		request.Header = headers.Clone()
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			return 0, nil, nil, err
		}
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		return response.StatusCode, response.Header.Clone(), encoded, err
	}
}

func statelessAccountCookieHeader(jar map[string]string) string {
	names := make([]string, 0, len(jar))
	for name := range jar {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, name+"="+jar[name])
	}
	return strings.Join(pairs, "; ")
}

func statelessAccountCookieBase(t *testing.T, jar map[string]string) string {
	t.Helper()
	for name := range jar {
		if strings.HasSuffix(name, ".account_data") {
			return name
		}
	}
	t.Fatalf("jar has no account_data cookie: %#v", jar)
	return ""
}

func cloneStatelessAccountJar(jar map[string]string) map[string]string {
	clone := make(map[string]string, len(jar))
	for name, value := range jar {
		clone[name] = value
	}
	return clone
}

func decodeStatelessAccountJSON(t *testing.T, encoded []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("decode JSON %q: %v", encoded, err)
	}
	return payload
}
