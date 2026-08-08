package singleauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

type oauthStateCase struct {
	Suite       string
	Title       string
	Observation oauthStateObservation
}

type oauthStateObservation struct {
	RedirectURL               string `json:"redirectURL"`
	Error                     string `json:"error"`
	ContainsLegacyRestartCode bool   `json:"containsLegacyRestartCode"`
}

type oauthStateExchange func(
	method, target string,
	headers http.Header,
	body []byte,
) (int, http.Header, []byte, error)

type oauthStateFailingAdapter struct {
	storage.Adapter
}

func (adapter *oauthStateFailingAdapter) FindMany(
	ctx context.Context,
	params storage.FindManyParams,
) ([]storage.Record, error) {
	if params.Model == "verification" {
		return nil, errors.New("OAuth state adapter failure")
	}
	return adapter.Adapter.FindMany(ctx, params)
}

func TestOAuthStateHTTPBehavior(t *testing.T) {
	for _, vector := range oauthStateCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				actual := runOAuthStateVector(t, transportName, vector.Title)
				if !reflect.DeepEqual(actual, vector.Observation) {
					t.Fatalf(
						"%s: OAuth state observation = %#v, want %#v",
						transportName,
						actual,
						vector.Observation,
					)
				}
			}
		})
	}
}

func runOAuthStateVector(t *testing.T, transportName, title string) oauthStateObservation {
	t.Helper()
	provider, err := providers.Google(providers.Options{
		ClientID: "client", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	options := singleauth.Options{
		BaseURL: "http://localhost:3000",
		Secret:  "0123456789abcdef0123456789abcdef",
		SocialProviders: map[string]*providers.Provider{
			"google": provider,
		},
	}
	var target string
	requestHeaders := make(http.Header)
	generatedState := false

	switch title {
	case "maps StateError state_not_found to error=state_not_found":
		options.Database = memory.MustNew()
		options.Account.StoreStateStrategy = "database"
		target = "/api/auth/callback/google"
	case "maps StateError state_invalid to error=state_invalid":
		options.Account.StoreStateStrategy = "cookie"
		target = "/api/auth/callback/google?state=issued-state"
		requestHeaders.Set("Cookie", "single-auth.oauth_state=not-ciphertext")
	case "maps StateError state_mismatch to error=state_mismatch":
		options.Database = memory.MustNew()
		options.Account.StoreStateStrategy = "database"
		target = "/api/auth/callback/google?state=missing-state"
	case "maps StateError state_security_mismatch to error=state_mismatch":
		options.Account.StoreStateStrategy = "cookie"
		generatedState = true
	case "maps an unexpected (non-StateError) failure to internal_server_error":
		options.Database = &oauthStateFailingAdapter{Adapter: memory.MustNew()}
		options.Account.StoreStateStrategy = "database"
		target = "/api/auth/callback/google?state=adapter-failure"
	case "appends error with & when the error URL already has a query string":
		options.Account.StoreStateStrategy = "cookie"
		options.OnAPIError.ErrorURL = "https://example.com/error?foo=bar"
		target = "/api/auth/callback/google?state=issued-state"
		requestHeaders.Set("Cookie", "single-auth.oauth_state=not-ciphertext")
	case "prefers the recovered per-flow errorURL and appends with & when it has a query":
		options.Account.StoreStateStrategy = "cookie"
		generatedState = true
	default:
		t.Fatalf("unknown upstream implementation OAuth state test %q", title)
	}

	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	exchange := newOAuthStateExchange(t, transportName, auth)
	if generatedState {
		errorCallbackURL := ""
		if strings.HasPrefix(title, "prefers the recovered") {
			errorCallbackURL = "/oauth-error?source=expo"
		}
		state, cookieHeader := startOAuthStateFlow(
			t,
			transportName,
			auth,
			exchange,
			errorCallbackURL,
		)
		target = "/api/auth/callback/google?state=" + url.QueryEscape(state+"-tampered")
		requestHeaders.Set("Cookie", cookieHeader)
	}

	status, responseHeaders, body, err := exchange(http.MethodGet, target, requestHeaders, nil)
	if err != nil || status != http.StatusFound || len(body) != 0 {
		t.Fatalf(
			"%s: OAuth callback status=%d body=%s err=%v",
			transportName,
			status,
			body,
			err,
		)
	}
	if generatedState && len(responseHeaders.Values("Set-Cookie")) != 0 {
		t.Fatalf(
			"%s: rejected OAuth state unexpectedly mutated cookies: %#v",
			transportName,
			responseHeaders.Values("Set-Cookie"),
		)
	}
	location := responseHeaders.Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return oauthStateObservation{
		RedirectURL:               location,
		Error:                     parsed.Query().Get("error"),
		ContainsLegacyRestartCode: strings.Contains(location, "please_restart_the_process"),
	}
}

func startOAuthStateFlow(
	t *testing.T,
	transportName string,
	auth *singleauth.Auth,
	exchange oauthStateExchange,
	errorCallbackURL string,
) (string, string) {
	t.Helper()
	payload := map[string]any{
		"provider":    "google",
		"callbackURL": "http://localhost:3000/done",
	}
	if errorCallbackURL != "" {
		payload["errorCallbackURL"] = errorCallbackURL
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{
		"Content-Type": {"application/json"},
		"Origin":       {"http://localhost:3000"},
	}
	status, responseHeaders, responseBody, err := exchange(
		http.MethodPost,
		"/api/auth/sign-in/social",
		headers,
		body,
	)
	if err != nil || status != http.StatusOK {
		t.Fatalf(
			"%s: create OAuth state status=%d body=%s err=%v",
			transportName,
			status,
			responseBody,
			err,
		)
	}
	var response struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatal(err)
	}
	authorizationURL, err := url.Parse(response.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := authorizationURL.Query().Get("state")
	if state == "" || authorizationURL.Query().Get("code_challenge") == "" {
		t.Fatalf("%s: generated OAuth URL lacks state or PKCE: %s", transportName, response.URL)
	}
	cookieHeader := cookies.ApplySetCookies("", responseHeaders.Values("Set-Cookie"))
	parsedCookies := cookies.Parse(cookieHeader)
	hasOAuthStateCookie := false
	for _, pair := range parsedCookies.Pairs() {
		if strings.HasSuffix(pair.Name, ".oauth_state") && pair.Value != "" {
			hasOAuthStateCookie = true
		}
	}
	if !hasOAuthStateCookie {
		t.Fatalf("%s: OAuth state creation did not set encrypted state cookie", transportName)
	}
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil || len(rows) != 0 {
		t.Fatalf(
			"%s: cookie state strategy persisted verification rows=%#v err=%v",
			transportName,
			rows,
			err,
		)
	}
	return state, cookieHeader
}

func newOAuthStateExchange(
	t *testing.T,
	transportName string,
	auth *singleauth.Auth,
) oauthStateExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			request.Header = headers.Clone()
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			encoded, err := io.ReadAll(response.Body)
			return response.StatusCode, response.Header.Clone(), encoded, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.SetRequestURI(target)
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
			httpHeaders := make(http.Header)
			handler(&requestContext)
			requestContext.Response.Header.VisitAll(func(name, value []byte) {
				httpHeaders.Add(string(name), string(value))
			})
			return requestContext.Response.StatusCode(), httpHeaders,
				append([]byte(nil), requestContext.Response.Body()...), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(method, target string, headers http.Header, body []byte) (int, http.Header, []byte, error) {
			request, err := http.NewRequest(
				method,
				"http://localhost:3000"+target,
				bytes.NewReader(body),
			)
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
	default:
		t.Fatalf("unknown OAuth state transport %q", transportName)
		return nil
	}
}

func TestOAuthStateScenarioDefinitions(t *testing.T) {
	cases := oauthStateCases()
	if len(cases) != 7 {
		t.Fatalf("OAuth state scenarios=%d, want 7", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, scenario := range cases {
		if scenario.Suite == "" || scenario.Title == "" || scenario.Observation.RedirectURL == "" || scenario.Observation.Error == "" {
			t.Fatalf("invalid OAuth state scenario: %#v", scenario)
		}
		if _, duplicate := seen[scenario.Title]; duplicate {
			t.Fatalf("duplicate OAuth state scenario %q", scenario.Title)
		}
		seen[scenario.Title] = struct{}{}
	}
}

func oauthStateCases() []oauthStateCase {
	const suite = "parseState error mapping"
	return []oauthStateCase{
		{Suite: suite, Title: "appends error with & when the error URL already has a query string", Observation: oauthStateObservation{RedirectURL: "https://example.com/error?foo=bar&error=state_invalid", Error: "state_invalid"}},
		{Suite: suite, Title: "maps StateError state_invalid to error=state_invalid", Observation: oauthStateObservation{RedirectURL: "http://localhost:3000/api/auth/error?error=state_invalid", Error: "state_invalid"}},
		{Suite: suite, Title: "maps StateError state_mismatch to error=state_mismatch", Observation: oauthStateObservation{RedirectURL: "http://localhost:3000/api/auth/error?error=state_mismatch", Error: "state_mismatch"}},
		{Suite: suite, Title: "maps StateError state_not_found to error=state_not_found", Observation: oauthStateObservation{RedirectURL: "http://localhost:3000/api/auth/error?error=state_not_found", Error: "state_not_found"}},
		{Suite: suite, Title: "maps StateError state_security_mismatch to error=state_mismatch", Observation: oauthStateObservation{RedirectURL: "http://localhost:3000/api/auth/error?error=state_mismatch", Error: "state_mismatch"}},
		{Suite: suite, Title: "maps an unexpected (non-StateError) failure to internal_server_error", Observation: oauthStateObservation{RedirectURL: "http://localhost:3000/api/auth/error?error=internal_server_error", Error: "internal_server_error"}},
		{Suite: suite, Title: "prefers the recovered per-flow errorURL and appends with & when it has a query", Observation: oauthStateObservation{RedirectURL: "/oauth-error?source=expo&error=state_mismatch", Error: "state_mismatch"}},
	}
}
