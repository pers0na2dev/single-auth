package oauthpopup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestFactoryStartFlowMatchesReferenceServerContract(t *testing.T) {
	provider, err := providers.Google(providers.Options{
		ClientID: "client", ClientSecret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: testSecret,
		Account:         singleauth.AccountOptions{StoreStateStrategy: "database"},
		SocialProviders: map[string]*providers.Provider{"google": provider},
		PluginFactories: []singleauth.PluginFactory{NewFactory()},
	})
	if err != nil {
		t.Fatal(err)
	}

	additional := url.QueryEscape(`{"link":{"email":"popup@test.com","userId":"other"},"tenant":"acme"}`)
	target := "/api/auth/oauth-popup/start?provider=google" +
		"&popupOrigin=" + url.QueryEscape("http://localhost:3000") +
		"&popupNonce=n1" +
		"&callbackURL=" + url.QueryEscape("http://localhost:3000/dashboard") +
		"&scopes=calendar,drive" +
		"&additionalData=" + additional
	recorder := requestAuth(t, auth, target)
	if recorder.Code != http.StatusFound {
		t.Fatalf("start status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Host != "accounts.google.com" || location.Query().Get("state") == "" {
		t.Fatalf("authorization URL = %q", location.String())
	}
	if got := location.Query()["scope"]; len(got) != 1 ||
		!strings.Contains(got[0], "calendar") || !strings.Contains(got[0], "drive") {
		t.Fatalf("provider scopes = %#v", got)
	}
	setCookies := recorder.Header().Values("Set-Cookie")
	joined := strings.Join(setCookies, "\n")
	if !strings.Contains(joined, "single-auth.state=") ||
		!strings.Contains(joined, "single-auth.oauth_popup=") {
		t.Fatalf("start cookies = %#v", setCookies)
	}

	records, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: "verification"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range records {
		encoded, _ := record["value"].(string)
		var state map[string]any
		if json.Unmarshal([]byte(encoded), &state) == nil && state["tenant"] == "acme" {
			found = true
			if _, exists := state["link"]; exists {
				t.Fatalf("internal link leaked into OAuth state: %#v", state)
			}
		}
	}
	if !found {
		t.Fatalf("tenant state not found in %#v", records)
	}
}

func TestFactoryStartRelaysSafeFailuresAndRejectsUntrustedOpener(t *testing.T) {
	provider, err := providers.Google(providers.Options{ClientID: "client", ClientSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: testSecret,
		SocialProviders: map[string]*providers.Provider{"google": provider},
		PluginFactories: []singleauth.PluginFactory{NewFactory()},
	})
	origin := url.QueryEscape("http://localhost:3000")

	unknown := requestAuth(t, auth, "/api/auth/oauth-popup/start?provider=nope&popupOrigin="+origin+"&popupNonce=n1")
	if unknown.Code != http.StatusOK || !strings.Contains(unknown.Body.String(), DataElementID) ||
		!strings.Contains(unknown.Body.String(), "provider_not_found") {
		t.Fatalf("unknown provider = %d %s", unknown.Code, unknown.Body.String())
	}
	if cache := unknown.Header().Get("Cache-Control"); cache != "no-store" {
		t.Fatalf("completion cache-control = %q", cache)
	}

	untrustedCallback := requestAuth(t, auth,
		"/api/auth/oauth-popup/start?provider=google&popupOrigin="+origin+
			"&callbackURL="+url.QueryEscape("https://evil.example.com"))
	if untrustedCallback.Code != http.StatusOK ||
		!strings.Contains(untrustedCallback.Body.String(), "invalid_callback_url") {
		t.Fatalf("untrusted callback = %d %s", untrustedCallback.Code, untrustedCallback.Body.String())
	}

	untrustedOrigin := requestAuth(t, auth,
		"/api/auth/oauth-popup/start?provider=google&popupOrigin="+
			url.QueryEscape("https://evil.example.com"))
	if untrustedOrigin.Code != http.StatusForbidden ||
		!strings.Contains(untrustedOrigin.Body.String(), "INVALID_ORIGIN") {
		t.Fatalf("untrusted origin = %d %s", untrustedOrigin.Code, untrustedOrigin.Body.String())
	}
}

func TestCallbackHookReplacesPopupRedirectAndPreservesEveryCookie(t *testing.T) {
	dispatcher := callbackDispatcher(t)
	marker := signedMarker(t, markerData{PopupOrigin: "http://localhost:3000", PopupNonce: "n1"})
	request := contract.NewRequest(http.MethodGet, "/api/auth/callback/google", contract.RequestOptions{
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: marker}),
	})
	response, err := dispatcher.Dispatch(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status() != http.StatusOK {
		t.Fatalf("callback status = %d body=%s", response.Status(), response.Body())
	}
	body := string(response.Body())
	for _, expected := range []string{DataElementID, "postMessage", "n1", "signed-session", "http://localhost:3000/dashboard"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("completion body missing %q: %s", expected, body)
		}
	}
	cookieLines := strings.Join(response.Headers().Values("Set-Cookie"), "\n")
	for _, expected := range []string{"single-auth.session_token=", "single-auth.session_data=", "single-auth.oauth_popup=; Max-Age=0"} {
		if !strings.Contains(cookieLines, expected) {
			t.Fatalf("callback cookies missing %q: %s", expected, cookieLines)
		}
	}
	if csp, _ := response.Headers().Get("Content-Security-Policy"); !strings.Contains(csp, CompleteScriptCSPHash) {
		t.Fatalf("completion CSP = %q", csp)
	}
}

func TestCallbackHookLeavesNormalRedirectAndRelaysOAuthError(t *testing.T) {
	dispatcher := callbackDispatcher(t)
	normal, err := dispatcher.Dispatch(contract.NewRequest(
		http.MethodGet, "/api/auth/callback/google", contract.RequestOptions{},
	))
	if err != nil || normal.Status() != http.StatusFound {
		t.Fatalf("normal callback = %d err=%v", normal.Status(), err)
	}
	location, _ := normal.Headers().Get("Location")
	if location != "http://localhost:3000/dashboard" {
		t.Fatalf("normal redirect = %q", location)
	}

	marker := signedMarker(t, markerData{PopupOrigin: "http://localhost:3000", PopupNonce: "error-nonce"})
	errorResponse, err := dispatcher.Dispatch(contract.NewRequest(
		http.MethodGet, "/api/auth/oauth2/callback/google", contract.RequestOptions{
			Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: marker}),
		},
	))
	if err != nil {
		t.Fatal(err)
	}
	if errorResponse.Status() != http.StatusOK ||
		!strings.Contains(string(errorResponse.Body()), "access_denied") ||
		!strings.Contains(string(errorResponse.Body()), "Denied by user") {
		t.Fatalf("error completion = %d %s", errorResponse.Status(), errorResponse.Body())
	}
}

func TestCompletionTokenAuthenticatesThroughBearerFactory(t *testing.T) {
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: testSecret,
		PluginFactories: []singleauth.PluginFactory{
			&callbackSessionFactory{}, NewFactory(), bearer.NewFactory(bearer.Options{}),
		},
	})
	marker := signedMarker(t, markerData{PopupOrigin: "http://localhost:3000", PopupNonce: "bearer"})
	callback := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost:3000/api/auth/callback/test", nil)
	request.Header.Set("Cookie", marker)
	auth.ServeHTTP(callback, request)
	if callback.Code != http.StatusOK {
		t.Fatalf("callback status = %d body=%s", callback.Code, callback.Body.String())
	}
	var sessionToken string
	for _, line := range callback.Header().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == "single-auth.session_token" {
				sessionToken = parsed.Attributes.Value
			}
		}
	}
	if sessionToken == "" || !strings.Contains(callback.Body.String(), sessionToken) {
		t.Fatalf("completion token missing: cookie=%q body=%s", sessionToken, callback.Body.String())
	}

	session := httptest.NewRecorder()
	sessionRequest := httptest.NewRequest(http.MethodGet, "http://localhost:3000/api/auth/get-session", nil)
	sessionRequest.Header.Set("Authorization", "Bearer "+sessionToken)
	auth.ServeHTTP(session, sessionRequest)
	if session.Code != http.StatusOK || !strings.Contains(session.Body.String(), "popup@test.com") {
		t.Fatalf("bearer session = %d %s", session.Code, session.Body.String())
	}
}

type callbackSessionFactory struct{}

func (*callbackSessionFactory) PluginID() string { return "oauth-popup-test-callback" }

func (*callbackSessionFactory) Schema() (storage.Schema, error) { return storage.Schema{}, nil }

func (*callbackSessionFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	return engine.Plugin{
		ID: "oauth-popup-test-callback",
		Endpoints: []engine.Endpoint{{
			Name: "callbackOAuth", Path: "/callback/:id", Methods: []string{http.MethodGet},
			Override: true,
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				user, err := host.CreateUser(ctx, storage.Record{
					"email": "popup@test.com", "name": "Popup User",
					"emailVerified": true, "createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(),
				})
				if err != nil {
					return contract.Response{}, err
				}
				userID, _ := user["id"].(string)
				if _, err := host.IssueSession(ctx, userID, false); err != nil {
					return contract.Response{}, err
				}
				return redirect("http://localhost:3000/dashboard"), nil
			},
		}},
	}, nil
}

func requestAuth(t *testing.T, auth *singleauth.Auth, target string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "http://localhost:3000"+target, nil))
	return recorder
}

func callbackDispatcher(t *testing.T) *engine.Dispatcher {
	t.Helper()
	pluginValue, err := New(Options{Runtime: Runtime{
		Secret: testSecret,
		Cookie: func(contract.Request, string, string) (string, cookies.Options) {
			return "single-auth.oauth_popup", cookies.Options{Path: "/", HTTPOnly: true, SameSite: "lax"}
		},
		SessionCookie: func(contract.Request) (string, cookies.Options) {
			return "single-auth.session_token", cookies.Options{Path: "/"}
		},
		IsTrustedOrigin: func(contract.Request, string, bool) (bool, error) { return true, nil },
		ResolveBaseURL:  func(contract.Request) (string, error) { return "http://localhost:3000/api/auth", nil },
		SocialProvider:  func(string) *providers.Provider { return nil },
		CreateOAuthState: func(*engine.Context, singleauth.PluginOAuthStateInput) (singleauth.PluginOAuthState, error) {
			return singleauth.PluginOAuthState{}, nil
		},
		HasPlugin: func(id string) bool { return id == "bearer" },
	}})
	if err != nil {
		t.Fatal(err)
	}
	core := []engine.Endpoint{
		{
			Name: "callback", Path: "/callback/:id", Methods: []string{http.MethodGet},
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				ctx.AddSetCookie("single-auth.session_token=signed-session; Path=/; HttpOnly")
				ctx.AddSetCookie("single-auth.session_data=cached; Path=/; HttpOnly")
				return redirect("http://localhost:3000/dashboard"), nil
			},
		},
		{
			Name: "genericCallback", Path: "/oauth2/callback/:providerId", Methods: []string{http.MethodGet},
			Handler: func(*engine.Context) (contract.Response, error) {
				return redirect("/error?error=access_denied&error_description=Denied+by+user"), nil
			},
		},
	}
	registry, err := engine.NewRegistry(core, pluginValue)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func signedMarker(t *testing.T, value markerData) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	signed := signCookie(string(encoded), testSecret)
	return cookies.SetRequestCookie("", "single-auth.oauth_popup", signed)
}

func TestCallbackHookIsSafeUnderConcurrentDispatch(t *testing.T) {
	dispatcher := callbackDispatcher(t)
	marker := signedMarker(t, markerData{PopupOrigin: "http://localhost:3000", PopupNonce: "n"})
	errors := make(chan error, 32)
	for range 32 {
		go func() {
			response, err := dispatcher.Dispatch(contract.NewRequest(
				http.MethodGet, "/api/auth/callback/google", contract.RequestOptions{
					Context: context.Background(),
					Headers: contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: marker}),
				},
			))
			if err == nil && response.Status() != http.StatusOK {
				err = &statusError{status: response.Status()}
			}
			errors <- err
		}()
	}
	for range 32 {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
}

type statusError struct{ status int }

func (err *statusError) Error() string { return http.StatusText(err.status) }
