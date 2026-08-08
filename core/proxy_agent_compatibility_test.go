package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

func TestOAuthUsesConfiguredGlobalHTTPClient(t *testing.T) {
	t.Run("GitHub", func(t *testing.T) {
		assertOAuthUsesConfiguredGlobalHTTPClient(t, "github")
	})
	t.Run("Google", func(t *testing.T) {
		assertOAuthUsesConfiguredGlobalHTTPClient(t, "google")
	})
}

func assertOAuthUsesConfiguredGlobalHTTPClient(t *testing.T, providerID string) {
	t.Helper()
	transport := &proxyBehaviorTransport{providerID: providerID}
	providerOptions := providers.Options{ClientID: "test_client_id", ClientSecret: "test_client_secret"}
	provider, err := providers.New(providerID, providerOptions)
	if err != nil {
		t.Fatal(err)
	}
	if provider.Options.HTTPClient != nil {
		t.Fatal("test must exercise the auth-wide HTTP client, not a provider-specific client")
	}
	auth := MustNew(Options{
		BaseURL: "http://auth.test",
		Secret:  "single-auth-secret-123456789",
		Account: AccountOptions{StoreStateStrategy: "database"},
		HTTPClient: &http.Client{
			Transport: transport,
		},
		SocialProviders: map[string]*providers.Provider{providerID: provider},
	})
	callbackURL := "http://auth.test/dashboard"
	status, headers, value := sessionTestRequest(t, auth, http.MethodPost, "/sign-in/social", "", map[string]any{
		"provider": providerID, "callbackURL": callbackURL,
	})
	if status != http.StatusOK {
		t.Fatalf("%s sign-in status=%d value=%#v", providerID, status, value)
	}
	result := value.(map[string]any)
	if result["redirect"] != true {
		t.Fatalf("%s sign-in result=%#v", providerID, result)
	}
	authorizeURL, err := url.Parse(objectString(t, result, "url"))
	if err != nil {
		t.Fatal(err)
	}
	if authorizeURL.Query().Get("state") == "" {
		t.Fatalf("%s authorize URL has no state: %s", providerID, authorizeURL)
	}
	wantHost := "github.com"
	if providerID == "google" {
		wantHost = "accounts.google.com"
	}
	if authorizeURL.Host != wantHost {
		t.Fatalf("%s authorization host=%q want=%q", providerID, authorizeURL.Host, wantHost)
	}

	cookieHeader := cookies.ApplySetCookies("", headers.Values("Set-Cookie"))
	callbackPath := "/callback/" + providerID + "?code=test_authorization_code&state=" +
		url.QueryEscape(authorizeURL.Query().Get("state"))
	status, callbackHeaders, callbackBody := sessionTestRequest(
		t, auth, http.MethodGet, callbackPath, cookieHeader, nil,
	)
	if status != http.StatusFound || callbackHeaders.Get("Location") != callbackURL || callbackBody != nil {
		t.Fatalf(
			"%s callback status=%d location=%q body=%#v",
			providerID, status, callbackHeaders.Get("Location"), callbackBody,
		)
	}

	got := transport.snapshot()
	want := []string{"POST " + provider.Metadata.TokenEndpoint}
	if providerID == "github" {
		want = append(want,
			"GET https://api.github.com/user",
			"GET https://api.github.com/user/emails",
		)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("%s outbound calls=%#v want=%#v", providerID, got, want)
	}
}

type proxyBehaviorTransport struct {
	providerID string
	mu         sync.Mutex
	calls      []string
}

func (transport *proxyBehaviorTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	transport.calls = append(transport.calls, request.Method+" "+request.URL.String())
	transport.mu.Unlock()

	var payload any
	switch request.URL.String() {
	case "https://github.com/login/oauth/access_token":
		payload = map[string]any{
			"access_token": "test_github_access_token", "token_type": "bearer", "scope": "user:email",
		}
	case "https://api.github.com/user":
		payload = map[string]any{
			"id": "12345", "login": "testuser", "email": "test@example.com",
			"name": "Test User", "avatar_url": "https://avatars.githubusercontent.com/u/12345",
		}
	case "https://api.github.com/user/emails":
		payload = []any{map[string]any{
			"email": "test@example.com", "primary": true, "verified": true, "visibility": "public",
		}}
	case "https://oauth2.googleapis.com/token":
		payload = map[string]any{
			"access_token": "test_google_access_token", "refresh_token": "test_refresh_token",
			"id_token": proxyBehaviorJWT(map[string]any{
				"sub": "1234567890", "name": "Test User", "email": "user@example.com",
				"email_verified": true, "picture": "https://lh3.googleusercontent.com/a-/test",
			}),
			"expires_in": 3600, "token_type": "Bearer",
		}
	default:
		return nil, fmt.Errorf("global OAuth transport received unexpected request %s %s", request.Method, request.URL)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(encoded))),
		Request:    request,
	}, nil
}

func (transport *proxyBehaviorTransport) snapshot() []string {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]string(nil), transport.calls...)
}

func proxyBehaviorJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + ".x"
}
