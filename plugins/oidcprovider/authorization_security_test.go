package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestPromptNoneLoginConsentAndSuccessPaths(t *testing.T) {
	harness := newHarness(t, nil)
	userID, headers := harness.signUp(t, 20)
	redirectURI := "https://client.example/prompt-none"
	registered := harness.register(t, headers, "prompt-none", []string{redirectURI})
	clientID := registered["client_id"].(string)
	baseQuery := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid profile email"}, "state": {"test-state"}, "prompt": {"none"},
		"code_challenge": {"test-challenge"}, "code_challenge_method": {"S256"},
	}
	unauthenticated, err := harness.call(t, "oAuth2authorize", http.MethodGet, contract.Headers{}, nil, baseQuery)
	if err != nil || !strings.Contains(headerValue(unauthenticated.Response.Headers(), "Location"), "error=login_required") {
		t.Fatalf("unauthenticated status=%d err=%v location=%q", unauthenticated.Response.Status(), err, headerValue(unauthenticated.Response.Headers(), "Location"))
	}
	location := headerValue(unauthenticated.Response.Headers(), "Location")
	if !strings.Contains(location, "Authentication") || !strings.Contains(location, "prompt") || !strings.Contains(location, "none") {
		t.Fatalf("login_required location=%q", location)
	}

	attackerQuery := cloneValues(baseQuery)
	attackerQuery.Set("redirect_uri", "https://malicious.example/callback")
	attacker, attackerErr := harness.call(t, "oAuth2authorize", http.MethodGet, contract.Headers{}, nil, attackerQuery)
	if attackerErr == nil || attacker.Response.Status() != http.StatusBadRequest ||
		strings.Contains(headerValue(attacker.Response.Headers(), "Location"), "malicious.example") {
		t.Fatalf("attacker status=%d err=%v location=%q", attacker.Response.Status(), attackerErr, headerValue(attacker.Response.Headers(), "Location"))
	}

	missingRedirectQuery := cloneValues(baseQuery)
	missingRedirectQuery.Del("redirect_uri")
	missing, missingErr := harness.call(t, "oAuth2authorize", http.MethodGet, contract.Headers{}, nil, missingRedirectQuery)
	oauthErrorObject(t, missing, missingErr, http.StatusBadRequest, "invalid_request")
	if strings.Contains(headerValue(missing.Response.Headers(), "Location"), "/login") {
		t.Fatalf("missing redirect leaked to login: %#v", missing.Response.Headers())
	}

	needsConsent, err := harness.call(t, "oAuth2authorize", http.MethodGet, headers, nil, baseQuery)
	if err != nil || !strings.Contains(headerValue(needsConsent.Response.Headers(), "Location"), "error=consent_required") {
		t.Fatalf("consent status=%d err=%v location=%q", needsConsent.Response.Status(), err, headerValue(needsConsent.Response.Headers(), "Location"))
	}

	now := harness.clock.Now()
	if _, err := harness.auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "oauthConsent", Data: storage.Record{
			"clientId": clientID, "userId": userID, "scopes": "openid profile email",
			"consentGiven": true, "createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		t.Fatal(err)
	}
	success, err := harness.call(t, "oAuth2authorize", http.MethodGet, headers, nil, baseQuery)
	successLocation := headerValue(success.Response.Headers(), "Location")
	if err != nil || !strings.Contains(successLocation, "code=") ||
		!strings.Contains(successLocation, "state=test-state") || strings.Contains(successLocation, "error=") {
		t.Fatalf("success status=%d err=%v location=%q", success.Response.Status(), err, successLocation)
	}
}

func TestPromptLoginContinuationConsentAndCookieCleanup(t *testing.T) {
	harness := newHarness(t, nil)
	_, sessionHeaders := harness.signUp(t, 21)
	redirectURI := "https://client.example/login-consent"
	registered := harness.register(t, sessionHeaders, "login-consent", []string{redirectURI})
	clientID := registered["client_id"].(string)
	authorized, err := harness.call(t, "oAuth2authorize", http.MethodGet, sessionHeaders, nil, url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid profile email"}, "state": {"test-state"}, "prompt": {"login"},
		"code_challenge": {"test-challenge"}, "code_challenge_method": {"S256"},
	})
	if err != nil || !strings.Contains(headerValue(authorized.Response.Headers(), "Location"), "/login") {
		t.Fatalf("authorize status=%d err=%v location=%q", authorized.Response.Status(), err, headerValue(authorized.Response.Headers(), "Location"))
	}
	promptCookie := cookies.ApplySetCookies("", authorized.Response.Headers().Values("Set-Cookie"))
	loginHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: promptCookie})
	loggedIn, err := harness.call(t, "signInEmail", http.MethodPost, loginHeaders, map[string]any{
		"email": "oidc-user-21@example.test", "password": "password-12345",
	}, nil)
	if err != nil {
		t.Fatalf("login continuation: %v body=%s", err, loggedIn.Response.Body())
	}
	location := headerValue(loggedIn.Response.Headers(), "Location")
	if strings.Contains(location, "/login") || !strings.Contains(location, "consent_code=") {
		t.Fatalf("continued location=%q headers=%#v", location, loggedIn.Response.Headers())
	}
	if !hasExpiredCookie(loggedIn.Response.Headers().Values("Set-Cookie"), "oidc_login_prompt") {
		t.Fatalf("login prompt cookie was not expired: %#v", loggedIn.Response.Headers().Values("Set-Cookie"))
	}

	normal, normalErr := harness.call(t, "signInEmail", http.MethodPost, contract.Headers{}, map[string]any{
		"email": "oidc-user-21@example.test", "password": "password-12345",
	}, nil)
	if normalErr != nil || strings.Contains(headerValue(normal.Response.Headers(), "Location"), "oauth2/callback") ||
		strings.Contains(headerValue(normal.Response.Headers(), "Location"), redirectURI) {
		t.Fatalf("normal login status=%d err=%v location=%q", normal.Response.Status(), normalErr, headerValue(normal.Response.Headers(), "Location"))
	}
}

func TestMaxAgeForcesOnlyStaleSessionLogin(t *testing.T) {
	trusted := Client{
		ClientID: "max-age-client", ClientSecret: "secret", Type: "web", Name: "max-age",
		RedirectURLs: []string{"https://client.example/max-age"}, SkipConsent: true,
	}
	harness := newHarness(t, func(options *Options) {
		options.TrustedClients = []Client{trusted}
	})
	_, headers := harness.signUp(t, 22)
	harness.clock.Advance(time.Millisecond)
	baseQuery := url.Values{
		"client_id": {trusted.ClientID}, "redirect_uri": {trusted.RedirectURLs[0]},
		"response_type": {"code"}, "scope": {"openid profile email"}, "state": {"state"},
		"code_challenge": {"test-challenge"}, "code_challenge_method": {"S256"},
	}
	staleQuery := cloneValues(baseQuery)
	staleQuery.Set("max_age", "0")
	stale, err := harness.call(t, "oAuth2authorize", http.MethodGet, headers, nil, staleQuery)
	if err != nil || !strings.Contains(headerValue(stale.Response.Headers(), "Location"), "/login") {
		t.Fatalf("stale status=%d err=%v location=%q", stale.Response.Status(), err, headerValue(stale.Response.Headers(), "Location"))
	}
	freshQuery := cloneValues(baseQuery)
	freshQuery.Set("max_age", "3600")
	fresh, err := harness.call(t, "oAuth2authorize", http.MethodGet, headers, nil, freshQuery)
	freshLocation := headerValue(fresh.Response.Headers(), "Location")
	if err != nil || strings.Contains(freshLocation, "/login") || !strings.Contains(freshLocation, "code=") {
		t.Fatalf("fresh status=%d err=%v location=%q", fresh.Response.Status(), err, freshLocation)
	}
}

func hasExpiredCookie(lines []string, name string) bool {
	for _, line := range lines {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == name && parsed.Attributes.MaxAge != nil && *parsed.Attributes.MaxAge == 0 {
				return true
			}
		}
	}
	return false
}

func cloneValues(input url.Values) url.Values {
	result := make(url.Values, len(input))
	for key, values := range input {
		result[key] = append([]string(nil), values...)
	}
	return result
}
