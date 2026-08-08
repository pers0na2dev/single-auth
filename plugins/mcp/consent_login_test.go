package mcp

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestConsentFlowAndDirectAuthorizationWithoutConsent(t *testing.T) {
	harness := newHarness(t, nil)
	userID, sessionHeaders := harness.signUp(t, 3)
	redirectURI := "http://localhost:3000/consent/callback"
	registered := harness.register(t, "none", "consent-client", redirectURI)
	clientID := registered["client_id"].(string)

	authorized, err := harness.call(t, "mcpOAuthAuthorize", http.MethodGet, sessionHeaders, nil, url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid profile email"}, "state": {"consent-state"}, "prompt": {"consent"},
		"code_challenge": {"test-challenge"}, "code_challenge_method": {"S256"},
	})
	if err != nil || authorized.Response.Status() != http.StatusFound {
		t.Fatalf("authorize status=%d err=%v body=%s", authorized.Response.Status(), err, authorized.Response.Body())
	}
	location := headerValue(authorized.Response.Headers(), "Location")
	if !strings.Contains(location, "/oauth/consent?") || strings.Contains(location, "?code=") {
		t.Fatalf("consent location=%q", location)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	consentCode := parsed.Query().Get("consent_code")
	if consentCode == "" || parsed.Query().Get("client_id") != clientID {
		t.Fatalf("consent location=%q", location)
	}
	currentCookie, _ := sessionHeaders.Get("Cookie")
	currentCookie = cookies.ApplySetCookies(currentCookie, authorized.Response.Headers().Values("Set-Cookie"))
	consentHeaders := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: currentCookie})
	accepted, err := harness.call(t, "oAuthConsent", http.MethodPost, consentHeaders, map[string]any{
		"accept": true, "consent_code": consentCode,
	}, nil)
	if err != nil {
		t.Fatalf("consent: %v body=%s", err, accepted.Response.Body())
	}
	finalRedirect := responseObject(t, accepted)["redirectURI"].(string)
	finalURL, _ := url.Parse(finalRedirect)
	if finalURL.Query().Get("code") == "" || finalURL.Query().Get("state") != "consent-state" {
		t.Fatalf("final redirect=%q", finalRedirect)
	}
	rows, err := harness.auth.Adapter().FindMany(t.Context(), storage.FindManyParams{
		Model: "oauthConsent", Where: []storage.Where{{Field: "clientId", Value: clientID}},
	})
	if err != nil || len(rows) != 1 || rows[0]["userId"] != userID || rows[0]["consentGiven"] != true {
		t.Fatalf("consents=%#v err=%v", rows, err)
	}

	noConsent := harness.register(t, "none", "no-consent-client", "http://localhost:3000/no-consent")
	direct, err := harness.call(t, "mcpOAuthAuthorize", http.MethodGet, sessionHeaders, nil, url.Values{
		"client_id": {noConsent["client_id"].(string)}, "redirect_uri": {"http://localhost:3000/no-consent"},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"direct-state"},
		"code_challenge": {"challenge"}, "code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	directLocation := headerValue(direct.Response.Headers(), "Location")
	if !strings.Contains(directLocation, "code=") || !strings.Contains(directLocation, "state=direct-state") ||
		strings.Contains(directLocation, "consent_code=") {
		t.Fatalf("direct location=%q", directLocation)
	}
}

func TestConsentDenialAndAtomicSingleDecision(t *testing.T) {
	harness := newHarness(t, nil)
	_, headers := harness.signUp(t, 4)
	seedClient(t, harness, "consent-deny-client", "", "public", false)
	state := "denied-state"
	seedCode(t, harness, "consent-deny-code", codeVerificationValue{
		ClientID: "consent-deny-client", RedirectURI: "http://localhost/callback",
		Scope: []string{"openid"}, UserID: "unused", RequireConsent: true, State: &state,
	})
	denied, err := harness.call(t, "oAuthConsent", http.MethodPost, headers, map[string]any{
		"accept": false, "consent_code": "consent-deny-code",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := responseObject(t, denied)["redirectURI"]; got != "http://localhost/callback?error=access_denied&error_description=User denied access" {
		t.Fatalf("redirect=%#v", got)
	}
	replayed, replayErr := harness.call(t, "oAuthConsent", http.MethodPost, headers, map[string]any{
		"accept": true, "consent_code": "consent-deny-code",
	}, nil)
	oauthErrorObject(t, replayed, replayErr, http.StatusUnauthorized, "invalid_request")
}

func TestOAuthLoginPromptCookieContinuesAuthorizationAfterSignIn(t *testing.T) {
	harness := newHarness(t, nil)
	_, _ = harness.signUp(t, 5)
	redirectURI := "http://localhost:3000/login-continuation/callback"
	registered := harness.register(t, "none", "login-continuation", redirectURI)
	clientID := registered["client_id"].(string)
	started, err := harness.call(t, "mcpOAuthAuthorize", http.MethodGet, contract.Headers{}, nil, url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid profile email"}, "state": {"login-state"}, "prompt": {"login"},
		"code_challenge": {"login-challenge"}, "code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if location := headerValue(started.Response.Headers(), "Location"); !strings.HasPrefix(location, "/login?") {
		t.Fatalf("login location=%q", location)
	}
	promptCookie := cookies.ApplySetCookies("", started.Response.Headers().Values("Set-Cookie"))
	if !strings.Contains(promptCookie, "oidc_login_prompt=") {
		t.Fatalf("prompt cookie=%q", promptCookie)
	}
	signedIn, err := harness.call(t, "signInEmail", http.MethodPost, contract.NewHeaders(
		contract.HeaderField{Name: "Cookie", Value: promptCookie},
	), map[string]any{
		"email": "mcp-user-5@example.test", "password": "password-12345",
	}, nil)
	if err != nil {
		t.Fatalf("sign in continuation: %v body=%s", err, signedIn.Response.Body())
	}
	location := headerValue(signedIn.Response.Headers(), "Location")
	if signedIn.Response.Status() != http.StatusFound || !strings.HasPrefix(location, redirectURI) ||
		!strings.Contains(location, "code=") || strings.Contains(location, "/api/auth/error") {
		t.Fatalf("continued status=%d location=%q body=%s", signedIn.Response.Status(), location, signedIn.Response.Body())
	}
	if !strings.Contains(strings.Join(signedIn.Response.Headers().Values("Set-Cookie"), ";"), "oidc_login_prompt=") {
		t.Fatalf("login prompt was not expired: %#v", signedIn.Response.Headers().Values("Set-Cookie"))
	}
}
