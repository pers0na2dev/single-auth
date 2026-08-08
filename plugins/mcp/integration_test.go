package mcp

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestRegisterPublicAndConfidentialClients(t *testing.T) {
	harness := newHarness(t, nil)
	public := harness.register(t, "none", "test-public-client", "http://localhost:3000/public/callback")
	if public["client_id"] == "" || public["client_name"] != "test-public-client" ||
		public["token_endpoint_auth_method"] != "none" {
		t.Fatalf("public=%#v", public)
	}
	if _, exists := public["client_secret"]; exists {
		t.Fatalf("public client leaked secret: %#v", public)
	}
	if _, exists := public["client_secret_expires_at"]; exists {
		t.Fatalf("public client advertised secret expiry: %#v", public)
	}
	confidentialResult, err := harness.call(t, "registerMcpClient", http.MethodPost, contract.Headers{}, map[string]any{
		"client_name":   "test-confidential-client",
		"redirect_uris": []string{"http://localhost:3000/confidential/callback"},
		"logo_uri":      "", "token_endpoint_auth_method": "client_secret_basic",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	confidential := responseObject(t, confidentialResult)
	if confidential["client_secret"] == "" || confidential["client_secret_expires_at"] != json.Number("0") {
		t.Fatalf("confidential=%#v", confidential)
	}
	if got := headerValue(confidentialResult.Response.Headers(), "Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q", got)
	}
	if got := headerValue(confidentialResult.Response.Headers(), "Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control=%q", got)
	}
	if got := headerValue(confidentialResult.Response.Headers(), "Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("CORS=%q", got)
	}
}

func TestDiscoveryAndProtectedResourceMetadata(t *testing.T) {
	harness := newHarness(t, nil)
	discoveryResult, err := harness.call(t, "getMcpOAuthConfig", http.MethodGet, contract.Headers{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	discovery := responseObject(t, discoveryResult)
	want := map[string]any{
		"issuer":                 "http://localhost:3000",
		"authorization_endpoint": "http://localhost:3000/api/auth/mcp/authorize",
		"token_endpoint":         "http://localhost:3000/api/auth/mcp/token",
		"userinfo_endpoint":      "http://localhost:3000/api/auth/mcp/userinfo",
		"jwks_uri":               "http://localhost:3000/api/auth/mcp/jwks",
		"registration_endpoint":  "http://localhost:3000/api/auth/mcp/register",
	}
	for key, value := range want {
		if discovery[key] != value {
			t.Fatalf("discovery[%s]=%#v want=%#v", key, discovery[key], value)
		}
	}
	if containsAny(discovery["id_token_signing_alg_values_supported"], "none") {
		t.Fatalf("discovery advertises alg=none: %#v", discovery)
	}
	protectedResult, err := harness.call(t, "getMCPProtectedResource", http.MethodGet, contract.Headers{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	protected := responseObject(t, protectedResult)
	if protected["resource"] != "http://localhost:3000" ||
		!containsAny(protected["authorization_servers"], "http://localhost:3000") ||
		!containsAny(protected["bearer_methods_supported"], "header") {
		t.Fatalf("protected=%#v", protected)
	}
	if containsAny(protected["resource_signing_alg_values_supported"], "none") {
		t.Fatalf("protected metadata advertises alg=none: %#v", protected)
	}
}

func TestPublicPKCEAuthorizationTokenAndSessionFlow(t *testing.T) {
	harness := newHarness(t, nil)
	userID, headers := harness.signUp(t, 1)
	redirectURI := "http://localhost:3000/public/callback"
	registered := harness.register(t, "none", "public-pkce", redirectURI)
	clientID := registered["client_id"].(string)
	verifier := "correct-horse-battery-staple-verifier"
	challenge := pkceChallenge(verifier)
	authorized, err := harness.call(t, "mcpOAuthAuthorize", http.MethodGet, headers, nil, url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {"openid profile email"}, "state": {"state-123"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "nonce": {"nonce-123"},
	})
	if err != nil || authorized.Response.Status() != http.StatusFound {
		t.Fatalf("authorize status=%d err=%v body=%s", authorized.Response.Status(), err, authorized.Response.Body())
	}
	location := headerValue(authorized.Response.Headers(), "Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	code := parsed.Query().Get("code")
	if code == "" || parsed.Query().Get("state") != "state-123" ||
		strings.Contains(location, "consent_code=") {
		t.Fatalf("authorize location=%q", location)
	}

	exchanged, err := harness.call(t, "mcpOAuthToken", http.MethodPost, headers, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID,
		"code": code, "redirect_uri": redirectURI, "code_verifier": verifier,
	}, nil)
	if err != nil {
		t.Fatalf("exchange: %v body=%s", err, exchanged.Response.Body())
	}
	token := responseObject(t, exchanged)
	if token["access_token"] == "" || token["token_type"] != "Bearer" || token["id_token"] == "" {
		t.Fatalf("token=%#v", token)
	}
	if _, exists := token["refresh_token"]; exists {
		t.Fatalf("refresh token returned without offline_access: %#v", token)
	}
	claims := decodeJWTPayload(t, token["id_token"].(string))
	if claims["sub"] != userID || claims["aud"] != clientID || claims["nonce"] != "nonce-123" || claims["email"] == "" {
		t.Fatalf("claims=%#v", claims)
	}

	session, err := harness.call(t, "getMcpSession", http.MethodGet, contract.NewHeaders(
		contract.HeaderField{Name: "Authorization", Value: "Bearer " + token["access_token"].(string)},
	), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sessionObject := responseObject(t, session)
	if sessionObject["userId"] != userID || sessionObject["clientId"] != clientID {
		t.Fatalf("session=%#v", sessionObject)
	}

	missingVerifier, missingErr := harness.call(t, "mcpOAuthToken", http.MethodPost, headers, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID,
		"code": "not-even-looked-up", "redirect_uri": redirectURI,
	}, nil)
	object := oauthErrorObject(t, missingVerifier, missingErr, http.StatusBadRequest, "invalid_request")
	if !strings.Contains(object["error_description"].(string), "code verifier is missing") {
		t.Fatalf("missing verifier=%#v", object)
	}
}

func TestConfidentialClientAuthorizationAndNoStateRedirect(t *testing.T) {
	harness := newHarness(t, nil)
	_, headers := harness.signUp(t, 2)
	redirectURI := "http://localhost:3000/confidential/callback"
	registered := harness.register(t, "client_secret_basic", "confidential", redirectURI)
	clientID := registered["client_id"].(string)
	clientSecret := registered["client_secret"].(string)
	verifier := "confidential-client-verifier"
	authorized, err := harness.call(t, "mcpOAuthAuthorize", http.MethodGet, headers, nil, url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope":          {"openid profile email offline_access"},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	location := headerValue(authorized.Response.Headers(), "Location")
	parsed, _ := url.Parse(location)
	if parsed.Query().Has("state") || parsed.Query().Get("code") == "" {
		t.Fatalf("location=%q", location)
	}
	exchanged, err := harness.call(t, "mcpOAuthToken", http.MethodPost, headers, map[string]any{
		"grant_type": "authorization_code", "client_id": clientID, "client_secret": clientSecret,
		"code": parsed.Query().Get("code"), "redirect_uri": redirectURI, "code_verifier": verifier,
	}, nil)
	if err != nil {
		t.Fatalf("exchange: %v body=%s", err, exchanged.Response.Body())
	}
	token := responseObject(t, exchanged)
	if token["access_token"] == "" || token["refresh_token"] == "" {
		t.Fatalf("token=%#v", token)
	}
}

func TestAdvertisedUserInfoEndpointFrozenInvalidTokenBehavior(t *testing.T) {
	harness := newHarness(t, nil)
	request := contract.NewRequest(http.MethodGet, "/api/auth/mcp/userinfo", contract.RequestOptions{
		Scheme: "http", Host: "localhost:3000",
		Headers: contract.NewHeaders(contract.HeaderField{Name: "Authorization", Value: "Bearer invalid-token"}),
	})
	response, err := harness.auth.Dispatch(request)
	if err == nil || response.Status() != http.StatusNotFound {
		t.Fatalf("userinfo status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
}

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT=%q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]any{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func containsAny(value any, target string) bool {
	switch values := value.(type) {
	case []any:
		for _, value := range values {
			if value == target {
				return true
			}
		}
	case []string:
		return contains(values, target)
	}
	return false
}
