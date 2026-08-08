package oidcprovider

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/storage"
)

func TestDiscoveryMetadataAndEndSessionValidation(t *testing.T) {
	harness := newHarness(t, nil)
	_, headers := harness.signUp(t, 50)
	redirectURI := "https://client.example/logout"
	registered := harness.register(t, headers, "logout-client", []string{redirectURI})
	clientID := registered["client_id"].(string)

	discoveryResult, err := harness.call(t, "getOpenIdConfig", http.MethodGet, contract.Headers{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	discovery := responseObject(t, discoveryResult)
	if discovery["issuer"] != "http://localhost:3000" ||
		discovery["authorization_endpoint"] != "http://localhost:3000/api/auth/oauth2/authorize" ||
		discovery["token_endpoint"] != "http://localhost:3000/api/auth/oauth2/token" ||
		discovery["userinfo_endpoint"] != "http://localhost:3000/api/auth/oauth2/userinfo" ||
		discovery["jwks_uri"] != "http://localhost:3000/api/auth/jwks" ||
		discovery["registration_endpoint"] != "http://localhost:3000/api/auth/oauth2/register" ||
		discovery["end_session_endpoint"] != "http://localhost:3000/api/auth/oauth2/endsession" {
		t.Fatalf("discovery=%#v", discovery)
	}
	if containsAny(discovery["id_token_signing_alg_values_supported"], "none") ||
		!containsAny(discovery["id_token_signing_alg_values_supported"], "HS256") ||
		!equalAnyStrings(discovery["code_challenge_methods_supported"], []string{"S256"}) {
		t.Fatalf("discovery security metadata=%#v", discovery)
	}

	invalidClient, invalidClientErr := harness.call(t, "endSession", http.MethodGet, contract.Headers{}, nil, url.Values{
		"client_id": {"invalid-client"},
	})
	oauthErrorObject(t, invalidClient, invalidClientErr, http.StatusBadRequest, "invalid_client")

	missingClient, missingClientErr := harness.call(t, "endSession", http.MethodGet, contract.Headers{}, nil, url.Values{
		"post_logout_redirect_uri": {redirectURI},
	})
	missingObject := oauthErrorObject(t, missingClient, missingClientErr, http.StatusBadRequest, "invalid_request")
	if !strings.Contains(missingObject["error_description"].(string), "client_id is required") {
		t.Fatalf("missing client=%#v", missingObject)
	}

	unregistered, unregisteredErr := harness.call(t, "endSession", http.MethodGet, contract.Headers{}, nil, url.Values{
		"client_id": {clientID}, "post_logout_redirect_uri": {"https://evil.example/callback"},
	})
	unregisteredObject := oauthErrorObject(t, unregistered, unregisteredErr, http.StatusBadRequest, "invalid_request")
	if !strings.Contains(unregisteredObject["error_description"].(string), "not registered") {
		t.Fatalf("unregistered=%#v", unregisteredObject)
	}

	redirected, err := harness.call(t, "endSession", http.MethodGet, contract.NewHeaders(
		contract.HeaderField{Name: "Sec-Fetch-Site", Value: "same-origin"},
	), nil, url.Values{
		"client_id": {clientID}, "post_logout_redirect_uri": {redirectURI}, "state": {"test-state"},
	})
	if err != nil || redirected.Response.Status() != http.StatusFound {
		t.Fatalf("redirect status=%d err=%v body=%s", redirected.Response.Status(), err, redirected.Response.Body())
	}
	location := headerValue(redirected.Response.Headers(), "Location")
	if !strings.HasPrefix(location, redirectURI) || !strings.Contains(location, "state=test-state") {
		t.Fatalf("location=%q", location)
	}

	withoutParameters, err := harness.call(t, "endSession", http.MethodGet, contract.Headers{}, nil, nil)
	if err != nil || responseObject(t, withoutParameters)["success"] != true {
		t.Fatalf("GET status=%d err=%v body=%s", withoutParameters.Response.Status(), err, withoutParameters.Response.Body())
	}
	post, err := harness.call(t, "endSession", http.MethodPost, contract.Headers{}, nil, nil)
	if err != nil || responseObject(t, post)["message"] != "Logout successful" {
		t.Fatalf("POST status=%d err=%v body=%s", post.Response.Status(), err, post.Response.Body())
	}
}

func TestEndSessionRejectsCrossSiteCookieLogoutAndAllowsSameSite(t *testing.T) {
	harness := newHarness(t, nil)
	userID, sessionHeaders := harness.signUp(t, 51)
	seedClient(t, harness, Client{
		ClientID: "endsession-client", ClientSecret: "endsession-secret", Type: "web",
		Name: "End Session", RedirectURLs: []string{"http://localhost/callback"},
	})
	seedAccessToken(
		t, harness, userID, "endsession-client", "endsession-access", "endsession-refresh",
		"openid", harness.clock.Now().Add(time.Hour), harness.clock.Now().Add(24*time.Hour),
	)
	crossSiteHeaders := sessionHeaders.Clone()
	crossSiteHeaders.Set("Sec-Fetch-Site", "cross-site")
	blocked, blockedErr := harness.call(t, "endSession", http.MethodGet, crossSiteHeaders, nil, nil)
	oauthErrorObject(t, blocked, blockedErr, http.StatusForbidden, "invalid_request")
	state, err := harness.auth.API().GetSession(t.Context(), singleauth.GetSessionInput{Headers: sessionHeaders})
	if err != nil || state == nil || state.User.ID != userID {
		t.Fatalf("blocked logout removed session: state=%#v err=%v", state, err)
	}
	tokenRecord, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "accessToken", Value: "endsession-access"}},
	})
	if err != nil || tokenRecord == nil {
		t.Fatalf("blocked logout removed token: record=%#v err=%v", tokenRecord, err)
	}

	sameSiteHeaders := sessionHeaders.Clone()
	sameSiteHeaders.Set("Sec-Fetch-Site", "same-origin")
	allowed, err := harness.call(t, "endSession", http.MethodGet, sameSiteHeaders, nil, nil)
	if err != nil || responseObject(t, allowed)["success"] != true {
		t.Fatalf("allowed status=%d err=%v body=%s", allowed.Response.Status(), err, allowed.Response.Body())
	}
	state, err = harness.auth.API().GetSession(t.Context(), singleauth.GetSessionInput{Headers: sessionHeaders})
	if err != nil || state != nil {
		t.Fatalf("same-site logout retained session: state=%#v err=%v", state, err)
	}
	tokenRecord, err = harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "accessToken", Value: "endsession-access"}},
	})
	if err != nil || tokenRecord != nil {
		t.Fatalf("same-site logout retained token: record=%#v err=%v", tokenRecord, err)
	}
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

func equalAnyStrings(value any, expected []string) bool {
	values, ok := value.([]any)
	if !ok || len(values) != len(expected) {
		return false
	}
	for index, item := range values {
		if item != expected[index] {
			return false
		}
	}
	return true
}
