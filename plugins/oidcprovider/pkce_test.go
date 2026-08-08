package oidcprovider

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestPKCESecurityGatesAndPlainOptInPersistence(t *testing.T) {
	trusted := Client{
		ClientID: "pkce-client", ClientSecret: "test-client-secret", Type: "web",
		Name: "test", RedirectURLs: []string{"http://localhost:3000/cb"}, SkipConsent: true,
	}
	build := func(allowPlain bool) *harness {
		return newHarness(t, func(options *Options) {
			options.RequirePKCE = false
			options.AllowPlainCodeChallengeMethod = allowPlain
			options.TrustedClients = []Client{trusted}
		})
	}
	base := url.Values{
		"client_id": {trusted.ClientID}, "redirect_uri": {trusted.RedirectURLs[0]},
		"response_type": {"code"}, "scope": {"openid profile email"}, "state": {"xyz"},
	}

	secure := build(false)
	_, secureHeaders := secure.signUp(t, 30)
	plainQuery := cloneValues(base)
	plainQuery.Set("code_challenge", "plainPkceVerifier_at_least_43_chars_long_for_validity")
	plainQuery.Set("code_challenge_method", "plain")
	plain, err := secure.call(t, "oAuth2authorize", http.MethodGet, secureHeaders, nil, plainQuery)
	plainLocation := headerValue(plain.Response.Headers(), "Location")
	if err != nil || !strings.Contains(plainLocation, "error=invalid_request") ||
		!strings.Contains(plainLocation, "invalid") || !strings.Contains(plainLocation, "challenge") {
		t.Fatalf("plain status=%d err=%v location=%q", plain.Response.Status(), err, plainLocation)
	}

	missingMethodQuery := cloneValues(base)
	missingMethodQuery.Set("code_challenge", "someChallengeValue_at_least_43_chars_long_for_validity")
	missingMethod, err := secure.call(t, "oAuth2authorize", http.MethodGet, secureHeaders, nil, missingMethodQuery)
	missingMethodLocation := headerValue(missingMethod.Response.Headers(), "Location")
	if err != nil || !strings.Contains(missingMethodLocation, "error=invalid_request") ||
		strings.Contains(missingMethodLocation, "code=") {
		t.Fatalf("missing method status=%d err=%v location=%q", missingMethod.Response.Status(), err, missingMethodLocation)
	}

	missingChallengeQuery := cloneValues(base)
	missingChallengeQuery.Set("code_challenge_method", "S256")
	missingChallenge, err := secure.call(t, "oAuth2authorize", http.MethodGet, secureHeaders, nil, missingChallengeQuery)
	missingChallengeLocation := headerValue(missingChallenge.Response.Headers(), "Location")
	if err != nil || !strings.Contains(missingChallengeLocation, "error=invalid_request") ||
		strings.Contains(missingChallengeLocation, "code=") {
		t.Fatalf("missing challenge status=%d err=%v location=%q", missingChallenge.Response.Status(), err, missingChallengeLocation)
	}

	legacy := build(true)
	_, legacyHeaders := legacy.signUp(t, 31)
	legacyQuery := cloneValues(base)
	challenge := "someChallengeValue_at_least_43_chars_long_for_validity"
	legacyQuery.Set("code_challenge", challenge)
	accepted, err := legacy.call(t, "oAuth2authorize", http.MethodGet, legacyHeaders, nil, legacyQuery)
	acceptedLocation := headerValue(accepted.Response.Headers(), "Location")
	if err != nil || !strings.Contains(acceptedLocation, "code=") || strings.Contains(acceptedLocation, "error=") {
		t.Fatalf("legacy status=%d err=%v location=%q", accepted.Response.Status(), err, acceptedLocation)
	}
	code := mustURL(t, acceptedLocation).Query().Get("code")
	record, err := legacy.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: code}},
	})
	if err != nil || record == nil {
		t.Fatalf("verification=%#v err=%v", record, err)
	}
	raw, _ := recordString(record, "value")
	var stored AuthorizationCodeValue
	if err := json.Unmarshal([]byte(raw), &stored); err != nil || stored.CodeChallengeMethod != "plain" {
		t.Fatalf("stored=%#v err=%v raw=%s", stored, err, raw)
	}
}

func TestRequiredPKCEAndBrowserFetchRedirectShape(t *testing.T) {
	trusted := Client{
		ClientID: "required-pkce", ClientSecret: "secret", Type: "web", Name: "test",
		RedirectURLs: []string{"https://client.example/callback"}, SkipConsent: true,
	}
	harness := newHarness(t, func(options *Options) {
		options.TrustedClients = []Client{trusted}
		options.RequirePKCE = true
	})
	_, headers := harness.signUp(t, 32)
	query := url.Values{
		"client_id": {trusted.ClientID}, "redirect_uri": {trusted.RedirectURLs[0]},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"state"},
	}
	missing, err := harness.call(t, "oAuth2authorize", http.MethodGet, headers, nil, query)
	if err != nil || !strings.Contains(headerValue(missing.Response.Headers(), "Location"), "pkce is required") {
		t.Fatalf("missing status=%d err=%v location=%q", missing.Response.Status(), err, headerValue(missing.Response.Headers(), "Location"))
	}
	browserHeaders := headers.Clone()
	browserHeaders.Set("Sec-Fetch-Mode", "cors")
	query.Set("code_challenge", pkceChallenge("browser-verifier"))
	query.Set("code_challenge_method", "S256")
	browser, err := harness.call(t, "oAuth2authorize", http.MethodGet, browserHeaders, nil, query)
	if err != nil || browser.Response.Status() != http.StatusOK {
		t.Fatalf("browser status=%d err=%v body=%s", browser.Response.Status(), err, browser.Response.Body())
	}
	body := responseObject(t, browser)
	if body["redirect"] != true || !strings.Contains(body["url"].(string), "code=") {
		t.Fatalf("browser body=%#v", body)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
