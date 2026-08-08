package oidcprovider

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/storage"
)

type oidcUnitExpectations struct {
	defaultAlgorithms []string
	legacyAlgorithms  []string
	endpointSuffixes  map[string]string
	scopes            []string
	claims            []string
	clientID          string
	responseType      string
	loginRedirect     string
	baseScopes        []string
	expandedScopes    []string
}

var oidcUnitCases = oidcUnitExpectations{
	defaultAlgorithms: []string{"HS256"},
	legacyAlgorithms:  []string{"HS256", "none"},
	endpointSuffixes: map[string]string{
		"authorization_endpoint": "/api/auth/oauth2/authorize",
		"jwks_uri":               "/api/auth/jwks",
		"registration_endpoint":  "/api/auth/oauth2/register",
		"token_endpoint":         "/api/auth/oauth2/token",
		"userinfo_endpoint":      "/api/auth/oauth2/userinfo",
	},
	scopes:        []string{"openid", "profile", "email", "offline_access"},
	claims:        []string{"sub", "iss", "aud", "exp", "nbf", "iat", "jti", "email", "email_verified", "name"},
	clientID:      "mock",
	responseType:  "code",
	loginRedirect: "/auth/login?client_id=mock&response_type=code",
	baseScopes:    []string{"openid", "profile"},
	expandedScopes: []string{
		"openid", "profile", "email",
	},
}

func TestUnitOIDCServerMetadataAndSecureDefault(t *testing.T) {
	expected := oidcUnitCases
	forEachOIDCUnitTransport(t, func(t *testing.T, build func(*testing.T, *harness) transportRoundTrip) {
		secure := newHarness(t, func(options *Options) {
			options.LoginPage = "/auth/login"
		}, jwt.NewFactory(jwt.Options{}))
		secureMetadata := readUnitDiscovery(t, build(t, secure))
		assertUnitMetadataSurface(t, secureMetadata, expected)
		if algorithms := unitStringSlice(t, secureMetadata["id_token_signing_alg_values_supported"]); !reflect.DeepEqual(algorithms, expected.defaultAlgorithms) {
			t.Fatalf("secure default algorithms = %#v, want %#v", algorithms, expected.defaultAlgorithms)
		}
		if containsAny(secureMetadata["id_token_signing_alg_values_supported"], "none") {
			t.Fatalf("secure default advertises unsigned ID tokens: %#v", secureMetadata)
		}

		legacy := newHarness(t, func(options *Options) {
			options.LoginPage = "/auth/login"
			options.Metadata = map[string]any{
				"id_token_signing_alg_values_supported": append([]string(nil), expected.legacyAlgorithms...),
			}
		}, jwt.NewFactory(jwt.Options{}))
		legacyMetadata := readUnitDiscovery(t, build(t, legacy))
		if algorithms := unitStringSlice(t, legacyMetadata["id_token_signing_alg_values_supported"]); !reflect.DeepEqual(algorithms, expected.legacyAlgorithms) {
			t.Fatalf("metadata override algorithms = %#v, want %#v", algorithms, expected.legacyAlgorithms)
		}
	})
}

func TestUnitOIDCAuthorizationCodeFlowRedirectsToLogin(t *testing.T) {
	expected := oidcUnitCases
	forEachOIDCUnitTransport(t, func(t *testing.T, build func(*testing.T, *harness) transportRoundTrip) {
		harness := newHarness(t, func(options *Options) {
			options.LoginPage = "/auth/login"
		}, jwt.NewFactory(jwt.Options{}))
		roundTrip := build(t, harness)
		_ = readUnitDiscovery(t, roundTrip)
		target := "/api/auth" + AuthorizePath + "?client_id=" +
			url.QueryEscape(expected.clientID) + "&response_type=" +
			url.QueryEscape(expected.responseType)
		response := roundTrip(http.MethodGet, target, "", nil, nil)
		if response.status != http.StatusFound ||
			response.headers.Get("Location") != expected.loginRedirect {
			t.Fatalf("authorization response status=%d location=%q body=%s", response.status, response.headers.Get("Location"), response.body)
		}
		if len(response.headers.Values("Set-Cookie")) == 0 {
			t.Fatal("authorization redirect did not persist the signed login prompt")
		}
	})
}

func TestUnitOIDCExpandedScopesRequireNewConsent(t *testing.T) {
	expected := oidcUnitCases
	forEachOIDCUnitTransport(t, func(t *testing.T, build func(*testing.T, *harness) transportRoundTrip) {
		harness := newHarness(t, func(options *Options) {
			options.LoginPage = "/auth/login"
			options.ConsentPage = "/auth/consent"
		}, jwt.NewFactory(jwt.Options{}))
		_, sessionHeaders := harness.signUp(t, 90)
		redirectURI := "https://rp.example.com/callback"
		registered := harness.register(t, sessionHeaders, "scope-test-client", []string{redirectURI})
		clientID := registered["client_id"].(string)
		roundTrip := build(t, harness)
		_ = readUnitDiscovery(t, roundTrip)
		cookie := headerValue(sessionHeaders, "Cookie")

		first := unitAuthorizeScopes(
			t, roundTrip, clientID, redirectURI, expected.baseScopes, cookie,
		)
		firstLocation := first.headers.Get("Location")
		firstURL, err := url.Parse(firstLocation)
		if err != nil || first.status != http.StatusFound || !strings.Contains(firstURL.Path, "/auth/consent") {
			t.Fatalf("initial authorization status=%d location=%q err=%v", first.status, firstLocation, err)
		}
		consentCode := firstURL.Query().Get("consent_code")
		if consentCode == "" {
			t.Fatalf("initial authorization omitted consent_code: %q", firstLocation)
		}
		accepted, err := harness.call(t, "oAuthConsent", http.MethodPost, sessionHeaders, map[string]any{
			"accept": true, "consent_code": consentCode,
		}, nil)
		if err != nil {
			t.Fatalf("accept consent: %v body=%s", err, accepted.Response.Body())
		}
		if redirect := responseObject(t, accepted)["redirectURI"].(string); !strings.Contains(redirect, "code=") {
			t.Fatalf("consent callback = %q", redirect)
		}

		unchanged := unitAuthorizeScopes(
			t, roundTrip, clientID, redirectURI, expected.baseScopes, cookie,
		)
		unchangedLocation := unchanged.headers.Get("Location")
		if unchanged.status != http.StatusFound || strings.Contains(unchangedLocation, "consent_code=") ||
			!strings.Contains(unchangedLocation, "code=") {
			t.Fatalf("unchanged scopes status=%d location=%q", unchanged.status, unchangedLocation)
		}

		expanded := unitAuthorizeScopes(
			t, roundTrip, clientID, redirectURI, expected.expandedScopes, cookie,
		)
		expandedLocation := expanded.headers.Get("Location")
		if expanded.status != http.StatusFound || !strings.Contains(expandedLocation, "consent_code=") {
			t.Fatalf("expanded scopes status=%d location=%q", expanded.status, expandedLocation)
		}
		consent, err := harness.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
			Model: "oauthConsent", Where: []storage.Where{
				{Field: "clientId", Value: clientID},
			},
		})
		if err != nil || consent == nil || consent["scopes"] != strings.Join(expected.baseScopes, " ") {
			t.Fatalf("persisted consent = %#v err=%v", consent, err)
		}
	})
}

func forEachOIDCUnitTransport(
	t *testing.T,
	run func(*testing.T, func(*testing.T, *harness) transportRoundTrip),
) {
	t.Helper()
	transports := []struct {
		name  string
		build func(*testing.T, *harness) transportRoundTrip
	}{
		{name: "net-http", build: netHTTPRoundTrip},
		{name: "fasthttp", build: fastHTTPRoundTrip},
		{name: "fiber", build: fiberRoundTrip},
	}
	for _, transport := range transports {
		transport := transport
		t.Run(transport.name, func(t *testing.T) { run(t, transport.build) })
	}
}

func readUnitDiscovery(t *testing.T, roundTrip transportRoundTrip) map[string]any {
	t.Helper()
	response := roundTrip(http.MethodGet, "/api/auth"+DiscoveryPath, "", nil, nil)
	if response.status != http.StatusOK {
		t.Fatalf("discovery status=%d body=%s", response.status, response.body)
	}
	var metadata map[string]any
	if err := json.Unmarshal(response.body, &metadata); err != nil {
		t.Fatal(err)
	}
	return metadata
}

func assertUnitMetadataSurface(t *testing.T, metadata map[string]any, expected oidcUnitExpectations) {
	t.Helper()
	for field, suffix := range expected.endpointSuffixes {
		value, ok := metadata[field].(string)
		if !ok || !strings.HasSuffix(value, suffix) {
			t.Fatalf("metadata[%q] = %#v, want suffix %q", field, metadata[field], suffix)
		}
	}
	expectedArrays := map[string][]string{
		"acr_values_supported":                  {"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"},
		"claims_supported":                      expected.claims,
		"code_challenge_methods_supported":      {"S256"},
		"grant_types_supported":                 {"authorization_code", "refresh_token"},
		"response_modes_supported":              {"query"},
		"response_types_supported":              {"code"},
		"scopes_supported":                      expected.scopes,
		"subject_types_supported":               {"public"},
		"token_endpoint_auth_methods_supported": {"client_secret_basic", "client_secret_post", "none"},
	}
	for field, expected := range expectedArrays {
		if actual := unitStringSlice(t, metadata[field]); !reflect.DeepEqual(actual, expected) {
			t.Fatalf("metadata[%q] = %#v, want %#v", field, actual, expected)
		}
	}
	issuer, ok := metadata["issuer"].(string)
	if !ok || !strings.Contains(issuer, "localhost") {
		t.Fatalf("metadata issuer = %#v", metadata["issuer"])
	}
}

func unitAuthorizeScopes(
	t *testing.T,
	roundTrip transportRoundTrip,
	clientID, redirectURI string,
	scopes []string,
	cookie string,
) transportResponse {
	t.Helper()
	query := url.Values{
		"client_id": {clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"scope": {strings.Join(scopes, " ")}, "code_challenge": {"challenge"},
		"code_challenge_method": {"S256"},
	}
	return roundTrip(
		http.MethodGet, "/api/auth"+AuthorizePath+"?"+query.Encode(), "", nil,
		http.Header{"Cookie": {cookie}},
	)
}

func unitStringSlice(t *testing.T, value any) []string {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		t.Fatalf("value is not a JSON array: %#v", value)
	}
	result := make([]string, len(values))
	for index, item := range values {
		stringValue, ok := item.(string)
		if !ok {
			t.Fatalf("array item %d is not a string: %#v", index, item)
		}
		result[index] = stringValue
	}
	return result
}
