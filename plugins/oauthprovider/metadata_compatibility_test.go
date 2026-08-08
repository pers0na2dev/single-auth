package oauthprovider

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

type metadataCase struct {
	Suite       string
	Title       string
	Observation map[string]any
}

type metadataHarness struct {
	auth    *singleauth.Auth
	service *MetadataService
}

func TestOAuthProviderMetadataRuntime(t *testing.T) {
	for _, vector := range metadataCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			actual := runMetadataCompatibilityVector(t, vector.Suite, vector.Title)
			assertMetadataObservation(t, actual, vector.Observation)
		})
	}
}

func runMetadataCompatibilityVector(t *testing.T, suite, title string) map[string]any {
	t.Helper()
	switch suite + "::" + title {
	case "oauth metadata::should get openid, equivalent auth server":
		harness := newMetadataHarness(t, defaultMetadataTestOptions(), singleauth.Options{})
		openID, err := invokeMetadata(t, harness.auth, "getOpenIdConfig")
		if err != nil {
			t.Fatal(err)
		}
		oauth, err := invokeMetadata(t, harness.auth, "getOAuthServerConfig")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"openID": openID, "oauth": oauth}

	case "oauth metadata::should serve authorization server metadata at the issuer-appended well-known URL":
		harness := newMetadataHarness(t, defaultMetadataTestOptions(), singleauth.Options{})
		return metadataHTTPObservation(t, harness.auth, http.MethodGet, "/api/auth/.well-known/oauth-authorization-server")

	case "oauth metadata::should serve authorization server metadata at the RFC 8414 path-insertion URL":
		harness := newMetadataHarness(t, defaultMetadataTestOptions(), singleauth.Options{})
		return metadataHTTPObservation(t, harness.auth, http.MethodGet, "/.well-known/oauth-authorization-server/api/auth")

	case "oauth metadata::should advertise dynamic client registration from direct OAuth metadata when enabled":
		options := defaultMetadataTestOptions()
		options.Scopes = []string{"create:test"}
		harness := newMetadataHarness(t, options, singleauth.Options{})
		response := exchangeMetadataHTTP(t, harness.auth, http.MethodGet, "/api/auth/.well-known/oauth-authorization-server")
		body := decodeHTTPMetadata(t, response)
		observation := map[string]any{
			"status":       response.Code,
			"issuer":       body["issuer"],
			"cacheControl": response.Header().Get("Cache-Control"),
			"contentType":  response.Header().Get("Content-Type"),
		}
		observation["registrationEndpoint"] = body["registration_endpoint"]
		return observation

	case "oauth metadata::should serve OIDC metadata at the direct issuer well-known URL":
		harness := newMetadataHarness(t, defaultMetadataTestOptions(), singleauth.Options{})
		return metadataHTTPObservation(t, harness.auth, http.MethodGet, "/api/auth/.well-known/openid-configuration")

	case "oauth metadata::should restrict direct metadata requests to GET and HEAD":
		harness := newMetadataHarness(t, defaultMetadataTestOptions(), singleauth.Options{})
		authorizationPaths := []string{
			"/api/auth/.well-known/oauth-authorization-server",
			"/.well-known/oauth-authorization-server/api/auth",
		}
		headStatuses := make([]int, 0, len(authorizationPaths))
		headBodies := make([]string, 0, len(authorizationPaths))
		for _, path := range authorizationPaths {
			response := exchangeMetadataHTTP(t, harness.auth, http.MethodHead, path)
			headStatuses = append(headStatuses, response.Code)
			headBodies = append(headBodies, response.Body.String())
		}
		postPaths := append(append([]string{}, authorizationPaths...), "/api/auth/.well-known/openid-configuration")
		postStatuses := make([]int, 0, len(postPaths))
		postAllows := make([]string, 0, len(postPaths))
		for _, path := range postPaths {
			response := exchangeMetadataHTTP(t, harness.auth, http.MethodPost, path)
			postStatuses = append(postStatuses, response.Code)
			postAllows = append(postAllows, response.Header().Get("Allow"))
		}
		return map[string]any{
			"headStatuses": headStatuses, "headBodies": headBodies,
			"postStatuses": postStatuses, "postAllows": postAllows,
		}

	case "oauth metadata::should only skip trailing slashes when configured":
		path := "/.well-known/oauth-authorization-server/api/auth/"
		strict := newMetadataHarness(t, defaultMetadataTestOptions(), singleauth.Options{})
		strictResponse := exchangeMetadataHTTP(t, strict.auth, http.MethodGet, path)
		rootOptions := singleauth.Options{}
		rootOptions.Advanced.SkipTrailingSlashes = true
		permissive := newMetadataHarness(t, defaultMetadataTestOptions(), rootOptions)
		permissiveResponse := exchangeMetadataHTTP(t, permissive.auth, http.MethodGet, path)
		body := decodeHTTPMetadata(t, permissiveResponse)
		return map[string]any{
			"defaultStatus": strictResponse.Code,
			"skipStatus":    permissiveResponse.Code,
			"skipIssuer":    body["issuer"],
		}

	case "oauth metadata::should not have an openid-configuration, has auth server configuration":
		options := defaultMetadataTestOptions()
		options.Scopes = []string{"create:test"}
		harness := newMetadataHarness(t, options, singleauth.Options{})
		_, openIDErr := invokeMetadata(t, harness.auth, "getOpenIdConfig")
		oauth, err := invokeMetadata(t, harness.auth, "getOAuthServerConfig")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"openIDError": metadataOpenIDErrorObservation(openIDErr), "oauth": oauth}

	case "oauth metadata::should not provide dynamic client registration endpoint when disabled":
		options := defaultMetadataTestOptions()
		options.AllowDynamicClientRegistration = false
		return registrationPresenceObservation(t, options)

	case "oauth metadata::should not provide dynamic client registration endpoint when undefined":
		options := defaultMetadataTestOptions()
		options.AllowDynamicClientRegistration = false
		return registrationPresenceObservation(t, options)

	case "oauth metadata::should utilize advertised metadata fields":
		options := defaultMetadataTestOptions()
		options.AdvertisedMetadata = MetadataAdvertisedOptions{
			ScopesSupported: []string{"email"},
			ClaimsSupported: []string{"sub", "iss", "aud", "exp", "iat", "scope"},
		}
		harness := newMetadataHarness(t, options, singleauth.Options{})
		openID, err := invokeMetadata(t, harness.auth, "getOpenIdConfig")
		if err != nil {
			t.Fatal(err)
		}
		oauth, err := invokeMetadata(t, harness.auth, "getOAuthServerConfig")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"openID": openID, "oauth": oauth}

	case "oauth metadata::should fail if advertised scope invalid":
		options := defaultMetadataTestOptions()
		options.AdvertisedMetadata.ScopesSupported = []string{"create:test"}
		_, err := NewMetadataService(
			options,
			func(contract.Request) (string, error) {
				return "http://localhost:3000/api/auth", nil
			},
			false,
		)
		return metadataErrorObservation(err)

	case "oauth metadata::should advertise custom claims":
		claims := append([]string{}, baseMetadataClaims...)
		claims = append(claims,
			"email", "email_verified", "name", "picture", "family_name", "given_name",
			"http://example.com/roles",
		)
		options := defaultMetadataTestOptions()
		options.AdvertisedMetadata.ClaimsSupported = claims
		harness := newMetadataHarness(t, options, singleauth.Options{})
		openID, err := invokeMetadata(t, harness.auth, "getOpenIdConfig")
		if err != nil {
			t.Fatal(err)
		}
		oauth, err := invokeMetadata(t, harness.auth, "getOAuthServerConfig")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"claims": openID["claims_supported"], "oauthClaims": oauth["claims_supported"],
		}

	case "oauth metadata::should use the remoteJwks url":
		options := defaultMetadataTestOptions()
		options.JWT.RemoteJWKSURL = "http://example.com/.well-known/openid-configuration"
		options.JWT.SigningAlgorithm = "ES256"
		harness := newMetadataHarness(t, options, singleauth.Options{})
		openID, err := invokeMetadata(t, harness.auth, "getOpenIdConfig")
		if err != nil {
			t.Fatal(err)
		}
		oauth, err := invokeMetadata(t, harness.auth, "getOAuthServerConfig")
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"jwksURI":           openID["jwks_uri"],
			"signingAlgorithms": openID["id_token_signing_alg_values_supported"],
			"oauthJWKSURI":      oauth["jwks_uri"],
		}

	case "oauth metadata::should support disableJwtPlugin":
		options := defaultMetadataTestOptions()
		options.DisableJWT = true
		harness := newMetadataHarness(t, options, singleauth.Options{})
		openID, err := invokeMetadata(t, harness.auth, "getOpenIdConfig")
		if err != nil {
			t.Fatal(err)
		}
		oauth, err := invokeMetadata(t, harness.auth, "getOAuthServerConfig")
		if err != nil {
			t.Fatal(err)
		}
		_, jwksPresent := openID["jwks_uri"]
		return map[string]any{
			"signingAlgorithms":      openID["id_token_signing_alg_values_supported"],
			"oauthSigningAlgorithms": oauth["id_token_signing_alg_values_supported"],
			"jwksPresent":            jwksPresent,
		}

	case "dynamic baseURL metadata wrappers::oauthProviderAuthServerMetadata resolves baseURL from the incoming request":
		harness := newDynamicMetadataHarness(t)
		handler := OAuthProviderAuthServerMetadata(harness.service)
		response, err := handler(dynamicMetadataRequest("/.well-known/oauth-authorization-server"))
		if err != nil {
			t.Fatal(err)
		}
		return metadataContractResponseObservation(t, response)

	case "dynamic baseURL metadata wrappers::oauthProviderOpenIdConfigMetadata resolves baseURL from the incoming request":
		harness := newDynamicMetadataHarness(t)
		handler := OAuthProviderOpenIDConfigMetadata(harness.service)
		response, err := handler(dynamicMetadataRequest("/.well-known/openid-configuration"))
		if err != nil {
			t.Fatal(err)
		}
		return metadataContractResponseObservation(t, response)

	default:
		t.Fatalf("unhandled single-auth metadata runtime ID %s::%s", suite, title)
		return nil
	}
}

func defaultMetadataTestOptions() MetadataPluginOptions {
	return MetadataPluginOptions{AllowDynamicClientRegistration: true}
}

func newMetadataHarness(
	t *testing.T,
	metadataOptions MetadataPluginOptions,
	rootOptions singleauth.Options,
) metadataHarness {
	t.Helper()
	factory := NewMetadataFactory(metadataOptions)
	if rootOptions.BaseURL == "" && rootOptions.DynamicBaseURL == nil {
		rootOptions.BaseURL = "http://localhost:3000"
	}
	rootOptions.PluginFactories = append(rootOptions.PluginFactories, factory)
	auth, err := singleauth.New(rootOptions)
	if err != nil {
		t.Fatal(err)
	}
	service, err := factory.Service()
	if err != nil {
		t.Fatal(err)
	}
	return metadataHarness{auth: auth, service: service}
}

func newDynamicMetadataHarness(t *testing.T) metadataHarness {
	t.Helper()
	return newMetadataHarness(t, defaultMetadataTestOptions(), singleauth.Options{
		DynamicBaseURL: &singleauth.DynamicBaseURLOptions{
			AllowedHosts: []string{"tenant.example.com"},
			Protocol:     "https",
			Fallback:     "https://fallback.example.com",
		},
	})
}

func invokeMetadata(t *testing.T, auth *singleauth.Auth, name string) (map[string]any, error) {
	t.Helper()
	response, err := auth.Invoke(name, engine.DirectInput{Request: contract.NewRequest(
		http.MethodGet,
		"/:direct",
		contract.RequestOptions{Scheme: "http", Host: "localhost:3000"},
	)})
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if decodeErr := json.Unmarshal(response.Body(), &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	return result, nil
}

func registrationPresenceObservation(t *testing.T, options MetadataPluginOptions) map[string]any {
	t.Helper()
	harness := newMetadataHarness(t, options, singleauth.Options{})
	openID, err := invokeMetadata(t, harness.auth, "getOpenIdConfig")
	if err != nil {
		t.Fatal(err)
	}
	oauth, err := invokeMetadata(t, harness.auth, "getOAuthServerConfig")
	if err != nil {
		t.Fatal(err)
	}
	_, openIDPresent := openID["registration_endpoint"]
	_, oauthPresent := oauth["registration_endpoint"]
	return map[string]any{
		"openIDRegistrationPresent": openIDPresent,
		"oauthRegistrationPresent":  oauthPresent,
	}
}

func metadataHTTPObservation(
	t *testing.T,
	auth *singleauth.Auth,
	method, path string,
) map[string]any {
	t.Helper()
	response := exchangeMetadataHTTP(t, auth, method, path)
	body := decodeHTTPMetadata(t, response)
	return map[string]any{
		"status":       response.Code,
		"issuer":       body["issuer"],
		"cacheControl": response.Header().Get("Cache-Control"),
		"contentType":  response.Header().Get("Content-Type"),
	}
}

func exchangeMetadataHTTP(
	t *testing.T,
	auth *singleauth.Auth,
	method, path string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "http://localhost:3000"+path, nil)
	request.Host = "localhost:3000"
	response := httptest.NewRecorder()
	auth.ServeHTTP(response, request)
	return response
}

func decodeHTTPMetadata(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode metadata status=%d body=%q: %v", response.Code, response.Body.String(), err)
	}
	return result
}

func dynamicMetadataRequest(path string) contract.Request {
	return contract.NewRequest(http.MethodGet, path, contract.RequestOptions{
		Scheme: "https", Host: "tenant.example.com",
	})
}

func metadataContractResponseObservation(t *testing.T, response contract.Response) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(response.Body(), &body); err != nil {
		t.Fatal(err)
	}
	cacheControl, _ := response.Headers().Get("Cache-Control")
	contentType, _ := response.Headers().Get("Content-Type")
	return map[string]any{
		"status": response.Status(), "issuer": body["issuer"],
		"cacheControl": cacheControl, "contentType": contentType,
	}
}

func metadataErrorObservation(err error) map[string]any {
	if err == nil {
		return map[string]any{"errorName": "", "errorMessage": ""}
	}
	observation := map[string]any{"errorMessage": err.Error()}
	var apiError *contract.APIError
	var referenceError *ReferenceError
	switch {
	case errors.As(err, &apiError):
		observation["errorName"] = "APIError"
		observation["status"] = apiError.Status
		observation["code"] = apiError.Code
	case errors.As(err, &referenceError):
		observation["errorName"] = "ReferenceError"
	default:
		observation["errorName"] = reflect.TypeOf(err).String()
	}
	return observation
}

func metadataOpenIDErrorObservation(err error) map[string]any {
	observation := map[string]any{
		"name": "", "message": "", "status": nil, "code": nil,
	}
	if err == nil {
		return observation
	}
	var apiError *contract.APIError
	if errors.As(err, &apiError) {
		observation["name"] = "APIError"
		observation["status"] = apiError.Code
		return observation
	}
	observation["name"] = reflect.TypeOf(err).String()
	observation["message"] = err.Error()
	return observation
}

func assertMetadataObservation(t *testing.T, actual, expected map[string]any) {
	t.Helper()
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	var actualCanonical any
	var expectedCanonical any
	if err := json.Unmarshal(actualJSON, &actualCanonical); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expectedJSON, &expectedCanonical); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualCanonical, expectedCanonical) {
		t.Fatalf("metadata observation mismatch\nactual:   %s\nexpected: %s", actualJSON, expectedJSON)
	}
}
