package jwt

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestConfigurationValidationMatchesUpstream(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
	store := &keyStore{}
	base := baseTestOptions(store, clock)

	tests := []struct {
		name    string
		mutate  func(*Options)
		message string
	}{
		{
			"remote-sign-needs-url", func(options *Options) {
				options.Token.Sign = func(context.Context, map[string]any) (string, error) { return "", nil }
			},
			"options.jwks.remoteUrl must be set when using options.jwt.sign",
		},
		{
			"remote-url-needs-alg", func(options *Options) { options.JWKS.RemoteURL = "not-a-url" },
			"options.jwks.keyPairConfig.alg must be specified when using the oidc plugin with options.jwks.remoteUrl",
		},
		{
			"relative-jwks-path", func(options *Options) { options.JWKS.Path = String("jwks") },
			"options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'",
		},
		{
			"empty-jwks-path", func(options *Options) { options.JWKS.Path = String("") },
			"options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'",
		},
		{
			"traversal-jwks-path", func(options *Options) { options.JWKS.Path = String("/keys/../jwks") },
			"options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := base
			test.mutate(&options)
			_, err := New(options)
			if err == nil || err.Error() != test.message {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestRemoteURLAcceptsAnyStringWhenAlgorithmIsPresent(t *testing.T) {
	clock := &testClock{now: time.Now()}
	for _, remote := range []string{
		"not-a-url", "http://", "//example.com", "example.com/jwks",
		"https://example.com/.well-known/jwks.json", "https://auth.example.com/jwks",
		"https://api.example.com/v1/keys", "https://example.com:8080/jwks.json",
		"https://example.com/jwks?version=1&format=json",
	} {
		options := baseTestOptions(&keyStore{}, clock)
		options.JWKS.RemoteURL = remote
		options.JWKS.KeyPair = &KeyPairConfig{Algorithm: ES256}
		if _, err := New(options); err != nil {
			t.Errorf("remote URL %q rejected: %v", remote, err)
		}
	}
	for _, algorithm := range []Algorithm{ES256, ES512, RS256, PS256, EdDSA} {
		options := baseTestOptions(&keyStore{}, clock)
		options.JWKS.RemoteURL = "https://example.com/.well-known/jwks.json"
		options.JWKS.KeyPair = &KeyPairConfig{Algorithm: algorithm}
		if _, err := New(options); err != nil {
			t.Errorf("remote algorithm %s rejected: %v", algorithm, err)
		}
	}
}

func TestExportedHelpersDoNotRunPluginConstructorValidation(t *testing.T) {
	called := false
	options := Options{
		JWKS: JWKSOptions{Path: String("invalid-relative-path")},
		Token: TokenOptions{Sign: func(_ context.Context, payload map[string]any) (string, error) {
			called = payload["sub"] == "helper"
			return "remote-helper-token", nil
		}},
		Runtime: Runtime{
			Clock:   func() time.Time { return time.Unix(1000, 0) },
			BaseURL: "https://auth.example.test",
		},
	}
	token, err := SignJWT(nil, options, map[string]any{"sub": "helper"})
	if err != nil || token != "remote-helper-token" || !called {
		t.Fatalf("token=%q called=%v err=%v", token, called, err)
	}
	if _, err := GenerateExportedKeyPair(options); err != nil {
		t.Fatalf("key utility ran descriptor validation: %v", err)
	}
}

func TestDescriptorSurfaceAndCustomPath(t *testing.T) {
	clock := &testClock{now: time.Now()}
	options := baseTestOptions(&keyStore{}, clock)
	options.JWKS.Path = String("/.well-known/jwks.json")
	dispatcher, descriptor := newTestDispatcher(t, options)
	if descriptor.ID != PluginID || descriptor.Version != Version || len(descriptor.Endpoints) != 4 || len(descriptor.Hooks.After) != 1 {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	want := map[string]struct {
		path       string
		serverOnly bool
	}{
		"getJwks":   {"/.well-known/jwks.json", false},
		"getToken":  {"/token", false},
		"signJWT":   {"", true},
		"verifyJWT": {"", true},
	}
	for _, endpoint := range descriptor.Endpoints {
		expected, ok := want[endpoint.Name]
		if !ok || endpoint.Path != expected.path || endpoint.ServerOnly != expected.serverOnly {
			t.Fatalf("endpoint = %#v", endpoint)
		}
	}
	response, err := dispatcher.Dispatch(request(http.MethodGet, "/.well-known/jwks.json", nil))
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("custom JWKS status=%d err=%v", response.Status(), err)
	}
	response, err = dispatcher.Dispatch(request(http.MethodGet, "/jwks", nil))
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != http.StatusNotFound || response.Status() != http.StatusNotFound {
		t.Fatalf("old JWKS status=%d err=%#v", response.Status(), err)
	}
}

func TestJWKSGenerationAndRemoteDisable(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
	store := &keyStore{}
	options := baseTestOptions(store, clock)
	dispatcher, _ := newTestDispatcher(t, options)
	response, err := dispatcher.Dispatch(request(http.MethodGet, "/jwks", nil))
	if err != nil || response.Status() != http.StatusOK {
		t.Fatalf("jwks status=%d err=%v body=%s", response.Status(), err, response.Body())
	}
	value := decodeObjectResponse(t, response)
	keys := value["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("keys = %#v", keys)
	}
	key := keys[0].(map[string]any)
	if key["alg"] != "EdDSA" || key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["kid"] != "key-1" {
		t.Fatalf("public JWK = %#v", key)
	}
	stored := store.snapshot()
	if len(stored) != 1 || stored[0].Algorithm != EdDSA || stored[0].Curve != "Ed25519" || !strings.HasPrefix(stored[0].PrivateKey, `"`) || strings.Contains(stored[0].PublicKey, `"d"`) {
		t.Fatalf("stored key = %#v", stored)
	}

	remoteOptions := baseTestOptions(&keyStore{}, clock)
	remoteOptions.JWKS.RemoteURL = "not-a-url"
	remoteOptions.JWKS.KeyPair = &KeyPairConfig{Algorithm: ES256}
	remoteDispatcher, _ := newTestDispatcher(t, remoteOptions)
	response, err = remoteDispatcher.Dispatch(request(http.MethodGet, "/jwks", nil))
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != http.StatusNotFound || response.Status() != http.StatusNotFound {
		t.Fatalf("remote JWKS status=%d err=%#v", response.Status(), err)
	}
}

func TestSignAndVerifyAllAlgorithmsWithEncryptedAndPlainKeys(t *testing.T) {
	algorithms := []KeyPairConfig{
		{Algorithm: EdDSA, Curve: "Ed25519"}, {Algorithm: ES256}, {Algorithm: ES512},
		{Algorithm: PS256}, {Algorithm: RS256},
	}
	for _, config := range algorithms {
		for _, disabled := range []bool{false, true} {
			name := string(config.Algorithm)
			if disabled {
				name += "-plain"
			}
			t.Run(name, func(t *testing.T) {
				clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
				store := &keyStore{}
				options := baseTestOptions(store, clock)
				options.JWKS.KeyPair = &config
				options.JWKS.DisablePrivateKeyEncryption = disabled
				options.Token.Issuer = String("https://example.com")
				options.Token.Audience = "https://example.com"
				implementation, err := normalize(options, false)
				if err != nil {
					t.Fatal(err)
				}
				token, err := implementation.signJWT(nil, map[string]any{
					"sub": "123", "exp": clock.Now().Unix() + 600, "iat": clock.Now().Unix(),
					"iss": "https://example.com", "aud": "https://example.com", "custom": "custom",
				})
				if err != nil {
					t.Fatal(err)
				}
				header, payload := tokenParts(t, token)
				if header["alg"] != string(config.Algorithm) || header["kid"] != "key-1" || payload["custom"] != "custom" {
					t.Fatalf("header=%#v payload=%#v", header, payload)
				}
				verified := implementation.verifyJWT(nil, token)
				if verified == nil || verified["sub"] != "123" {
					t.Fatalf("verified = %#v", verified)
				}
				parts := strings.Split(token, ".")
				first := byte('A')
				if parts[2][0] == first {
					first = 'B'
				}
				parts[2] = string(first) + parts[2][1:]
				mutated := strings.Join(parts, ".")
				if implementation.verifyJWT(nil, mutated) != nil {
					t.Fatal("mutated signature verified")
				}
				stored := store.snapshot()[0]
				if disabled {
					if !strings.HasPrefix(stored.PrivateKey, "{") {
						t.Fatalf("plain private key = %q", stored.PrivateKey)
					}
				} else if !strings.HasPrefix(stored.PrivateKey, `"`) {
					t.Fatalf("encrypted private key = %q", stored.PrivateKey)
				}
			})
		}
	}
}

func TestTokenEndpointAndServerOnlyEndpoints(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
	store := &keyStore{}
	options := baseTestOptions(store, clock)
	dispatcher, _ := newTestDispatcher(t, options)
	response, err := dispatcher.Dispatch(request(http.MethodGet, "/token", nil))
	if err != nil {
		t.Fatal(err)
	}
	token := decodeObjectResponse(t, response)["token"].(string)
	_, payload := tokenParts(t, token)
	if payload["sub"] != "user-1" || payload["id"] != "user-1" || payload["iss"] != "http://localhost:3000" || payload["aud"] != "http://localhost:3000" {
		t.Fatalf("payload = %#v", payload)
	}
	if _, err := dispatcher.Dispatch(request(http.MethodPost, "/sign-jwt", map[string]any{"payload": map[string]any{"sub": "x"}})); err == nil {
		t.Fatal("server-only sign endpoint was HTTP reachable")
	}

	response, err = dispatcher.Invoke("signJWT", engine.DirectInput{Request: request(http.MethodPost, "/:direct", map[string]any{
		"payload": map[string]any{"sub": "direct", "iss": "http://localhost:3000", "aud": "http://localhost:3000"},
	})})
	if err != nil {
		t.Fatal(err)
	}
	directToken := decodeObjectResponse(t, response)["token"].(string)
	response, err = dispatcher.Invoke("verifyJWT", engine.DirectInput{Request: request(http.MethodPost, "/:direct", map[string]any{
		"token": directToken,
	})})
	if err != nil {
		t.Fatal(err)
	}
	verified := decodeObjectResponse(t, response)["payload"].(map[string]any)
	if verified["sub"] != "direct" {
		t.Fatalf("verified = %#v", verified)
	}
}

func TestGetSessionHookSetsJWTAndExposesHeader(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
	options := baseTestOptions(&keyStore{}, clock)
	core := engine.Endpoint{
		Name: "getSession", Path: "/get-session", Methods: []string{http.MethodGet},
		Handler: func(*engine.Context) (contract.Response, error) {
			response, err := contract.JSONResponse(http.StatusOK, map[string]any{"session": true})
			return response.WithHeader("Access-Control-Expose-Headers", "x-existing, x-existing"), err
		},
	}
	dispatcher, _ := newTestDispatcher(t, options, core)
	response, err := dispatcher.Dispatch(request(http.MethodGet, "/get-session", nil))
	if err != nil {
		t.Fatal(err)
	}
	jwtHeader, _ := response.Headers().Get("set-auth-jwt")
	exposed, _ := response.Headers().Get("Access-Control-Expose-Headers")
	if jwtHeader == "" || exposed != "x-existing, set-auth-jwt" {
		t.Fatalf("headers = %#v", response.Headers().Fields())
	}

	options.DisableSettingJWTHeader = true
	disabled, _ := newTestDispatcher(t, options, core)
	response, err = disabled.Dispatch(request(http.MethodGet, "/get-session", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := response.Headers().Get("set-auth-jwt"); exists {
		t.Fatal("disabled plugin set JWT header")
	}
}

func TestCustomRemoteSignReceivesResolvedClaims(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
	options := baseTestOptions(&keyStore{}, clock)
	options.JWKS.RemoteURL = "https://keys.example.test/jwks"
	options.JWKS.KeyPair = &KeyPairConfig{Algorithm: ES256}
	var received map[string]any
	options.Token.Sign = func(_ context.Context, payload map[string]any) (string, error) {
		received = cloneMap(payload)
		header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT"})
		body, _ := json.Marshal(payload)
		return rawURL.EncodeToString(header) + "." + rawURL.EncodeToString(body) + ".mock-signature", nil
	}
	implementation, err := normalize(options, false)
	if err != nil {
		t.Fatal(err)
	}
	token, err := implementation.signJWT(nil, map[string]any{"sub": "remote"})
	if err != nil || !strings.Contains(token, "mock-signature") {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if received["sub"] != "remote" || received["iss"] != "http://localhost:3000" || received["aud"] != "http://localhost:3000" || received["exp"] != float64(clock.Now().Unix()+900) {
		t.Fatalf("remote payload = %#v", received)
	}
}

func TestExplicitEmptyIssuerAndSubjectFollowNullishSemantics(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)}
	options := baseTestOptions(&keyStore{}, clock)
	options.Token.Issuer = String("")
	options.Token.Audience = "audience"
	options.Token.GetSubject = func(*engine.Context, SessionState) (*string, error) {
		return String(""), nil
	}
	implementation, err := normalize(options, false)
	if err != nil {
		t.Fatal(err)
	}
	state, err := options.Runtime.ResolveSession(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	token, err := implementation.getJWTToken(nil, *state)
	if err != nil {
		t.Fatal(err)
	}
	_, payload := tokenParts(t, token)
	if payload["iss"] != "" || payload["sub"] != "" {
		t.Fatalf("payload = %#v", payload)
	}
	if implementation.verifyJWT(nil, token) != nil {
		t.Fatal("token with empty subject unexpectedly verified")
	}
}

func TestOptionsAreSnapshotted(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := &keyStore{}
	config := &KeyPairConfig{Algorithm: ES256}
	audience := []string{"aud-1", "aud-2"}
	options := baseTestOptions(store, clock)
	options.JWKS.KeyPair = config
	options.Token.Audience = audience
	implementation, err := normalize(options, false)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	config.Algorithm = RS256
	audience[0] = "mutated"
	if descriptor.Endpoints[0].Path != "/jwks" {
		t.Fatal("descriptor mutated")
	}
	if !reflect.DeepEqual(implementation.options.Token.Audience, []string{"aud-1", "aud-2"}) {
		t.Fatalf("audience snapshot = %#v", implementation.options.Token.Audience)
	}
}
