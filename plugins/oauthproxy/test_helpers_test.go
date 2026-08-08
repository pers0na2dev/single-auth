package oauthproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	previewBase      = "http://preview.example.com"
	productionBase   = "http://localhost:3000"
	previewSecret    = "preview-main-secret-at-least-32-chars"
	productionSecret = "production-main-secret-at-least-32"
	sharedSecret     = "shared-oauth-proxy-secret-at-least-32"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func unsignedJWT(payload map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	body, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body) + ".signature"
}

func testGoogleProvider(t *testing.T, options ...providers.Options) *providers.Provider {
	t.Helper()
	configured := providers.Options{ClientID: "test", ClientSecret: "test"}
	if len(options) != 0 {
		configured = options[0]
		if configured.ClientID == nil {
			configured.ClientID = "test"
		}
		if configured.ClientSecret == "" {
			configured.ClientSecret = "test"
		}
	}
	profileToken := unsignedJWT(map[string]any{
		"sub": "1234567890", "email": "user@email.com",
		"name": "First Last", "picture": "https://example.com/avatar.png",
		"email_verified": true,
	})
	configured.HTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://oauth2.googleapis.com/token" {
			return nil, io.EOF
		}
		body, _ := json.Marshal(map[string]any{
			"access_token": "test-access", "refresh_token": "test-refresh",
			"id_token": profileToken, "scope": "openid profile email",
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(body)), Request: request,
		}, nil
	})}
	provider, err := providers.Google(configured)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func testAppleProvider(t *testing.T) *providers.Provider {
	t.Helper()
	token := unsignedJWT(map[string]any{
		"sub": "apple-user-id", "email": "jane@privaterelay.appleid.com",
		"email_verified": true,
	})
	provider, err := providers.Apple(providers.Options{
		ClientID: "test-apple-client", ClientSecret: "test-apple-secret",
		HTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body, _ := json.Marshal(map[string]any{
				"access_token": "apple-access-token", "id_token": token,
				"token_type": "Bearer", "expires_in": 3600,
			})
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(body)), Request: request,
			}, nil
		})},
	})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func testAuth(t *testing.T, baseURL, secret string, pluginOptions Options, account singleauth.AccountOptions, provider *providers.Provider) *singleauth.Auth {
	t.Helper()
	if provider == nil {
		provider = testGoogleProvider(t)
	}
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: baseURL, Secret: secret, Account: account,
		SocialProviders: map[string]*providers.Provider{provider.ID: provider},
		PluginFactories: []singleauth.PluginFactory{NewFactory(pluginOptions)},
		Clock:           time.Now, Random: rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

type responseSnapshot struct {
	Status  int
	Header  http.Header
	Body    []byte
	Cookies map[string]string
}

func exchange(t *testing.T, auth *singleauth.Auth, method, absoluteTarget string, body any, jar map[string]string) responseSnapshot {
	t.Helper()
	var reader io.Reader
	var encoded []byte
	contentType := ""
	switch typed := body.(type) {
	case nil:
	case string:
		encoded = []byte(typed)
		reader = bytes.NewReader(encoded)
		contentType = "application/x-www-form-urlencoded"
	default:
		var err error
		encoded, err = json.Marshal(typed)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
		contentType = "application/json"
	}
	request := httptest.NewRequest(method, absoluteTarget, reader)
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	if len(jar) != 0 {
		names := make([]string, 0, len(jar))
		for name := range jar {
			names = append(names, name)
		}
		for _, name := range names {
			request.AddCookie(&http.Cookie{Name: name, Value: jar[name]})
		}
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	result := recorder.Result()
	defer result.Body.Close()
	responseBody, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	if jar == nil {
		jar = make(map[string]string)
	}
	for _, line := range result.Header.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Attributes.MaxAge != nil && *parsed.Attributes.MaxAge == 0 {
				delete(jar, parsed.Name)
			} else {
				jar[parsed.Name] = parsed.Attributes.Value
			}
		}
	}
	return responseSnapshot{Status: result.StatusCode, Header: result.Header.Clone(), Body: responseBody, Cookies: jar}
}

func startSocial(t *testing.T, auth *singleauth.Auth, baseURL, providerID string, jar map[string]string) *url.URL {
	t.Helper()
	response := exchange(t, auth, http.MethodPost, baseURL+"/api/auth/sign-in/social", map[string]any{
		"provider": providerID, "callbackURL": "/dashboard", "disableRedirect": true,
	}, jar)
	if response.Status != http.StatusOK {
		t.Fatalf("sign-in status=%d body=%s", response.Status, response.Body)
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(response.Body, &body); err != nil || body.URL == "" {
		t.Fatalf("sign-in response=%s err=%v", response.Body, err)
	}
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func records(t *testing.T, auth *singleauth.Auth, model string) []storage.Record {
	t.Helper()
	result, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: model})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func extractProfile(t *testing.T, location string) (callbackURL, profile string) {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("callbackURL"), parsed.Query().Get("profile")
}

func decryptPayload(t *testing.T, options Options, runtime Runtime, value string) passthroughPayload {
	t.Helper()
	p, err := normalize(Options{
		Secret: options.Secret, SecretConfig: options.SecretConfig,
		Runtime: runtime,
	})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := p.decryptProxy(value)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := decodePassthroughPayload(plain)
	if !ok {
		t.Fatalf("invalid passthrough payload: %s", plain)
	}
	return payload
}
