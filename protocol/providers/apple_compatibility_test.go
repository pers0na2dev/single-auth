package providers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"reflect"
	"testing"
	"time"
)

type appleOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type appleConformanceOracle struct {
	SchemaVersion   int               `json:"schemaVersion"`
	UpstreamPackage string            `json:"upstreamPackage"`
	OracleKind      string            `json:"oracleKind"`
	Sources         []appleOracleFile `json:"sources"`
	Runtime         appleOracleFile   `json:"runtime"`
	ManifestTestIDs []string          `json:"manifestTestIDs"`
	TestCount       int               `json:"testCount"`
	Cases           []struct {
		ID        string `json:"id"`
		File      string `json:"file"`
		Suite     string `json:"suite"`
		Title     string `json:"title"`
		Operation string `json:"operation"`
		Input     struct {
			State        string            `json:"state"`
			RedirectURI  string            `json:"redirectURI"`
			CodeVerifier string            `json:"codeVerifier"`
			TokenNonce   string            `json:"tokenNonce"`
			RequestNonce string            `json:"requestNonce"`
			Token        string            `json:"token"`
			Nonce        string            `json:"nonce"`
			Headers      map[string]string `json:"headers"`
		} `json:"input"`
		Observation struct {
			URL                 string   `json:"url"`
			CodeChallengeMethod *string  `json:"codeChallengeMethod"`
			CodeChallenge       *string  `json:"codeChallenge"`
			HasCodeVerifier     bool     `json:"hasCodeVerifier"`
			Verified            bool     `json:"verified"`
			FetchURLs           []string `json:"fetchURLs"`
			SeenPlatform        string   `json:"seenPlatform"`
		} `json:"observation"`
	} `json:"cases"`
}

type appleRecordingTransport struct {
	fixture fixtureResponse
	urls    []string
}

func (transport *appleRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.urls = append(transport.urls, request.URL.String())
	return fixtureTransport{request.URL.String(): transport.fixture}.RoundTrip(request)
}

func TestAppleBehavior(t *testing.T) {
	oracle := loadAppleConformanceOracle(t)
	for _, vector := range oracle.Cases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			switch vector.Operation {
			case "createAuthorizationURL":
				provider, err := Apple(Options{
					ClientID:     "service.example.app",
					ClientSecret: "test-secret",
				})
				if err != nil {
					t.Fatal(err)
				}
				authorizationURL, err := provider.CreateAuthorizationURL(AuthorizationInput{
					State:        vector.Input.State,
					RedirectURI:  vector.Input.RedirectURI,
					CodeVerifier: vector.Input.CodeVerifier,
				})
				if err != nil {
					t.Fatal(err)
				}
				query := authorizationURL.Query()
				if authorizationURL.String() != vector.Observation.URL ||
					!reflect.DeepEqual(nullableQueryValue(query, "code_challenge_method"), vector.Observation.CodeChallengeMethod) ||
					!reflect.DeepEqual(nullableQueryValue(query, "code_challenge"), vector.Observation.CodeChallenge) ||
					query.Has("code_verifier") != vector.Observation.HasCodeVerifier {
					t.Fatalf("Apple authorization URL = %s, query=%v; want %s", authorizationURL, query, vector.Observation.URL)
				}
			case "verifyIdToken":
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				jwk := map[string]any{
					"kid": "test-apple-key",
					"alg": "ES256",
					"kty": "EC",
					"use": "sig",
					"crv": "P-256",
					"x":   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))),
					"y":   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32))),
				}
				transport := &appleRecordingTransport{fixture: jsonFixture(map[string]any{"keys": []any{jwk}})}
				provider, err := Apple(Options{
					ClientID:            "service.example.app",
					ClientSecret:        "test-secret",
					AppBundleIdentifier: "com.example.app",
					HTTPClient:          &http.Client{Transport: transport},
				})
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().Unix()
				token := signES256(t, key, "test-apple-key", map[string]any{
					"sub":            "apple-user-123",
					"email":          "user@example.com",
					"email_verified": true,
					"nonce":          vector.Input.TokenNonce,
					"iss":            "https://appleid.apple.com",
					"aud":            "com.example.app",
					"iat":            now,
					"exp":            now + 3600,
				})
				verified, err := provider.VerifyIDToken(context.Background(), token, vector.Input.RequestNonce)
				if err != nil {
					t.Fatal(err)
				}
				if verified != vector.Observation.Verified || !reflect.DeepEqual(transport.urls, vector.Observation.FetchURLs) {
					t.Fatalf("Apple verification = %v, fetch URLs=%v; want %v, %v", verified, transport.urls, vector.Observation.Verified, vector.Observation.FetchURLs)
				}
			case "customVerifyIdToken":
				seenPlatform := ""
				provider, err := Apple(Options{
					ClientID:     "service.example.app",
					ClientSecret: "test-secret",
					VerifyIDToken: func(ctx context.Context, token, nonce string) (bool, error) {
						requestContext, ok := VerifyIDTokenRequestContextFrom(ctx)
						if ok {
							seenPlatform = requestContext.Headers.Get("x-platform")
						}
						return token == vector.Input.Token && nonce == vector.Input.Nonce && seenPlatform == "ios", nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				headers := make(http.Header, len(vector.Input.Headers))
				for name, value := range vector.Input.Headers {
					headers.Set(name, value)
				}
				verified, err := provider.VerifyIDTokenWithRequestContext(
					context.Background(),
					vector.Input.Token,
					vector.Input.Nonce,
					VerifyIDTokenRequestContext{Headers: headers},
				)
				if err != nil {
					t.Fatal(err)
				}
				if verified != vector.Observation.Verified || seenPlatform != vector.Observation.SeenPlatform {
					t.Fatalf("custom Apple verification = %v, platform=%q; want %v, %q", verified, seenPlatform, vector.Observation.Verified, vector.Observation.SeenPlatform)
				}
			default:
				t.Fatalf("unknown Apple oracle operation %q", vector.Operation)
			}
		})
	}
}

func nullableQueryValue(values map[string][]string, name string) *string {
	entries, ok := values[name]
	if !ok || len(entries) == 0 {
		return nil
	}
	value := entries[0]
	return &value
}

func loadAppleConformanceOracle(t *testing.T) appleConformanceOracle {
	t.Helper()
	return appleConformanceOracle{Cases: appleCases}
}
