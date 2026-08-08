package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

type googleOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type googleRequestObservation struct {
	URL           string  `json:"url"`
	Method        string  `json:"method"`
	Authorization *string `json:"authorization"`
}

type googleConformanceOracle struct {
	SchemaVersion   int                `json:"schemaVersion"`
	UpstreamPackage string             `json:"upstreamPackage"`
	OracleKind      string             `json:"oracleKind"`
	Sources         []googleOracleFile `json:"sources"`
	Runtime         googleOracleFile   `json:"runtime"`
	ManifestTestIDs []string           `json:"manifestTestIDs"`
	TestCount       int                `json:"testCount"`
	Cases           []struct {
		ID        string `json:"id"`
		File      string `json:"file"`
		Suite     string `json:"suite"`
		Title     string `json:"title"`
		Operation string `json:"operation"`
		Input     struct {
			ConfiguredHD *string `json:"configuredHD"`
			TokenHD      *string `json:"tokenHD"`
		} `json:"input"`
		Observation struct {
			Verified   *bool                      `json:"verified"`
			ResultNull *bool                      `json:"resultNull"`
			UserEmail  *string                    `json:"userEmail"`
			Requests   []googleRequestObservation `json:"requests"`
		} `json:"observation"`
	} `json:"cases"`
}

type googleRecordingTransport struct {
	jwk      map[string]any
	requests []googleRequestObservation
}

func (transport *googleRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests = append(transport.requests, googleRequestObservation{
		URL:           request.URL.String(),
		Method:        request.Method,
		Authorization: nullableGoogleString(request.Header.Get("Authorization")),
	})
	raw, err := json.Marshal(map[string]any{"keys": []any{transport.jwk}})
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(raw))),
		Request:    request,
	}, nil
}

func nullableGoogleString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func TestGoogleBehavior(t *testing.T) {
	oracle := loadGoogleConformanceOracle(t)
	for _, vector := range oracle.Cases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
			transport := &googleRecordingTransport{
				jwk: map[string]any{
					"kid": "test-google-key",
					"alg": "RS256",
					"kty": "RSA",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(exponent),
				},
				requests: make([]googleRequestObservation, 0),
			}
			options := Options{
				ClientID:     "google-client-id",
				ClientSecret: "google-client-secret",
				HTTPClient:   &http.Client{Transport: transport},
			}
			if vector.Input.ConfiguredHD != nil {
				options.HostedDomain = *vector.Input.ConfiguredHD
			}
			provider, err := Google(options)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().Unix()
			claims := map[string]any{
				"sub":            "google-user-123",
				"email":          "user@example.com",
				"email_verified": true,
				"name":           "Workspace User",
				"picture":        "https://example.com/avatar.png",
				"iss":            "https://accounts.google.com",
				"aud":            "google-client-id",
				"iat":            now,
				"exp":            now + 3600,
			}
			if vector.Input.TokenHD != nil {
				claims["hd"] = *vector.Input.TokenHD
			}
			token := signRS256(t, key, "test-google-key", claims)

			switch vector.Operation {
			case "verifyIdToken":
				verified, err := provider.VerifyIDToken(context.Background(), token, "")
				if err != nil {
					t.Fatal(err)
				}
				if vector.Observation.Verified == nil || verified != *vector.Observation.Verified {
					t.Fatalf("Google verification = %v, want %v", verified, vector.Observation.Verified)
				}
			case "getUserInfo":
				info, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{
					IDToken:     token,
					AccessToken: "access",
				})
				if err != nil {
					t.Fatal(err)
				}
				if vector.Observation.ResultNull == nil || (info == nil) != *vector.Observation.ResultNull {
					t.Fatalf("Google result = %#v, want resultNull=%v", info, vector.Observation.ResultNull)
				}
				if info == nil {
					if vector.Observation.UserEmail != nil {
						t.Fatalf("Google user email = nil, want %q", *vector.Observation.UserEmail)
					}
				} else if vector.Observation.UserEmail == nil || !reflect.DeepEqual(info.User.Email, vector.Observation.UserEmail) {
					t.Fatalf("Google user email = %v, want %v", info.User.Email, vector.Observation.UserEmail)
				}
			default:
				t.Fatalf("unknown Google oracle operation %q", vector.Operation)
			}

			if !reflect.DeepEqual(transport.requests, vector.Observation.Requests) {
				t.Fatalf("Google requests = %#v, want %#v", transport.requests, vector.Observation.Requests)
			}
		})
	}
}

func loadGoogleConformanceOracle(t *testing.T) googleConformanceOracle {
	t.Helper()
	return googleConformanceOracle{Cases: googleCases}
}
