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
)

type microsoftEntraIDOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type microsoftEntraIDConformanceOracle struct {
	SchemaVersion   int                          `json:"schemaVersion"`
	UpstreamPackage string                       `json:"upstreamPackage"`
	OracleKind      string                       `json:"oracleKind"`
	Sources         []microsoftEntraIDOracleFile `json:"sources"`
	Runtime         microsoftEntraIDOracleFile   `json:"runtime"`
	ManifestTestIDs []string                     `json:"manifestTestIDs"`
	TestCount       int                          `json:"testCount"`
	Cases           []struct {
		ID        string `json:"id"`
		File      string `json:"file"`
		Suite     string `json:"suite"`
		Title     string `json:"title"`
		Operation string `json:"operation"`
		Input     struct {
			TenantID  string  `json:"tenantId"`
			Authority *string `json:"authority"`
			Tokens    []struct {
				TID    *string `json:"tid"`
				Issuer string  `json:"issuer"`
			} `json:"tokens"`
		} `json:"input"`
		Observation struct {
			Verified  []bool   `json:"verified"`
			FetchURLs []string `json:"fetchURLs"`
		} `json:"observation"`
	} `json:"cases"`
}

type microsoftEntraIDRecordingTransport struct {
	jwk  map[string]any
	urls []string
}

func (transport *microsoftEntraIDRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.urls = append(transport.urls, request.URL.String())
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

func TestMicrosoftEntraIDBehavior(t *testing.T) {
	oracle := loadMicrosoftEntraIDConformanceOracle(t)
	for _, vector := range oracle.Cases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
			transport := &microsoftEntraIDRecordingTransport{jwk: map[string]any{
				"kid": "ms-test-key",
				"alg": "RS256",
				"kty": "RSA",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(exponent),
			}}
			options := Options{
				ClientID:   "ms-app",
				TenantID:   vector.Input.TenantID,
				HTTPClient: &http.Client{Transport: transport},
			}
			if vector.Input.Authority != nil {
				options.Authority = *vector.Input.Authority
			}
			provider, err := Microsoft(options)
			if err != nil {
				t.Fatal(err)
			}

			verified := make([]bool, 0, len(vector.Input.Tokens))
			for _, tokenInput := range vector.Input.Tokens {
				now := time.Now().Unix()
				claims := map[string]any{
					"sub": "ms-user-1",
					"iss": tokenInput.Issuer,
					"aud": "ms-app",
					"iat": now,
					"exp": now + 3600,
				}
				if tokenInput.TID != nil {
					claims["tid"] = *tokenInput.TID
				}
				valid, err := provider.VerifyIDToken(
					context.Background(),
					signRS256(t, key, "ms-test-key", claims),
					"",
				)
				if err != nil {
					t.Fatal(err)
				}
				verified = append(verified, valid)
			}
			if !reflect.DeepEqual(verified, vector.Observation.Verified) ||
				!reflect.DeepEqual(transport.urls, vector.Observation.FetchURLs) {
				t.Fatalf(
					"Microsoft Entra ID verification = %v, fetch URLs=%v; want %v, %v",
					verified,
					transport.urls,
					vector.Observation.Verified,
					vector.Observation.FetchURLs,
				)
			}
		})
	}
}

func loadMicrosoftEntraIDConformanceOracle(t *testing.T) microsoftEntraIDConformanceOracle {
	t.Helper()
	return microsoftEntraIDConformanceOracle{Cases: microsoftEntraIDCases}
}
