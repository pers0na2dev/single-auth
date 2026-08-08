package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type refreshAccessTokenOracle struct {
	Tests []refreshAccessTokenOracleTest
}

type refreshAccessTokenOracleTest struct {
	ID          string                              `json:"id"`
	Title       string                              `json:"title"`
	Observation refreshAccessTokenOracleObservation `json:"observation"`
}

type refreshAccessTokenOracleObservation struct {
	Response              map[string]any `json:"response"`
	RequestMethod         string         `json:"requestMethod"`
	RequestBody           string         `json:"requestBody"`
	AccessToken           string         `json:"accessToken"`
	RefreshToken          string         `json:"refreshToken"`
	TokenType             string         `json:"tokenType"`
	AccessTokenExpiresIn  *int64         `json:"accessTokenExpiresInSeconds"`
	RefreshTokenExpiresIn *int64         `json:"refreshTokenExpiresInSeconds"`
}

func TestRefreshAccessTokenBehavior(t *testing.T) {
	oracle := loadRefreshAccessTokenOracle(t)
	if len(oracle.Tests) != 3 {
		t.Fatalf("refreshAccessToken has %d test cases, want 3", len(oracle.Tests))
	}
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			var capturedMethod, capturedBody string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				capturedMethod = request.Method
				body := make([]byte, request.ContentLength)
				_, _ = request.Body.Read(body)
				capturedBody = string(body)
				w.Header().Set("content-type", "application/json")
				if err := json.NewEncoder(w).Encode(vector.Observation.Response); err != nil {
					t.Errorf("encode response: %v", err)
				}
			}))
			defer server.Close()

			before := time.Now()
			tokens, err := RefreshAccessToken(context.Background(), RefreshAccessTokenOptions{
				RefreshToken:  "old-refresh-token",
				Options:       ProviderOptions{ClientID: "test-client", ClientSecret: "test-secret"},
				TokenEndpoint: server.URL,
			})
			after := time.Now()
			if err != nil {
				t.Fatal(err)
			}
			if capturedMethod != vector.Observation.RequestMethod || capturedBody != vector.Observation.RequestBody {
				t.Fatalf("refresh request method=%q body=%q, want method=%q body=%q", capturedMethod, capturedBody, vector.Observation.RequestMethod, vector.Observation.RequestBody)
			}
			if tokens.AccessToken != vector.Observation.AccessToken || tokens.RefreshToken != vector.Observation.RefreshToken || tokens.TokenType != vector.Observation.TokenType {
				t.Fatalf("tokens=%#v, want access=%q refresh=%q type=%q", tokens, vector.Observation.AccessToken, vector.Observation.RefreshToken, vector.Observation.TokenType)
			}
			assertRefreshExpiryConformance(t, "accessTokenExpiresAt", tokens.AccessTokenExpiresAt, vector.Observation.AccessTokenExpiresIn, before, after)
			assertRefreshExpiryConformance(t, "refreshTokenExpiresAt", tokens.RefreshTokenExpiresAt, vector.Observation.RefreshTokenExpiresIn, before, after)
			if tokens.Raw != nil {
				t.Fatalf("refresh tokens expose raw response: %#v", tokens.Raw)
			}
		})
	}
}

func assertRefreshExpiryConformance(t *testing.T, name string, actual *time.Time, expectedSeconds *int64, before, after time.Time) {
	t.Helper()
	if expectedSeconds == nil {
		if actual != nil {
			t.Fatalf("%s=%v, want absent", name, actual)
		}
		return
	}
	if actual == nil {
		t.Fatalf("%s is absent, want now+%ds", name, *expectedSeconds)
	}
	delta := time.Duration(*expectedSeconds) * time.Second
	if actual.Before(before.Add(delta-time.Second)) || actual.After(after.Add(delta+time.Second)) {
		t.Fatalf("%s=%v, want now+%v between %v and %v", name, actual, delta, before, after)
	}
}

func loadRefreshAccessTokenOracle(t *testing.T) refreshAccessTokenOracle {
	t.Helper()
	return refreshAccessTokenOracle{Tests: refreshAccessTokenCases}
}
