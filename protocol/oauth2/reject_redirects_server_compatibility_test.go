package oauth2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

type rejectRedirectsServerOracle struct {
	SchemaVersion   int                         `json:"schemaVersion"`
	UpstreamVersion string                      `json:"upstreamVersion"`
	OracleKind      string                      `json:"oracleKind"`
	Sources         []rejectRedirectsOracleFile `json:"sources"`
	Runtime         []rejectRedirectsOracleFile `json:"runtime"`
	ManifestTestIDs []string                    `json:"manifestTestIDs"`
	Tests           []struct {
		ID          string                     `json:"id"`
		File        string                     `json:"file"`
		Suite       string                     `json:"suite"`
		Title       string                     `json:"title"`
		Observation rejectRedirectsObservation `json:"observation"`
	} `json:"tests"`
}

type rejectRedirectsOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type rejectRedirectsObservation struct {
	Rejected       bool   `json:"rejected"`
	ErrorMessage   string `json:"errorMessage"`
	ResponseStatus int    `json:"responseStatus"`
	InternalHit    bool   `json:"internalHit"`
}

func TestRejectRedirectsServerBehavior(t *testing.T) {
	oracle := loadRejectRedirectsServerOracle(t)
	var baseURL string
	var internalHit atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		path := strings.SplitN(request.URL.Path, "?", 2)[0]
		switch path {
		case "/redirecting-token", "/redirecting-jwks":
			target := "/internal-token"
			if path == "/redirecting-jwks" {
				target = "/internal-jwks"
			}
			response.Header().Set("Location", baseURL+target)
			response.WriteHeader(http.StatusFound)
		case "/internal-token":
			internalHit.Store(true)
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"access_token":"leaked-internal-token","token_type":"Bearer"}`)
		case "/internal-jwks":
			internalHit.Store(true)
			response.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(response, `{"keys":[]}`)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	baseURL = server.URL

	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			internalHit.Store(false)
			actual, err := runRejectRedirectsVector(t, baseURL, vector.Title)
			actual.InternalHit = internalHit.Load()
			if err != nil {
				actual.Rejected = true
				actual.ErrorMessage = strings.ReplaceAll(err.Error(), baseURL, "<baseUrl>")
			}
			if vector.Observation.Rejected && !errors.Is(err, ErrOAuthRedirect) {
				t.Fatalf("error = %v, want ErrOAuthRedirect", err)
			}
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("redirect observation = %#v, want %#v", actual, vector.Observation)
			}
		})
	}
}

func runRejectRedirectsVector(t *testing.T, baseURL, title string) (rejectRedirectsObservation, error) {
	t.Helper()
	ctx := context.Background()
	switch title {
	case "sanity: a client that follows redirects does reach the internal endpoint":
		response, err := http.Get(baseURL + "/redirecting-token")
		if err != nil {
			return rejectRedirectsObservation{}, err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return rejectRedirectsObservation{ResponseStatus: response.StatusCode}, nil
	case "validateAuthorizationCode rejects the redirect and never connects to the internal host":
		request := CreateAuthorizationCodeRequest(AuthorizationCodeRequestOptions{
			Code:        "auth-code",
			RedirectURI: baseURL + "/callback",
			Options: ProviderOptions{
				ClientID:     "client",
				ClientSecret: "secret",
			},
		})
		_, err := DoForm(ctx, nil, baseURL+"/redirecting-token", request)
		return rejectRedirectsObservation{}, err
	case "refreshAccessToken rejects the redirect and never connects to the internal host":
		request := CreateRefreshAccessTokenRequest(RefreshTokenRequestOptions{
			RefreshToken: "refresh-token",
			Options: ProviderOptions{
				ClientID:     "client",
				ClientSecret: "secret",
			},
		})
		_, err := DoForm(ctx, nil, baseURL+"/redirecting-token", request)
		return rejectRedirectsObservation{}, err
	case "clientCredentialsToken rejects the redirect and never connects to the internal host":
		request := CreateClientCredentialsTokenRequest(ClientCredentialsRequestOptions{
			Options: ProviderOptions{
				ClientID:     "client",
				ClientSecret: "secret",
			},
			Scope: "openid",
		})
		_, err := DoForm(ctx, nil, baseURL+"/redirecting-token", request)
		return rejectRedirectsObservation{}, err
	case "validateToken (JWKS) rejects the redirect and never connects to the internal host":
		_, err := FetchJWKSet(ctx, nil, baseURL+"/redirecting-jwks")
		return rejectRedirectsObservation{}, err
	default:
		t.Fatalf("unknown the reference implementation reject-redirects test %q", title)
		return rejectRedirectsObservation{}, nil
	}
}

func loadRejectRedirectsServerOracle(t *testing.T) rejectRedirectsServerOracle {
	t.Helper()
	return rejectRedirectsServerOracle{Tests: rejectRedirectServerCases}
}
