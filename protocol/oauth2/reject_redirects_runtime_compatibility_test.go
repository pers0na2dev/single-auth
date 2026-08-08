package oauth2

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type rejectRedirectsRuntimeFileDescription struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type rejectRedirectsRuntimeObservation struct {
	Rejected       bool   `json:"rejected"`
	ErrorName      string `json:"errorName"`
	ErrorMessage   string `json:"errorMessage"`
	FetchCallCount int    `json:"fetchCallCount"`
	Redirect       string `json:"redirect"`
}

type rejectRedirectsRuntimeOracle struct {
	SchemaVersion   int                                     `json:"schemaVersion"`
	UpstreamVersion string                                  `json:"upstreamVersion"`
	OracleKind      string                                  `json:"oracleKind"`
	Sources         []rejectRedirectsRuntimeFileDescription `json:"sources"`
	Runtime         []rejectRedirectsRuntimeFileDescription `json:"runtime"`
	ManifestTestIDs []string                                `json:"manifestTestIDs"`
	Tests           []struct {
		ID          string                            `json:"id"`
		File        string                            `json:"file"`
		Suite       string                            `json:"suite"`
		Title       string                            `json:"title"`
		Observation rejectRedirectsRuntimeObservation `json:"observation"`
	} `json:"tests"`
}

type rejectRedirectsRuntimeTransport struct {
	calls   int
	request *http.Request
}

func (transport *rejectRedirectsRuntimeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	transport.request = request.Clone(request.Context())
	return &http.Response{
		StatusCode: http.StatusFound,
		Status:     "302 Found",
		Header:     http.Header{"Location": {"http://169.254.169.254/"}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    request,
	}, nil
}

func TestRejectRedirectsHTTPClientBehavior(t *testing.T) {
	oracle := loadRejectRedirectsRuntimeOracle(t)
	vector := oracle.Tests[0]
	t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
		transport := &rejectRedirectsRuntimeTransport{}
		_, err := RefreshAccessToken(context.Background(), RefreshAccessTokenOptions{
			RefreshToken: "refresh-token",
			Options: ProviderOptions{
				ClientID: "client", ClientSecret: "secret",
			},
			TokenEndpoint: "https://idp.example/token",
			Client:        &http.Client{Transport: transport},
		})

		var redirectError *RedirectRefusedError
		if !vector.Observation.Rejected || err == nil ||
			!errors.As(err, &redirectError) || !errors.Is(err, ErrOAuthRedirect) {
			t.Fatalf("RefreshAccessToken error = %T %v, want typed redirect refusal", err, err)
		}
		if err.Error() != vector.Observation.ErrorMessage {
			t.Fatalf("redirect refusal error = %q, want %q", err.Error(), vector.Observation.ErrorMessage)
		}
		if transport.calls != vector.Observation.FetchCallCount || transport.request == nil {
			t.Fatalf("outbound calls = %d, request = %#v, want %d calls", transport.calls, transport.request, vector.Observation.FetchCallCount)
		}
		if transport.request.URL.String() != "https://idp.example/token" ||
			transport.request.Method != http.MethodPost {
			t.Fatalf("outbound request = %s %s", transport.request.Method, transport.request.URL)
		}
		if vector.Observation.Redirect != "manual" || vector.Observation.ErrorName == "" {
			t.Fatalf("invalid pinned runtime redirect observation: %#v", vector.Observation)
		}
	})
}

func loadRejectRedirectsRuntimeOracle(t *testing.T) rejectRedirectsRuntimeOracle {
	t.Helper()
	return rejectRedirectsRuntimeOracle{Tests: rejectRedirectRuntimeCases}
}
