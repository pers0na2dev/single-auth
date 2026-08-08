package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var redirectStatuses = map[int]struct{}{
	http.StatusMovedPermanently:  {},
	http.StatusFound:             {},
	http.StatusSeeOther:          {},
	http.StatusTemporaryRedirect: {},
	http.StatusPermanentRedirect: {},
}

// ErrOAuthRedirect identifies a refused server-side OAuth redirect.
var ErrOAuthRedirect = errors.New("OAuth endpoint returned an HTTP redirect")

// RedirectRefusedError is the Go equivalent of ReferenceError emitted when a
// server-side OAuth endpoint attempts an HTTP redirect.
type RedirectRefusedError struct {
	Endpoint string
}

func (err *RedirectRefusedError) Error() string {
	return fmt.Sprintf(
		"The OAuth endpoint %q returned an HTTP redirect. Server-side OAuth fetches refuse redirects to prevent SSRF; configure the final endpoint URL.",
		err.Endpoint,
	)
}

func (err *RedirectRefusedError) Unwrap() error {
	return ErrOAuthRedirect
}

// RefuseRedirects clones or creates a client whose redirect policy returns the
// first redirect response without connecting to its target.
func RefuseRedirects(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	clone := *client
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

// ResponseMetadata is the runtime-neutral subset used to recognize redirects.
// Type is relevant to fetch-compatible transports, which expose manual browser
// redirects as "opaqueredirect" with status zero.
type ResponseMetadata struct {
	Status int    `json:"status"`
	Type   string `json:"type"`
}

// AssertResponseMetadataNotRedirect returns RedirectRefusedError for every
// response shape the reference implementation treats as a server-side OAuth SSRF boundary.
func AssertResponseMetadataNotRedirect(endpoint string, response ResponseMetadata) error {
	_, statusRedirect := redirectStatuses[response.Status]
	if statusRedirect || response.Type == "opaqueredirect" {
		return &RedirectRefusedError{Endpoint: endpoint}
	}
	return nil
}

// AssertResponseNotRedirect applies redirect protection to net/http responses.
func AssertResponseNotRedirect(endpoint string, response *http.Response) error {
	if response == nil {
		return nil
	}
	return AssertResponseMetadataNotRedirect(endpoint, ResponseMetadata{Status: response.StatusCode})
}

// DoRefusingRedirects executes one HTTP request and never follows a redirect.
// The response body is closed before a redirect error is returned.
func DoRefusingRedirects(client *http.Client, request *http.Request) (*http.Response, error) {
	response, err := RefuseRedirects(client).Do(request)
	if err != nil {
		return nil, err
	}
	if err := AssertResponseNotRedirect(request.URL.String(), response); err != nil {
		response.Body.Close()
		return nil, err
	}
	return response, nil
}

// JWKSet is the JSON envelope returned by an OAuth/OIDC JWKS endpoint.
type JWKSet struct {
	Keys []map[string]any `json:"keys"`
}

// FetchJWKSet retrieves a remote JWKS without allowing the endpoint to redirect
// the server-side request to another host.
func FetchJWKSet(ctx context.Context, client *http.Client, endpoint string) (JWKSet, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return JWKSet{}, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := DoRefusingRedirects(client, request)
	if err != nil {
		return JWKSet{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return JWKSet{}, fmt.Errorf("OAuth endpoint %q returned %d: %s", endpoint, response.StatusCode, strings.TrimSpace(response.Status))
	}
	var set JWKSet
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&set); err != nil {
		return JWKSet{}, err
	}
	return set, nil
}
