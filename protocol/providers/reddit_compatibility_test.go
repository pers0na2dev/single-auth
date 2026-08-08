package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

type redditOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type redditRequestObservation struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	Authorization string `json:"authorization"`
	UserAgent     string `json:"userAgent"`
}

type redditUserObservation struct {
	ID            *string `json:"id"`
	Name          *string `json:"name"`
	Email         *string `json:"email"`
	EmailVerified *bool   `json:"emailVerified"`
	Image         *string `json:"image"`
}

type redditConformanceOracle struct {
	SchemaVersion   int                `json:"schemaVersion"`
	UpstreamPackage string             `json:"upstreamPackage"`
	OracleKind      string             `json:"oracleKind"`
	Sources         []redditOracleFile `json:"sources"`
	Runtime         redditOracleFile   `json:"runtime"`
	ManifestTestIDs []string           `json:"manifestTestIDs"`
	TestCount       int                `json:"testCount"`
	Cases           []struct {
		ID        string `json:"id"`
		File      string `json:"file"`
		Suite     string `json:"suite"`
		Title     string `json:"title"`
		Operation string `json:"operation"`
		Input     struct {
			ClientID     string           `json:"clientId"`
			ClientSecret string           `json:"clientSecret"`
			Profiles     []map[string]any `json:"profiles"`
			AccessTokens []string         `json:"accessTokens"`
			MappedEmail  *string          `json:"mappedEmail"`
		} `json:"input"`
		Observation struct {
			Users                      []redditUserObservation    `json:"users"`
			EmailsDistinct             *bool                      `json:"emailsDistinct"`
			EmailsContainOAuthClientID bool                       `json:"emailsContainOAuthClientId"`
			Requests                   []redditRequestObservation `json:"requests"`
		} `json:"observation"`
	} `json:"cases"`
}

type redditRecordingTransport struct {
	mu       sync.Mutex
	profiles []map[string]any
	requests []redditRequestObservation
}

func (transport *redditRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()

	transport.requests = append(transport.requests, redditRequestObservation{
		URL:           request.URL.String(),
		Method:        request.Method,
		Authorization: request.Header.Get("Authorization"),
		UserAgent:     request.Header.Get("User-Agent"),
	})
	if len(transport.profiles) == 0 {
		return nil, fmt.Errorf("unexpected Reddit request to %s", request.URL)
	}
	profile := transport.profiles[0]
	transport.profiles = transport.profiles[1:]
	raw, err := json.Marshal(profile)
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

func (transport *redditRecordingTransport) snapshot() ([]redditRequestObservation, int) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]redditRequestObservation(nil), transport.requests...), len(transport.profiles)
}

func TestRedditBehavior(t *testing.T) {
	oracle := loadRedditConformanceOracle(t)
	for _, vector := range oracle.Cases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			transport := &redditRecordingTransport{
				profiles: append([]map[string]any(nil), vector.Input.Profiles...),
				requests: make([]redditRequestObservation, 0, len(vector.Input.Profiles)),
			}
			options := Options{
				ClientID:     vector.Input.ClientID,
				ClientSecret: vector.Input.ClientSecret,
				HTTPClient:   &http.Client{Transport: transport},
			}
			if vector.Input.MappedEmail != nil {
				mappedEmail := *vector.Input.MappedEmail
				options.MapProfileToUser = func(context.Context, map[string]any) (map[string]any, error) {
					return map[string]any{"email": mappedEmail}, nil
				}
			}
			provider, err := Reddit(options)
			if err != nil {
				t.Fatal(err)
			}

			actualUsers := make([]redditUserObservation, 0, len(vector.Input.AccessTokens))
			actualEmails := make([]string, 0, len(vector.Input.AccessTokens))
			containsOAuthClientID := false
			for index, accessToken := range vector.Input.AccessTokens {
				result, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: accessToken})
				if err != nil {
					t.Fatal(err)
				}
				if result == nil {
					t.Fatalf("Reddit user-info result %d is nil", index)
				}
				if !reflect.DeepEqual(result.Data, vector.Input.Profiles[index]) {
					t.Fatalf("Reddit profile data %d = %#v, want %#v", index, result.Data, vector.Input.Profiles[index])
				}
				actualUsers = append(actualUsers, redditUserFromResult(result))
				if result.User.Email != nil {
					actualEmails = append(actualEmails, *result.User.Email)
					clientID, _ := vector.Input.Profiles[index]["oauth_client_id"].(string)
					containsOAuthClientID = containsOAuthClientID || strings.Contains(*result.User.Email, clientID)
				}
			}
			if !reflect.DeepEqual(actualUsers, vector.Observation.Users) {
				t.Fatalf("Reddit users = %#v, want %#v", actualUsers, vector.Observation.Users)
			}
			if vector.Observation.EmailsDistinct != nil {
				actualDistinct := len(actualEmails) > 1 && len(uniqueRedditStrings(actualEmails)) == len(actualEmails)
				if actualDistinct != *vector.Observation.EmailsDistinct {
					t.Fatalf("Reddit emails distinct = %v, want %v", actualDistinct, *vector.Observation.EmailsDistinct)
				}
			}
			if containsOAuthClientID != vector.Observation.EmailsContainOAuthClientID {
				t.Fatalf("Reddit emails contain oauth_client_id = %v, want %v", containsOAuthClientID, vector.Observation.EmailsContainOAuthClientID)
			}
			requests, remaining := transport.snapshot()
			if remaining != 0 {
				t.Fatalf("Reddit transport has %d unconsumed profiles", remaining)
			}
			expectedRequests := append([]redditRequestObservation(nil), vector.Observation.Requests...)
			for index := range requests {
				if requests[index].UserAgent != "single-auth" {
					t.Fatalf("Reddit request %d user agent = %q", index, requests[index].UserAgent)
				}
				expectedRequests[index].UserAgent = requests[index].UserAgent
			}
			if !reflect.DeepEqual(requests, expectedRequests) {
				t.Fatalf("Reddit requests = %#v, want %#v", requests, expectedRequests)
			}
		})
	}
}

func redditUserFromResult(result *UserInfoResult) redditUserObservation {
	id := result.User.ID
	name := result.User.Name
	verified := result.User.EmailVerified
	var image *string
	if result.User.Image != "" {
		value := result.User.Image
		image = &value
	}
	return redditUserObservation{
		ID:            &id,
		Name:          &name,
		Email:         result.User.Email,
		EmailVerified: &verified,
		Image:         image,
	}
}

func uniqueRedditStrings(values []string) map[string]struct{} {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	return unique
}

func loadRedditConformanceOracle(t *testing.T) redditConformanceOracle {
	t.Helper()
	return redditConformanceOracle{Cases: redditCases}
}
