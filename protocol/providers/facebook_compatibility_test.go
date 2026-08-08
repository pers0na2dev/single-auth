package providers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

type facebookOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type facebookRequestObservation struct {
	URL           string  `json:"url"`
	Method        string  `json:"method"`
	Authorization *string `json:"authorization"`
}

type facebookConformanceOracle struct {
	SchemaVersion   int                  `json:"schemaVersion"`
	UpstreamPackage string               `json:"upstreamPackage"`
	OracleKind      string               `json:"oracleKind"`
	Sources         []facebookOracleFile `json:"sources"`
	Runtime         facebookOracleFile   `json:"runtime"`
	ManifestTestIDs []string             `json:"manifestTestIDs"`
	TestCount       int                  `json:"testCount"`
	Cases           []struct {
		ID        string `json:"id"`
		File      string `json:"file"`
		Suite     string `json:"suite"`
		Title     string `json:"title"`
		Operation string `json:"operation"`
		Input     struct {
			ClientID     any            `json:"clientId"`
			ClientSecret string         `json:"clientSecret"`
			Token        string         `json:"token"`
			Debug        map[string]any `json:"debug"`
			Profile      map[string]any `json:"profile"`
		} `json:"input"`
		Observation struct {
			Verified      *bool                        `json:"verified"`
			ResultNull    *bool                        `json:"resultNull"`
			UserID        *string                      `json:"userId"`
			UserEmail     *string                      `json:"userEmail"`
			UserImage     *string                      `json:"userImage"`
			EmailVerified *bool                        `json:"emailVerified"`
			Requests      []facebookRequestObservation `json:"requests"`
		} `json:"observation"`
	} `json:"cases"`
}

type facebookRecordingTransport struct {
	debug    map[string]any
	profile  map[string]any
	requests []facebookRequestObservation
}

func (transport *facebookRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	authorization := nullableFacebookString(request.Header.Get("Authorization"))
	transport.requests = append(transport.requests, facebookRequestObservation{
		URL:           request.URL.String(),
		Method:        request.Method,
		Authorization: authorization,
	})
	var body any = transport.profile
	if strings.Contains(request.URL.String(), "debug_token") {
		body = map[string]any{"data": transport.debug}
	}
	raw, err := json.Marshal(body)
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

func nullableFacebookString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func TestFacebookBehavior(t *testing.T) {
	oracle := loadFacebookConformanceOracle(t)
	for _, vector := range oracle.Cases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			transport := &facebookRecordingTransport{
				debug:    vector.Input.Debug,
				profile:  vector.Input.Profile,
				requests: make([]facebookRequestObservation, 0),
			}
			provider, err := Facebook(Options{
				ClientID:     vector.Input.ClientID,
				ClientSecret: vector.Input.ClientSecret,
				HTTPClient:   &http.Client{Transport: transport},
			})
			if err != nil {
				t.Fatal(err)
			}

			switch vector.Operation {
			case "verifyIdToken":
				verified, err := provider.VerifyIDToken(context.Background(), vector.Input.Token, "")
				if err != nil {
					t.Fatal(err)
				}
				if vector.Observation.Verified == nil || verified != *vector.Observation.Verified {
					t.Fatalf("Facebook verification = %v, want %v", verified, vector.Observation.Verified)
				}
			case "getUserInfo":
				info, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{AccessToken: vector.Input.Token})
				if err != nil {
					t.Fatal(err)
				}
				if vector.Observation.ResultNull == nil || (info == nil) != *vector.Observation.ResultNull {
					t.Fatalf("Facebook result = %#v, want resultNull=%v", info, vector.Observation.ResultNull)
				}
				if info != nil {
					assertFacebookUserObservation(t, info, vector.Observation.UserID, vector.Observation.UserEmail, vector.Observation.UserImage, vector.Observation.EmailVerified)
				}
			default:
				t.Fatalf("unknown Facebook oracle operation %q", vector.Operation)
			}
			if !reflect.DeepEqual(transport.requests, vector.Observation.Requests) {
				t.Fatalf("Facebook requests = %#v, want %#v", transport.requests, vector.Observation.Requests)
			}
		})
	}
}

func assertFacebookUserObservation(t *testing.T, result *UserInfoResult, id, email, image *string, verified *bool) {
	t.Helper()
	if id == nil || result.User.ID != *id {
		t.Fatalf("Facebook user id = %q, want %v", result.User.ID, id)
	}
	if !reflect.DeepEqual(result.User.Email, email) {
		t.Fatalf("Facebook user email = %v, want %v", result.User.Email, email)
	}
	if image == nil || result.User.Image != *image {
		t.Fatalf("Facebook user image = %q, want %v", result.User.Image, image)
	}
	if verified == nil || result.User.EmailVerified != *verified {
		t.Fatalf("Facebook emailVerified = %v, want %v", result.User.EmailVerified, verified)
	}
}

func loadFacebookConformanceOracle(t *testing.T) facebookConformanceOracle {
	t.Helper()
	return facebookConformanceOracle{Cases: facebookCases}
}
