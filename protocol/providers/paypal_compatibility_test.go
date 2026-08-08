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

type paypalOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type paypalRequestObservation struct {
	URL           string  `json:"url"`
	Method        string  `json:"method"`
	Authorization *string `json:"authorization"`
	Accept        *string `json:"accept"`
}

type paypalUserObservation struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Email         *string `json:"email"`
	Image         string  `json:"image"`
	EmailVerified bool    `json:"emailVerified"`
}

type paypalConformanceOracle struct {
	SchemaVersion   int                `json:"schemaVersion"`
	UpstreamPackage string             `json:"upstreamPackage"`
	OracleKind      string             `json:"oracleKind"`
	Sources         []paypalOracleFile `json:"sources"`
	Runtime         paypalOracleFile   `json:"runtime"`
	ManifestTestIDs []string           `json:"manifestTestIDs"`
	TestCount       int                `json:"testCount"`
	Cases           []struct {
		ID        string `json:"id"`
		File      string `json:"file"`
		Suite     string `json:"suite"`
		Title     string `json:"title"`
		Operation string `json:"operation"`
		Input     struct {
			ClientID       string         `json:"clientId"`
			ClientSecret   string         `json:"clientSecret"`
			Environment    string         `json:"environment"`
			AccessToken    string         `json:"accessToken"`
			IDTokenSubject string         `json:"idTokenSubject"`
			Profile        map[string]any `json:"profile"`
		} `json:"input"`
		Observation struct {
			ResultNull bool                       `json:"resultNull"`
			User       *paypalUserObservation     `json:"user"`
			Data       map[string]any             `json:"data"`
			Requests   []paypalRequestObservation `json:"requests"`
		} `json:"observation"`
	} `json:"cases"`
}

type paypalRecordingTransport struct {
	profile  map[string]any
	requests []paypalRequestObservation
}

func (transport *paypalRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests = append(transport.requests, paypalRequestObservation{
		URL:           request.URL.String(),
		Method:        request.Method,
		Authorization: nullablePayPalString(request.Header.Get("Authorization")),
		Accept:        nullablePayPalString(request.Header.Get("Accept")),
	})
	raw, err := json.Marshal(transport.profile)
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

func nullablePayPalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func TestPayPalBehavior(t *testing.T) {
	oracle := loadPayPalConformanceOracle(t)
	for _, vector := range oracle.Cases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			if vector.Operation != "getUserInfo" {
				t.Fatalf("unknown PayPal oracle operation %q", vector.Operation)
			}
			transport := &paypalRecordingTransport{
				profile:  vector.Input.Profile,
				requests: make([]paypalRequestObservation, 0, 1),
			}
			provider, err := PayPal(Options{
				ClientID:     vector.Input.ClientID,
				ClientSecret: vector.Input.ClientSecret,
				Environment:  vector.Input.Environment,
				HTTPClient:   &http.Client{Transport: transport},
			})
			if err != nil {
				t.Fatal(err)
			}
			idToken := signHS256(map[string]any{
				"sub": vector.Input.IDTokenSubject,
				"iat": int64(1_700_000_000),
				"exp": int64(1_700_003_600),
			}, "test-secret")
			actual, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{
				AccessToken: vector.Input.AccessToken,
				IDToken:     idToken,
			})
			if err != nil {
				t.Fatal(err)
			}
			if (actual == nil) != vector.Observation.ResultNull {
				t.Fatalf("PayPal result = %#v, want resultNull=%v", actual, vector.Observation.ResultNull)
			}
			if actual != nil {
				actualUser := &paypalUserObservation{
					ID:            actual.User.ID,
					Name:          actual.User.Name,
					Email:         actual.User.Email,
					Image:         actual.User.Image,
					EmailVerified: actual.User.EmailVerified,
				}
				if !reflect.DeepEqual(actualUser, vector.Observation.User) {
					t.Fatalf("PayPal user = %#v, want %#v", actualUser, vector.Observation.User)
				}
				if !reflect.DeepEqual(actual.Data, vector.Observation.Data) {
					t.Fatalf("PayPal data = %#v, want %#v", actual.Data, vector.Observation.Data)
				}
			} else if vector.Observation.User != nil || vector.Observation.Data != nil {
				t.Fatalf("nil PayPal result has non-nil oracle observation: %#v", vector.Observation)
			}
			if !reflect.DeepEqual(transport.requests, vector.Observation.Requests) {
				t.Fatalf("PayPal requests = %#v, want %#v", transport.requests, vector.Observation.Requests)
			}
		})
	}
}

func loadPayPalConformanceOracle(t *testing.T) paypalConformanceOracle {
	t.Helper()
	return paypalConformanceOracle{Cases: paypalCases}
}
