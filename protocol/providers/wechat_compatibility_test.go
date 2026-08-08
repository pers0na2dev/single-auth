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

type wechatOracleFile struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type wechatRequestObservation struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

type wechatUserObservation struct {
	ID            *string `json:"userId"`
	Name          *string `json:"userName"`
	Email         *string `json:"userEmail"`
	Image         *string `json:"userImage"`
	EmailVerified *bool   `json:"emailVerified"`
}

type wechatConformanceOracle struct {
	SchemaVersion   int                `json:"schemaVersion"`
	UpstreamPackage string             `json:"upstreamPackage"`
	OracleKind      string             `json:"oracleKind"`
	Sources         []wechatOracleFile `json:"sources"`
	Runtime         wechatOracleFile   `json:"runtime"`
	ManifestTestIDs []string           `json:"manifestTestIDs"`
	TestCount       int                `json:"testCount"`
	Cases           []struct {
		ID        string `json:"id"`
		File      string `json:"file"`
		Suite     string `json:"suite"`
		Title     string `json:"title"`
		Operation string `json:"operation"`
		Input     struct {
			ClientID     string         `json:"clientId"`
			ClientSecret string         `json:"clientSecret"`
			AccessToken  string         `json:"accessToken"`
			OpenID       *string        `json:"openid"`
			Profile      map[string]any `json:"profile"`
			MappedEmail  *string        `json:"mappedEmail"`
		} `json:"input"`
		Observation struct {
			ResultNull bool `json:"resultNull"`
			wechatUserObservation
			Data     map[string]any             `json:"data"`
			Requests []wechatRequestObservation `json:"requests"`
		} `json:"observation"`
	} `json:"cases"`
}

type wechatRecordingTransport struct {
	mu       sync.Mutex
	profile  map[string]any
	requests []wechatRequestObservation
}

func (transport *wechatRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	defer transport.mu.Unlock()

	transport.requests = append(transport.requests, wechatRequestObservation{
		URL:    request.URL.String(),
		Method: request.Method,
	})
	if transport.profile == nil {
		return nil, fmt.Errorf("unexpected WeChat request to %s", request.URL)
	}
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

func (transport *wechatRecordingTransport) snapshot() []wechatRequestObservation {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	requests := make([]wechatRequestObservation, len(transport.requests))
	copy(requests, transport.requests)
	return requests
}

func TestWeChatBehavior(t *testing.T) {
	oracle := loadWeChatConformanceOracle(t)
	for _, vector := range oracle.Cases {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			transport := &wechatRecordingTransport{
				profile:  vector.Input.Profile,
				requests: make([]wechatRequestObservation, 0, len(vector.Observation.Requests)),
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
			provider, err := WeChat(options)
			if err != nil {
				t.Fatal(err)
			}

			var raw map[string]any
			if vector.Input.OpenID != nil {
				raw = map[string]any{"openid": *vector.Input.OpenID}
			}
			result, err := provider.GetUserInfo(context.Background(), oauth2.Tokens{
				AccessToken: vector.Input.AccessToken,
				Raw:         raw,
			})
			if err != nil {
				t.Fatal(err)
			}
			if (result == nil) != vector.Observation.ResultNull {
				t.Fatalf("WeChat result = %#v, want resultNull=%v", result, vector.Observation.ResultNull)
			}
			if result != nil {
				actualUser := wechatUserFromResult(result)
				if !reflect.DeepEqual(actualUser, vector.Observation.wechatUserObservation) {
					t.Fatalf("WeChat user = %#v, want %#v", actualUser, vector.Observation.wechatUserObservation)
				}
				if !reflect.DeepEqual(result.Data, vector.Observation.Data) {
					t.Fatalf("WeChat data = %#v, want %#v", result.Data, vector.Observation.Data)
				}
			}
			if requests := transport.snapshot(); !reflect.DeepEqual(requests, vector.Observation.Requests) {
				t.Fatalf("WeChat requests = %#v, want %#v", requests, vector.Observation.Requests)
			}
		})
	}
}

func wechatUserFromResult(result *UserInfoResult) wechatUserObservation {
	id := result.User.ID
	name := result.User.Name
	image := result.User.Image
	verified := result.User.EmailVerified
	return wechatUserObservation{
		ID:            &id,
		Name:          &name,
		Email:         result.User.Email,
		Image:         &image,
		EmailVerified: &verified,
	}
}

func loadWeChatConformanceOracle(t *testing.T) wechatConformanceOracle {
	t.Helper()
	return wechatConformanceOracle{Cases: wechatCases}
}
