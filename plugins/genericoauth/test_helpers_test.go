package genericoauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	genericBaseURL = "http://auth.test"
	genericSecret  = "generic-oauth-test-secret-at-least-32"
)

type genericOAuthServer struct {
	server *httptest.Server

	mu                   sync.Mutex
	profile              Profile
	tokenStatus          int
	userInfoStatus       int
	discovery            discoveryDocument
	tokenRequests        []*http.Request
	tokenBodies          []url.Values
	refreshCalls         int
	accessToken          string
	refreshToken         string
	refreshedAccessToken string
	rotatedRefreshToken  string
}

func newGenericOAuthServer(t *testing.T, profile Profile) *genericOAuthServer {
	t.Helper()
	fixture := &genericOAuthServer{
		profile: cloneProfile(profile), tokenStatus: http.StatusOK,
		userInfoStatus: http.StatusOK,
		accessToken:    "access-token", refreshToken: "refresh-token",
		refreshedAccessToken: "access-token", rotatedRefreshToken: "refresh-token",
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			fixture.mu.Lock()
			document := fixture.discovery
			fixture.mu.Unlock()
			if document.AuthorizationEndpoint == "" {
				document.AuthorizationEndpoint = fixture.server.URL + "/authorize"
			}
			if document.TokenEndpoint == "" {
				document.TokenEndpoint = fixture.server.URL + "/token"
			}
			if document.UserInfoEndpoint == "" {
				document.UserInfoEndpoint = fixture.server.URL + "/userinfo"
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(document)
		case "/token", "/token-get":
			_ = request.ParseForm()
			fixture.mu.Lock()
			fixture.tokenRequests = append(fixture.tokenRequests, request.Clone(request.Context()))
			fixture.tokenBodies = append(fixture.tokenBodies, request.Form)
			refresh := request.Form.Get("grant_type") == "refresh_token"
			if refresh {
				fixture.refreshCalls++
			}
			status := fixture.tokenStatus
			accessToken := fixture.accessToken
			refreshToken := fixture.refreshToken
			if refresh {
				accessToken = fixture.refreshedAccessToken
				refreshToken = fixture.rotatedRefreshToken
			}
			fixture.mu.Unlock()
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(status)
			if status >= 200 && status < 300 {
				_ = json.NewEncoder(response).Encode(map[string]any{
					"access_token": accessToken, "refresh_token": refreshToken,
					"token_type": "Bearer", "expires_in": 3600,
					"scope": "openid profile email",
				})
			} else {
				_, _ = io.WriteString(response, `{"error":"server_error"}`)
			}
		case "/userinfo":
			fixture.mu.Lock()
			profile := cloneProfile(fixture.profile)
			status := fixture.userInfoStatus
			fixture.mu.Unlock()
			response.Header().Set("Content-Type", "application/json")
			response.WriteHeader(status)
			if status >= 200 && status < 300 {
				_ = json.NewEncoder(response).Encode(profile)
			} else {
				_, _ = io.WriteString(response, `{"error":"server_error"}`)
			}
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (server *genericOAuthServer) config(providerID string) Config {
	return Config{
		ProviderID: providerID, DiscoveryURL: server.server.URL + "/.well-known/openid-configuration",
		ClientID: "client-id", ClientSecret: "client-secret", PKCE: true,
		Scopes: []string{"openid", "profile", "email"}, HTTPClient: server.server.Client(),
	}
}

func (server *genericOAuthServer) setProfile(profile Profile) {
	server.mu.Lock()
	server.profile = cloneProfile(profile)
	server.mu.Unlock()
}

func (server *genericOAuthServer) setTokenResponses(
	accessToken, refreshToken, refreshedAccessToken, rotatedRefreshToken string,
) {
	server.mu.Lock()
	server.accessToken = accessToken
	server.refreshToken = refreshToken
	server.refreshedAccessToken = refreshedAccessToken
	server.rotatedRefreshToken = rotatedRefreshToken
	server.mu.Unlock()
}

func (server *genericOAuthServer) lastTokenRequest() (*http.Request, url.Values) {
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.tokenRequests) == 0 {
		return nil, nil
	}
	return server.tokenRequests[len(server.tokenRequests)-1], server.tokenBodies[len(server.tokenBodies)-1]
}

type genericResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

func genericExchange(
	t *testing.T,
	auth *singleauth.Auth,
	method, target string,
	body any,
	jar map[string]string,
) genericResponse {
	t.Helper()
	if jar == nil {
		jar = make(map[string]string)
	}
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = genericBaseURL + "/api/auth" + target
	}
	request := httptest.NewRequest(method, target, reader)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if method == http.MethodPost {
		request.Header.Set("Origin", genericBaseURL)
	}
	if len(jar) != 0 {
		names := make([]string, 0, len(jar))
		for name := range jar {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			request.AddCookie(&http.Cookie{Name: name, Value: jar[name]})
		}
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	result := recorder.Result()
	defer result.Body.Close()
	encoded, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range result.Header.Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Attributes.MaxAge != nil && *parsed.Attributes.MaxAge == 0 {
				delete(jar, parsed.Name)
			} else {
				jar[parsed.Name] = parsed.Attributes.Value
			}
		}
	}
	return genericResponse{Status: result.StatusCode, Header: result.Header.Clone(), Body: encoded}
}

func genericTestAuth(t *testing.T, config Config, mutate func(*singleauth.Options)) *singleauth.Auth {
	t.Helper()
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	options := singleauth.Options{
		BaseURL: genericBaseURL, Secret: genericSecret,
		Clock:   func() time.Time { return now },
		Account: singleauth.AccountOptions{StoreStateStrategy: "database"},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Config: []Config{config},
		})},
	}
	if mutate != nil {
		mutate(&options)
	}
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

type genericStartedFlow struct {
	AuthorizationURL *url.URL
	State            string
	Jar              map[string]string
}

func startGenericFlow(
	t *testing.T,
	auth *singleauth.Auth,
	providerID, callbackURL, newUserURL, errorURL string,
	extra map[string]any,
) genericStartedFlow {
	t.Helper()
	body := map[string]any{
		"providerId": providerID, "callbackURL": callbackURL,
		"disableRedirect": true,
	}
	if newUserURL != "" {
		body["newUserCallbackURL"] = newUserURL
	}
	if errorURL != "" {
		body["errorCallbackURL"] = errorURL
	}
	for key, value := range extra {
		body[key] = value
	}
	jar := make(map[string]string)
	response := genericExchange(t, auth, http.MethodPost, "/sign-in/oauth2", body, jar)
	if response.Status != http.StatusOK {
		t.Fatalf("start OAuth status=%d body=%s", response.Status, response.Body)
	}
	var result struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(response.Body, &result); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(result.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatalf("authorization URL has no state: %s", parsed)
	}
	return genericStartedFlow{AuthorizationURL: parsed, State: state, Jar: jar}
}

func finishGenericFlow(
	t *testing.T,
	auth *singleauth.Auth,
	providerID string,
	flow genericStartedFlow,
	extra url.Values,
) genericResponse {
	t.Helper()
	query := url.Values{"code": {"valid-code"}, "state": {flow.State}}
	for key, values := range extra {
		query[key] = append([]string(nil), values...)
	}
	return genericExchange(
		t, auth, http.MethodGet,
		"/oauth2/callback/"+url.PathEscape(providerID)+"?"+query.Encode(), nil, flow.Jar,
	)
}

func genericRecords(t *testing.T, auth *singleauth.Auth, model string) []storage.Record {
	t.Helper()
	rows, err := auth.Adapter().FindMany(t.Context(), storage.FindManyParams{Model: model})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func genericRecordString(record storage.Record, field string) string {
	value, _ := record[field].(string)
	return value
}
