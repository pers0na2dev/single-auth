package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

type mutableClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *mutableClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *mutableClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

type sequenceReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *sequenceReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	for index := range target {
		target[index] = reader.next
		reader.next++
	}
	return len(target), nil
}

type harness struct {
	auth  *singleauth.Auth
	clock *mutableClock
}

func newHarness(t *testing.T, configure func(*Options)) *harness {
	t.Helper()
	clock := &mutableClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	options := Options{
		LoginPage: "/login",
		OIDCConfig: OIDCOptions{
			ConsentPage: "/oauth/consent", RequirePKCE: true,
		},
	}
	if configure != nil {
		configure(&options)
	}
	disabled := false
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "0123456789abcdef0123456789abcdef",
		Clock: clock.Now, Random: &sequenceReader{},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		RateLimit:        singleauth.RateLimitOptions{Enabled: &disabled},
		PluginFactories:  []singleauth.PluginFactory{NewFactory(options)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{auth: auth, clock: clock}
}

func (h *harness) call(
	t *testing.T,
	name, method string,
	headers contract.Headers,
	body any,
	query url.Values,
) (singleauth.DirectCallResult, error) {
	t.Helper()
	return h.auth.API().Call(t.Context(), name, singleauth.DirectCallInput{
		Method: method, Scheme: "http", Host: "localhost:3000",
		Headers: headers, Body: body, Query: query,
	})
}

func (h *harness) register(
	t *testing.T,
	authMethod, name, redirectURI string,
) map[string]any {
	t.Helper()
	result, err := h.call(t, "registerMcpClient", http.MethodPost, contract.Headers{}, map[string]any{
		"client_name": name, "redirect_uris": []string{redirectURI},
		"logo_uri": "", "token_endpoint_auth_method": authMethod,
	}, nil)
	if err != nil {
		t.Fatalf("register: %v body=%s", err, result.Response.Body())
	}
	object, ok := result.Value.(map[string]any)
	if !ok {
		t.Fatalf("register response = %#v", result.Value)
	}
	return object
}

func (h *harness) signUp(t *testing.T, sequence int) (string, contract.Headers) {
	t.Helper()
	result, err := h.auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name:     fmt.Sprintf("MCP User %d", sequence),
		Email:    fmt.Sprintf("mcp-user-%d@example.test", sequence),
		Password: "password-12345",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookies.ApplySetCookies("", result.Headers.Values("Set-Cookie"))
	return result.User.ID, contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookie})
}

func responseObject(t *testing.T, result singleauth.DirectCallResult) map[string]any {
	t.Helper()
	object, ok := result.Value.(map[string]any)
	if !ok {
		t.Fatalf("response = %#v body=%s", result.Value, result.Response.Body())
	}
	return object
}

func headerValue(headers contract.Headers, name string) string {
	value, _ := headers.Get(name)
	return value
}

func oauthErrorObject(t *testing.T, result singleauth.DirectCallResult, err error, status int, code string) map[string]any {
	t.Helper()
	if err == nil {
		t.Fatalf("expected OAuth error %s, response=%s", code, result.Response.Body())
	}
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != status {
		t.Fatalf("error = %T %#v", err, err)
	}
	object := responseObject(t, result)
	if object["error"] != code {
		t.Fatalf("OAuth error = %#v", object)
	}
	return object
}

func seedClient(t *testing.T, h *harness, id, secret, clientType string, disabled bool) {
	t.Helper()
	now := h.clock.Now()
	data := storage.Record{
		"clientId": id, "type": clientType, "name": "Seeded client",
		"redirectUrls": "http://localhost/callback", "disabled": disabled,
		"createdAt": now, "updatedAt": now,
	}
	if secret != "" {
		data["clientSecret"] = secret
	}
	if _, err := h.auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "oauthApplication", Data: data,
	}); err != nil {
		t.Fatal(err)
	}
}

func seedToken(
	t *testing.T,
	h *harness,
	userID, clientID, access, refresh, scopes string,
	accessExpiry, refreshExpiry time.Time,
) {
	t.Helper()
	now := h.clock.Now()
	if _, err := h.auth.Adapter().Create(t.Context(), storage.CreateParams{
		Model: "oauthAccessToken",
		Data: storage.Record{
			"accessToken": access, "refreshToken": refresh,
			"accessTokenExpiresAt": accessExpiry, "refreshTokenExpiresAt": refreshExpiry,
			"clientId": clientID, "userId": userID, "scopes": scopes,
			"createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func seedCode(t *testing.T, h *harness, identifier string, value codeVerificationValue) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	now := h.clock.Now()
	if _, err := h.auth.Adapter().Create(context.Background(), storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"identifier": identifier, "value": string(encoded),
			"expiresAt": now.Add(10 * time.Minute), "createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		t.Fatal(err)
	}
}
