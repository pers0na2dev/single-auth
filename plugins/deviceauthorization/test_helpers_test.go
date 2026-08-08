package deviceauthorization

import (
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

type testClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *testClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

type testUser struct {
	ID      string
	Headers contract.Headers
}

type deviceHarness struct {
	auth    *singleauth.Auth
	clock   *testClock
	options Options
}

func newDeviceHarness(t *testing.T, configure func(*Options)) *deviceHarness {
	t.Helper()
	clock := &testClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
	options := Options{ExpiresIn: 5 * time.Minute, Interval: 2 * time.Second}
	if configure != nil {
		configure(&options)
	}
	disabled := false
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000",
		Secret:  "0123456789abcdef0123456789abcdef",
		Clock:   clock.Now,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
		},
		RateLimit: singleauth.RateLimitOptions{Enabled: &disabled},
		PluginFactories: []singleauth.PluginFactory{
			NewFactory(options),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &deviceHarness{auth: auth, clock: clock, options: options}
}

func (h *deviceHarness) call(
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

func (h *deviceHarness) requestCode(t *testing.T, body map[string]any) DeviceCodeResponse {
	t.Helper()
	result, err := h.call(t, "deviceCode", http.MethodPost, contract.Headers{}, body, nil)
	if err != nil {
		t.Fatalf("deviceCode: %v body=%s", err, result.Response.Body())
	}
	var response DeviceCodeResponse
	if err := json.Unmarshal(result.Response.Body(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func (h *deviceHarness) poll(t *testing.T, deviceCode, clientID string) (singleauth.DirectCallResult, error) {
	t.Helper()
	return h.call(t, "deviceToken", http.MethodPost, contract.Headers{}, map[string]any{
		"grant_type": DeviceCodeGrantType, "device_code": deviceCode, "client_id": clientID,
	}, nil)
}

func (h *deviceHarness) verify(t *testing.T, userCode string, headers contract.Headers) (singleauth.DirectCallResult, error) {
	t.Helper()
	return h.call(t, "deviceVerify", http.MethodGet, headers, nil, url.Values{"user_code": {userCode}})
}

func (h *deviceHarness) decision(t *testing.T, endpoint, userCode string, headers contract.Headers) (singleauth.DirectCallResult, error) {
	t.Helper()
	return h.call(t, endpoint, http.MethodPost, headers, map[string]any{"userCode": userCode}, nil)
}

func (h *deviceHarness) signUp(t *testing.T, sequence int) testUser {
	t.Helper()
	result, err := h.auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name:     fmt.Sprintf("Device User %d", sequence),
		Email:    fmt.Sprintf("device-user-%d@example.test", sequence),
		Password: "password-12345",
	})
	if err != nil {
		t.Fatal(err)
	}
	cookieHeader := cookies.ApplySetCookies("", result.Headers.Values("Set-Cookie"))
	headers := contract.NewHeaders(contract.HeaderField{Name: "Cookie", Value: cookieHeader})
	return testUser{ID: result.User.ID, Headers: headers}
}

func (h *deviceHarness) deviceRecord(t *testing.T, field string, value any) storage.Record {
	t.Helper()
	record, err := h.auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "deviceCode", Where: []storage.Where{{Field: field, Value: value}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func decodeObjectResponse(t *testing.T, result singleauth.DirectCallResult) map[string]any {
	t.Helper()
	object, ok := result.Value.(map[string]any)
	if !ok {
		t.Fatalf("response value = %#v", result.Value)
	}
	return object
}

func assertOAuthError(t *testing.T, result singleauth.DirectCallResult, err error, status int, code, description string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s error, response=%s", code, result.Response.Body())
	}
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != status {
		t.Fatalf("error = %T %#v", err, err)
	}
	object := decodeObjectResponse(t, result)
	if object["error"] != code || object["error_description"] != description {
		t.Fatalf("OAuth error = %#v", object)
	}
}
