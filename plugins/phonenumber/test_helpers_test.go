package phonenumber

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

const (
	testBaseURL = "http://auth.example.test"
	testSecret  = "0123456789abcdef0123456789abcdef"
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

type captureStore struct {
	mu        sync.Mutex
	otp       map[string]string
	resetOTP  map[string]string
	events    []VerificationEvent
	resetUser []string
}

func newCaptureStore() *captureStore {
	return &captureStore{otp: map[string]string{}, resetOTP: map[string]string{}}
}

func (store *captureStore) sendOTP(_ context.Context, message OTPMessage, _ *engine.Context) error {
	store.mu.Lock()
	store.otp[message.PhoneNumber] = message.Code
	store.mu.Unlock()
	return nil
}

func (store *captureStore) code(phone string) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.otp[phone]
}

func (store *captureStore) resetCode(phone string) string {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.resetOTP[phone]
}

type httpResult struct {
	status  int
	headers http.Header
	body    map[string]any
	rawBody string
	cookie  string
}

func newRootHarness(
	t *testing.T,
	pluginOptions Options,
	mutate func(*singleauth.Options),
) (*singleauth.Auth, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, time.August, 9, 9, 0, 0, 0, time.UTC)}
	options := singleauth.Options{
		BaseURL: testBaseURL,
		Secret:  testSecret,
		Clock:   clock.Now,
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "test:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "test:"+password },
			},
		},
		PluginFactories: []singleauth.PluginFactory{NewFactory(pluginOptions)},
	}
	if mutate != nil {
		mutate(&options)
	}
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return auth, clock
}

func exchange(
	t *testing.T,
	auth *singleauth.Auth,
	method, path, cookie string,
	body any,
) httpResult {
	t.Helper()
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(encoded))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
		request.Header.Set("Origin", testBaseURL)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	result := httpResult{
		status: recorder.Code, headers: recorder.Header(), rawBody: recorder.Body.String(),
		cookie: cookies.ApplySetCookies(cookie, recorder.Header().Values("Set-Cookie")),
	}
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &result.body); err != nil {
			t.Fatalf("decode status=%d body=%q: %v", recorder.Code, recorder.Body.String(), err)
		}
	}
	return result
}

func bodyString(t *testing.T, body map[string]any, field string) string {
	t.Helper()
	value, ok := body[field].(string)
	if !ok {
		t.Fatalf("body[%q] = %#v", field, body[field])
	}
	return value
}

func bodyObject(t *testing.T, body map[string]any, field string) map[string]any {
	t.Helper()
	value, ok := body[field].(map[string]any)
	if !ok {
		t.Fatalf("body[%q] = %#v", field, body[field])
	}
	return value
}

func errorCode(result httpResult) string {
	value, _ := result.body["code"].(string)
	return value
}
