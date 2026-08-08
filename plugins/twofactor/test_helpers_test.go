package twofactor

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
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	testBaseURL = "http://auth.example.test"
	testSecret  = "0123456789abcdef0123456789abcdef"
	testEmail   = "two-factor@example.test"
	testPass    = "password123"
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

type otpCapture struct {
	mu   sync.Mutex
	code string
}

func (capture *otpCapture) send(_ context.Context, message OTPMessage, _ *engine.Context) error {
	capture.mu.Lock()
	capture.code = message.OTP
	capture.mu.Unlock()
	return nil
}

func (capture *otpCapture) get() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.code
}

type testResult struct {
	status  int
	headers contract.Headers
	body    map[string]any
	raw     []byte
	cookie  string
	err     error
}

func newHarness(t *testing.T, pluginOptions Options, mutate func(*singleauth.Options)) (*singleauth.Auth, *testClock) {
	t.Helper()
	clock := &testClock{now: time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)}
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

func invoke(t *testing.T, auth *singleauth.Auth, name, method, path, cookie string, body any) testResult {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	headers := contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"})
	if cookie != "" {
		headers.Add("Cookie", cookie)
		headers.Add("Origin", testBaseURL)
	}
	request := contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Scheme: "http", Host: "auth.example.test", Headers: headers, Body: raw,
	})
	response, err := auth.Invoke(name, engine.DirectInput{Request: request})
	return decodeResult(t, response, cookie, err)
}

func invokeRaw(auth *singleauth.Auth, name, method, path, cookie string, body any) (contract.Response, error) {
	raw, _ := json.Marshal(body)
	headers := contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"})
	if cookie != "" {
		headers.Add("Cookie", cookie)
		headers.Add("Origin", testBaseURL)
	}
	request := contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Scheme: "http", Host: "auth.example.test", Headers: headers, Body: raw,
	})
	return auth.Invoke(name, engine.DirectInput{Request: request})
}

func dispatch(t *testing.T, auth *singleauth.Auth, method, path, cookie string, body any) testResult {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	headers := contract.NewHeaders(contract.HeaderField{Name: "Content-Type", Value: "application/json"})
	if cookie != "" {
		headers.Add("Cookie", cookie)
		headers.Add("Origin", testBaseURL)
	}
	request := contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Scheme: "http", Host: "auth.example.test", Headers: headers, Body: raw,
	})
	response, err := auth.Dispatch(request)
	return decodeResult(t, response, cookie, err)
}

func exchangeHTTP(t *testing.T, auth *singleauth.Auth, method, path, cookie string, body any) testResult {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, testBaseURL+"/api/auth"+path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
		request.Header.Set("Origin", testBaseURL)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	headers := contract.Headers{}
	for key, values := range recorder.Header() {
		for _, value := range values {
			headers.Add(key, value)
		}
	}
	response := contract.NewResponse(recorder.Code, headers, recorder.Body.Bytes())
	return decodeResult(t, response, cookie, nil)
}

func decodeResult(t *testing.T, response contract.Response, cookie string, err error) testResult {
	t.Helper()
	result := testResult{
		status: response.Status(), headers: response.Headers(), raw: response.Body(), err: err,
		cookie: cookies.ApplySetCookies(cookie, response.Headers().Values("Set-Cookie")),
	}
	if len(result.raw) > 0 {
		if jsonErr := json.Unmarshal(result.raw, &result.body); jsonErr != nil {
			t.Fatalf("decode status=%d body=%q: %v", result.status, result.raw, jsonErr)
		}
	}
	return result
}

func signUp(t *testing.T, auth *singleauth.Auth) testResult {
	t.Helper()
	result := invoke(t, auth, "signUpEmail", http.MethodPost, "/sign-up/email", "", map[string]any{
		"name": "Two Factor", "email": testEmail, "password": testPass,
	})
	if result.status != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s err=%v", result.status, result.raw, result.err)
	}
	return result
}

func enable(t *testing.T, auth *singleauth.Auth, cookie string) testResult {
	t.Helper()
	result := invoke(t, auth, "enableTwoFactor", http.MethodPost, "/two-factor/enable", cookie, map[string]any{
		"password": testPass,
	})
	if result.status != http.StatusOK {
		t.Fatalf("enable status=%d body=%s err=%v", result.status, result.raw, result.err)
	}
	return result
}

func twoFactorRow(t *testing.T, auth *singleauth.Auth) storage.Record {
	t.Helper()
	row, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{Model: "twoFactor"})
	if err != nil || row == nil {
		t.Fatalf("twoFactor row=%#v err=%v", row, err)
	}
	return row
}

func verifyEnrollment(t *testing.T, auth *singleauth.Auth, clock *testClock, cookie string) testResult {
	t.Helper()
	row := twoFactorRow(t, auth)
	encrypted, _ := recordString(row, "secret")
	// The root factory snapshot intentionally has no bound runtime. Use the
	// public encrypted-value compatibility helper through the frozen test
	// secret, which is the root's legacy key in this harness.
	plain, err := baCrypto.Decrypt(testSecret, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	code, err := GenerateTOTP(string(plain), clock.Now(), 6, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result := invoke(t, auth, "verifyTOTP", http.MethodPost, "/two-factor/verify-totp", cookie, map[string]any{"code": code})
	if result.status != http.StatusOK {
		t.Fatalf("verify enrollment status=%d body=%s err=%v", result.status, result.raw, result.err)
	}
	return result
}

func errorCode(result testResult) string {
	value, _ := result.body["code"].(string)
	return value
}

type enrolledHarness struct {
	auth         *singleauth.Auth
	clock        *testClock
	signedUp     testResult
	activeCookie string
	userID       string
	secret       string
	backupCodes  []string
}

func setupEnrolled(t *testing.T, options Options, mutate func(*singleauth.Options)) enrolledHarness {
	t.Helper()
	auth, clock := newHarness(t, options, mutate)
	signedUp := signUp(t, auth)
	enrollment := enable(t, auth, signedUp.cookie)
	row := twoFactorRow(t, auth)
	secret := decryptTwoFactorSecret(t, row)
	verified := verifyEnrollment(t, auth, clock, signedUp.cookie)
	activeCookie := cookies.ApplySetCookies(signedUp.cookie, verified.headers.Values("Set-Cookie"))
	user, err := auth.Adapter().FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: testEmail}},
	})
	if err != nil || user == nil {
		t.Fatalf("enrolled user=%#v err=%v", user, err)
	}
	userIDValue, _ := recordString(user, "id")
	rawCodes, ok := enrollment.body["backupCodes"].([]any)
	if !ok {
		t.Fatalf("backupCodes=%#v", enrollment.body["backupCodes"])
	}
	backupCodes := make([]string, len(rawCodes))
	for index, value := range rawCodes {
		backupCodes[index], _ = value.(string)
	}
	return enrolledHarness{
		auth: auth, clock: clock, signedUp: signedUp, activeCookie: activeCookie,
		userID: userIDValue, secret: secret, backupCodes: backupCodes,
	}
}

func (h enrolledHarness) challenge(t *testing.T) testResult {
	t.Helper()
	result := invoke(t, h.auth, "signInEmail", http.MethodPost, "/sign-in/email", "", map[string]any{
		"email": testEmail, "password": testPass,
	})
	if result.status != http.StatusOK || result.body["twoFactorRedirect"] != true {
		t.Fatalf("challenge status=%d body=%#v err=%v", result.status, result.body, result.err)
	}
	return result
}

func (h enrolledHarness) currentTOTP(t *testing.T) string {
	t.Helper()
	code, err := GenerateTOTP(h.secret, h.clock.Now(), 6, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func updateTwoFactor(t *testing.T, auth *singleauth.Auth, update storage.Record) storage.Record {
	t.Helper()
	row := twoFactorRow(t, auth)
	id, _ := recordString(row, "id")
	updated, err := auth.Adapter().Update(t.Context(), storage.UpdateParams{
		Model: "twoFactor", Where: []storage.Where{{Field: "id", Value: id}}, Update: update,
	})
	if err != nil || updated == nil {
		t.Fatalf("update twoFactor=%#v err=%v", updated, err)
	}
	return updated
}
