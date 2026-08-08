package haveibeenpwned

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- the HIBP test protocol requires SHA-1.
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
)

func TestRootFactoryPreservesCorePasswordEndpointOrder(t *testing.T) {
	stub := newRangeStub()
	const breached = "breached-password"
	stub.Breach(breached)
	auth := newRootAuth(t, stub.Client(), Options{})

	short := postAuth(t, auth, "/sign-up/email", `{
		"name":"Short", "email":"short@example.com", "password":"short"
	}`, "")
	assertWireError(t, short, http.StatusBadRequest, "PASSWORD_TOO_SHORT", "")
	if stub.CallCount() != 0 {
		t.Fatalf("length validation called HIBP %d times", stub.CallCount())
	}

	rejected := postAuth(t, auth, "/sign-up/email", `{
		"name":"Rejected", "email":"order@example.com", "password":"breached-password"
	}`, "")
	assertWireError(t, rejected, http.StatusBadRequest, ErrorPasswordCompromised, DefaultCompromisedMessage)
	if stub.CallCount() != 1 {
		t.Fatalf("compromised sign-up calls = %d", stub.CallCount())
	}

	accepted := postAuth(t, auth, "/sign-up/email", `{
		"name":"Accepted", "email":"order@example.com", "password":"safe-password"
	}`, "")
	if accepted.Code != http.StatusOK {
		t.Fatalf("safe retry status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	if stub.CallCount() != 2 {
		t.Fatalf("safe sign-up calls = %d", stub.CallCount())
	}
	cookieHeader := cookies.ApplySetCookies("", accepted.Header().Values("Set-Cookie"))
	if cookieHeader == "" {
		t.Fatal("safe sign-up did not create a session cookie")
	}

	// single-auth deliberately hashes on the duplicate-user timing path, so a
	// compromised password wins over the duplicate-account disclosure error.
	duplicate := postAuth(t, auth, "/sign-up/email", `{
		"name":"Duplicate", "email":"order@example.com", "password":"breached-password"
	}`, "")
	assertWireError(t, duplicate, http.StatusBadRequest, ErrorPasswordCompromised, DefaultCompromisedMessage)
	if stub.CallCount() != 3 {
		t.Fatalf("duplicate timing path calls = %d", stub.CallCount())
	}

	// changePassword computes the new hash before verifying currentPassword.
	changed := postAuth(t, auth, "/change-password", `{
		"currentPassword":"wrong-password", "newPassword":"breached-password"
	}`, cookieHeader)
	assertWireError(t, changed, http.StatusBadRequest, ErrorPasswordCompromised, DefaultCompromisedMessage)
	if stub.CallCount() != 4 {
		t.Fatalf("change-password calls = %d", stub.CallCount())
	}

	// resetPassword consumes and validates the reset token before hashing.
	invalidReset := postAuth(t, auth, "/reset-password", `{
		"token":"missing-token", "newPassword":"breached-password"
	}`, "")
	assertWireError(t, invalidReset, http.StatusBadRequest, "INVALID_TOKEN", "")
	if stub.CallCount() != 4 {
		t.Fatalf("invalid reset token called HIBP %d times", stub.CallCount())
	}
}

func TestRootFactoryEnabledAndPathOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		options Options
	}{
		{name: "disabled", options: Options{Enabled: Bool(false)}},
		{name: "explicit-empty-paths", options: Options{Paths: []string{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := newRangeStub()
			stub.Breach("breached-password")
			auth := newRootAuth(t, stub.Client(), test.options)
			response := postAuth(t, auth, "/sign-up/email", `{
				"name":"Allowed", "email":"allowed@example.com", "password":"breached-password"
			}`, "")
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if stub.CallCount() != 0 {
				t.Fatalf("disabled check made %d requests", stub.CallCount())
			}
		})
	}
}

func TestFactorySnapshotsOptionsBeforeRootInitialization(t *testing.T) {
	stub := newRangeStub()
	stub.Breach("breached-password")
	paths := []string{"/sign-up/email"}
	enabled := true
	factory := NewFactory(Options{Paths: paths, Enabled: &enabled})
	paths[0] = "/not-sign-up"
	enabled = false
	auth, err := singleauth.New(rootOptions(stub.Client(), factory))
	if err != nil {
		t.Fatal(err)
	}
	response := postAuth(t, auth, "/sign-up/email", `{
		"name":"Snapshot", "email":"snapshot@example.com", "password":"breached-password"
	}`, "")
	assertWireError(t, response, http.StatusBadRequest, ErrorPasswordCompromised, DefaultCompromisedMessage)
	if stub.CallCount() != 1 {
		t.Fatalf("snapshot plugin calls = %d", stub.CallCount())
	}
}

func TestEmailOTPResetUsesRequestAwareHashChain(t *testing.T) {
	stub := newRangeStub()
	const breached = "email-otp-breached"
	stub.Breach(breached)
	var sentMu sync.Mutex
	var sent emailotp.OTPMessage
	options := rootOptions(stub.Client(),
		NewFactory(Options{}),
		emailotp.NewFactory(emailotp.Options{
			SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
				sentMu.Lock()
				sent = message
				sentMu.Unlock()
				return nil
			},
		}),
	)
	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}

	signUp := postAuth(t, auth, "/sign-up/email", `{
		"name":"OTP User", "email":"otp@example.com", "password":"safe-password"
	}`, "")
	if signUp.Code != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", signUp.Code, signUp.Body.String())
	}
	requestReset := postAuth(t, auth, "/email-otp/request-password-reset", `{
		"email":"otp@example.com"
	}`, "")
	if requestReset.Code != http.StatusOK {
		t.Fatalf("request reset status=%d body=%s", requestReset.Code, requestReset.Body.String())
	}
	sentMu.Lock()
	otp := sent.OTP
	typeSeen := sent.Type
	sentMu.Unlock()
	if otp == "" || typeSeen != emailotp.TypeForgetPassword {
		t.Fatalf("reset OTP = %q type=%q", otp, typeSeen)
	}

	before := stub.CallCount()
	reset := postAuth(t, auth, "/email-otp/reset-password", `{
		"email":"otp@example.com", "otp":"`+otp+`", "password":"`+breached+`"
	}`, "")
	assertWireError(t, reset, http.StatusBadRequest, ErrorPasswordCompromised, DefaultCompromisedMessage)
	if stub.CallCount() != before+1 {
		t.Fatalf("email OTP reset calls = %d, before=%d", stub.CallCount(), before)
	}

	// The OTP check precedes password hashing and consumes a valid OTP. A retry
	// therefore fails without another HIBP request.
	replay := postAuth(t, auth, "/email-otp/reset-password", `{
		"email":"otp@example.com", "otp":"`+otp+`", "password":"another-safe-password"
	}`, "")
	assertWireError(t, replay, http.StatusBadRequest, "INVALID_OTP", "")
	if stub.CallCount() != before+1 {
		t.Fatalf("OTP replay called HIBP %d times", stub.CallCount()-before)
	}
}

func newRootAuth(t *testing.T, client *http.Client, options Options) *singleauth.Auth {
	t.Helper()
	auth, err := singleauth.New(rootOptions(client, NewFactory(options)))
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func rootOptions(client *http.Client, factories ...singleauth.PluginFactory) singleauth.Options {
	return singleauth.Options{
		BaseURL: "http://auth.example.test",
		Secret:  "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hashed:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hashed:"+password },
			},
		},
		HTTPClient:      client,
		PluginFactories: factories,
	}
}

func postAuth(t *testing.T, auth *singleauth.Auth, path, body, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(
		http.MethodPost,
		"http://auth.example.test/api/auth"+path,
		bytes.NewBufferString(body),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://auth.example.test")
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	return recorder
}

func assertWireError(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	status int,
	code string,
	message string,
) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d body=%s, want %d", recorder.Code, recorder.Body.String(), status)
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", recorder.Body.String(), err)
	}
	if body.Code != code {
		t.Fatalf("code=%q body=%s, want %q", body.Code, recorder.Body.String(), code)
	}
	if message != "" && body.Message != message {
		t.Fatalf("message=%q, want %q", body.Message, message)
	}
}

type rangeStub struct {
	mu       sync.RWMutex
	breached map[string][]string
	calls    int
}

func newRangeStub() *rangeStub {
	return &rangeStub{breached: make(map[string][]string)}
}

func (stub *rangeStub) Breach(password string) {
	digest := passwordDigest(password)
	stub.mu.Lock()
	stub.breached[digest[:5]] = append(stub.breached[digest[:5]], digest[5:])
	stub.mu.Unlock()
}

func (stub *rangeStub) CallCount() int {
	stub.mu.RLock()
	defer stub.mu.RUnlock()
	return stub.calls
}

func (stub *rangeStub) Client() *http.Client {
	return &http.Client{Transport: roundTripFunc(stub.roundTrip)}
}

func (stub *rangeStub) roundTrip(request *http.Request) (*http.Response, error) {
	prefix := strings.TrimPrefix(request.URL.Path, "/range/")
	stub.mu.Lock()
	stub.calls++
	suffixes := append([]string(nil), stub.breached[prefix]...)
	stub.mu.Unlock()
	lines := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		lines = append(lines, suffix+":1")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(strings.Join(lines, "\n"))),
		Request:    request,
	}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func passwordDigest(password string) string {
	digest := sha1.Sum([]byte(password)) // #nosec G401 -- HIBP protocol hash.
	return strings.ToUpper(hex.EncodeToString(digest[:]))
}
