package captcha

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
)

type captureTransport struct {
	mu       sync.Mutex
	status   int
	response string
	calls    int
	url      string
	method   string
	headers  http.Header
	body     string
}

func (transport *captureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	transport.mu.Lock()
	transport.calls++
	transport.url = request.URL.String()
	transport.method = request.Method
	transport.headers = request.Header.Clone()
	transport.body = string(body)
	status := transport.status
	responseBody := transport.response
	transport.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(responseBody)),
		Request:    request,
	}, nil
}

func (transport *captureTransport) snapshot() (int, string, string, http.Header, string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.calls, transport.url, transport.method, transport.headers.Clone(), transport.body
}

func TestRootFactoryBindsHTTPClientBasePathAndAdvancedIPAddress(t *testing.T) {
	transport := &captureTransport{response: `{"success":true,"hostname":"auth.test"}`}
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		BasePath:   "/custom-auth",
		HTTPClient: &http.Client{Transport: transport},
		Advanced: singleauth.AdvancedOptions{IPAddress: ratelimit.IPOptions{
			Headers: []string{"x-real-client-ip"},
		}},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Provider: GoogleRecaptcha, SecretKey: "factory-secret",
		})},
	})

	missing := httptest.NewRequest(http.MethodPost, "http://auth.test/custom-auth/sign-up/email", nil)
	missingRecorder := httptest.NewRecorder()
	auth.ServeHTTP(missingRecorder, missing)
	if missingRecorder.Code != http.StatusBadRequest || missingRecorder.Body.String() != missingResponseBody {
		t.Fatalf("missing response = %d %s", missingRecorder.Code, missingRecorder.Body.String())
	}

	body := []byte(`{"name":"Captcha User","email":"captcha@example.test","password":"password123"}`)
	request := httptest.NewRequest(http.MethodPost, "http://auth.test/custom-auth/sign-up/email", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("x-captcha-response", "factory-token")
	request.Header.Set("x-real-client-ip", "198.51.100.44")
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("sign up = %d %s", recorder.Code, recorder.Body.String())
	}
	calls, url, method, headers, providerBody := transport.snapshot()
	if calls != 1 || url != GoogleRecaptchaSiteVerifyURL || method != http.MethodPost {
		t.Fatalf("provider request = calls:%d %s %s", calls, method, url)
	}
	if headers.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("provider content type = %q", headers.Get("Content-Type"))
	}
	if providerBody != "secret=factory-secret&response=factory-token&remoteip=198.51.100.44" {
		t.Fatalf("provider body = %q", providerBody)
	}
}

func TestRootRateLimitRunsBeforeCaptchaVerification(t *testing.T) {
	transport := &captureTransport{response: `{"success":false,"error-codes":["invalid-input-response"]}`}
	enabled := true
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
		Environment: "production",
		HTTPClient:  &http.Client{Transport: transport},
		Advanced: singleauth.AdvancedOptions{IPAddress: ratelimit.IPOptions{
			Headers: []string{"x-real-client-ip"},
		}},
		RateLimit: singleauth.RateLimitOptions{
			Enabled: &enabled, Window: 10, Max: 1,
			CustomRules: []ratelimit.CustomRule{{
				Pattern: "/sign-in/email", Rule: ratelimit.Rule{Window: 10, Max: 1},
			}},
		},
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		PluginFactories: []singleauth.PluginFactory{NewFactory(Options{
			Provider: CloudflareTurnstile, SecretKey: "secret",
		})},
	})

	request := func() *http.Request {
		body := bytes.NewBufferString(`{"email":"nobody@example.test","password":"password123"}`)
		value := httptest.NewRequest(http.MethodPost, "http://auth.test/api/auth/sign-in/email", body)
		value.Header.Set("Content-Type", "application/json")
		value.Header.Set("x-captcha-response", "invalid-token")
		value.Header.Set("x-real-client-ip", "203.0.113.55")
		return value
	}
	first := httptest.NewRecorder()
	auth.ServeHTTP(first, request())
	second := httptest.NewRecorder()
	auth.ServeHTTP(second, request())
	if first.Code != http.StatusForbidden || second.Code != http.StatusTooManyRequests {
		t.Fatalf("statuses = %d %s, %d %s", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	calls, _, _, _, _ := transport.snapshot()
	if calls != 1 {
		t.Fatalf("provider calls = %d, want 1", calls)
	}
}

func TestEmailOTPDefaultExemptionAndExplicitOptIn(t *testing.T) {
	newAuth := func(endpoints []string, sent *emailotp.OTPMessage) *singleauth.Auth {
		t.Helper()
		return singleauth.MustNew(singleauth.Options{
			BaseURL: "http://auth.test", Secret: "0123456789abcdef0123456789abcdef",
			HTTPClient: &http.Client{Transport: &captureTransport{response: `{"success":true}`}},
			PluginFactories: []singleauth.PluginFactory{
				NewFactory(Options{
					Provider: CloudflareTurnstile, SecretKey: "secret", Endpoints: endpoints,
				}),
				emailotp.NewFactory(emailotp.Options{
					SendVerificationOTP: func(_ context.Context, message emailotp.OTPMessage, _ *engine.Context) error {
						*sent = message
						return nil
					},
				}),
			},
		})
	}
	post := func(auth *singleauth.Auth, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "http://auth.test/api/auth"+path, bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		return recorder
	}

	var defaultMessage emailotp.OTPMessage
	defaultAuth := newAuth(nil, &defaultMessage)
	if response := post(defaultAuth, "/email-otp/send-verification-otp", `{"email":"otp@example.test","type":"sign-in"}`); response.Code != http.StatusOK {
		t.Fatalf("send default OTP = %d %s", response.Code, response.Body.String())
	}
	if defaultMessage.OTP == "" {
		t.Fatal("default OTP was not captured")
	}
	response := post(defaultAuth, "/sign-in/email-otp", `{"email":"otp@example.test","otp":"`+defaultMessage.OTP+`","name":"OTP User"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("default exempt sign in = %d %s", response.Code, response.Body.String())
	}

	var explicitMessage emailotp.OTPMessage
	explicitAuth := newAuth([]string{"/sign-in/email-otp"}, &explicitMessage)
	response = post(explicitAuth, "/sign-in/email-otp", `{"email":"otp@example.test","otp":"000000"}`)
	if response.Code != http.StatusBadRequest || response.Body.String() != missingResponseBody {
		t.Fatalf("explicit opt-in = %d %s", response.Code, response.Body.String())
	}
}
