package captcha

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func TestProtectedPathMatchesReferenceSubstringAndExemptionRules(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		basePath  string
		endpoints []string
		protected bool
	}{
		{name: "default sign up", path: "/api/auth/sign-up/email", basePath: "/api/auth", protected: true},
		{name: "default sign in child by substring", path: "/api/auth/x/sign-in/email/child", basePath: "/api/auth", protected: true},
		{name: "base path replaced at first non-prefix occurrence", path: "/prefix/api/auth/sign-in/email", basePath: "/api/auth", protected: true},
		{name: "default password reset", path: "/api/auth/request-password-reset", basePath: "/api/auth", protected: true},
		{name: "unprotected", path: "/api/auth/get-session", basePath: "/api/auth", protected: false},
		{name: "email otp default exemption", path: "/api/auth/sign-in/email-otp", basePath: "/api/auth", protected: false},
		{name: "email otp remains exempt for another custom endpoint", path: "/api/auth/sign-in/email-otp", basePath: "/api/auth", endpoints: []string{"/sign-in/email"}, protected: false},
		{name: "email otp explicit opt in", path: "/api/auth/sign-in/email-otp", basePath: "/api/auth", endpoints: []string{"/sign-in/email-otp"}, protected: true},
		{name: "empty custom list selects defaults", path: "/api/auth/sign-in/email", basePath: "/api/auth", endpoints: []string{}, protected: true},
		{name: "empty endpoint matches everything", path: "/api/auth/get-session", basePath: "/api/auth", endpoints: []string{""}, protected: true},
		{name: "leading and trailing double slash normalized once", path: "/custom//sign-in/email//", basePath: "/custom", protected: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := protectedPath(test.path, test.basePath, test.endpoints); got != test.protected {
				t.Fatalf("protectedPath(%q, %q, %#v) = %t, want %t", test.path, test.basePath, test.endpoints, got, test.protected)
			}
		})
	}
}

func TestURLSearchParamsEncodingIsOrderedAndWHATWGCompatible(t *testing.T) {
	fields := []formField{
		{name: "secret", value: "a~ b!*'()-_."},
		{name: "response", value: "Привет/世界"},
		{name: "remoteIp", value: "192.0.2.1"},
	}
	const expected = "secret=a%7E+b%21*%27%28%29-_.&response=%D0%9F%D1%80%D0%B8%D0%B2%D0%B5%D1%82%2F%E4%B8%96%E7%95%8C&remoteIp=192.0.2.1"
	if got := encodeForm(fields); got != expected {
		t.Fatalf("encoded form = %q, want %q", got, expected)
	}
}

func TestOptionsAreSnapshottedAndDefaultCopiesAreIndependent(t *testing.T) {
	endpoints := []string{"/custom"}
	hostnames := []string{"allowed.test"}
	minScore := 0.75
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		return jsonProviderResponse(http.StatusOK, `{"success":true,"score":0.8,"hostname":"allowed.test"}`), nil
	})
	descriptor, err := New(Options{
		Provider: GoogleRecaptcha, SecretKey: "secret", Endpoints: endpoints,
		AllowedHostnames: hostnames, MinScore: &minScore,
		Runtime: Runtime{HTTPClient: doer},
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoints[0] = "/different"
	hostnames[0] = "different.test"
	minScore = 0.9

	registry, err := engine.NewRegistry([]engine.Endpoint{{
		Name: "custom", Path: "/custom", Methods: []string{http.MethodPost},
		Handler: func(*engine.Context) (contract.Response, error) {
			return contract.NewResponse(http.StatusNoContent, contract.Headers{}, nil), nil
		},
	}}, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	response := dispatchCaptcha(t, dispatcher, context.Background(), http.MethodPost, "/api/auth/custom", captchaHeaders("token"))
	if response.Status() != http.StatusNoContent {
		t.Fatalf("snapshotted options response = %d %s", response.Status(), response.Body())
	}

	first := DefaultEndpoints()
	first[0] = "/mutated"
	if second := DefaultEndpoints(); reflect.DeepEqual(first, second) || second[0] != "/sign-up/email" {
		t.Fatalf("default endpoint copies alias: first=%#v second=%#v", first, second)
	}
}

func TestCaptchaResponseHeaderUsesWHATWGCombinedValue(t *testing.T) {
	var providerBody string
	dispatcher := testDispatcher(t, Options{
		Provider: HCaptcha, SecretKey: "secret",
		Runtime: Runtime{HTTPClient: doerFunc(func(request *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(request.Body)
			if err != nil {
				return nil, err
			}
			providerBody = string(body)
			return jsonProviderResponse(http.StatusOK, `{"success":true}`), nil
		})},
	})
	headers := contract.NewHeaders(
		contract.HeaderField{Name: "X-Captcha-Response", Value: "first"},
		contract.HeaderField{Name: "x-captcha-response", Value: "second"},
	)
	response := dispatchCaptcha(t, dispatcher, context.Background(), http.MethodPost, "/api/auth/sign-in/email", headers)
	if response.Status() != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", response.Status(), response.Body())
	}
	if providerBody != "secret=secret&response=first%2C+second" {
		t.Fatalf("provider body = %q", providerBody)
	}
}

func TestProviderResponseJavaScriptSemantics(t *testing.T) {
	tests := []struct {
		name       string
		provider   Provider
		body       string
		configure  func(*Options)
		wantStatus int
	}{
		{name: "truthy primitive has no success property", provider: HCaptcha, body: `"truthy"`, wantStatus: http.StatusForbidden},
		{name: "null data is service unavailable", provider: HCaptcha, body: `null`, wantStatus: http.StatusInternalServerError},
		{name: "truthy string success is accepted", provider: HCaptcha, body: `{"success":"yes"}`, wantStatus: http.StatusNoContent},
		{name: "numeric zero success fails", provider: HCaptcha, body: `{"success":0}`, wantStatus: http.StatusForbidden},
		{name: "google string score is not v3", provider: GoogleRecaptcha, body: `{"success":true,"score":"0.1"}`, wantStatus: http.StatusNoContent},
		{
			name: "google explicit zero score threshold", provider: GoogleRecaptcha,
			body: `{"success":true,"score":-0.1}`, wantStatus: http.StatusForbidden,
			configure: func(options *Options) { options.MinScore = Score(0) },
		},
		{
			name: "empty expected action is disabled", provider: CloudflareTurnstile,
			body: `{"success":true,"action":"other"}`, wantStatus: http.StatusNoContent,
			configure: func(options *Options) { options.ExpectedAction = "" },
		},
		{
			name: "empty hostname allowlist is disabled", provider: CloudflareTurnstile,
			body: `{"success":true}`, wantStatus: http.StatusNoContent,
			configure: func(options *Options) { options.AllowedHostnames = []string{} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := Options{
				Provider: test.provider, SecretKey: "secret",
				Runtime: Runtime{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
					return jsonProviderResponse(http.StatusOK, test.body), nil
				})},
			}
			if test.configure != nil {
				test.configure(&options)
			}
			response := dispatchCaptcha(
				t, testDispatcher(t, options), context.Background(), http.MethodPost,
				"/api/auth/sign-in/email", captchaHeaders("token"),
			)
			if response.Status() != test.wantStatus {
				t.Fatalf("status = %d body=%s, want %d", response.Status(), response.Body(), test.wantStatus)
			}
		})
	}
}

func TestProviderFailuresAlwaysFailClosed(t *testing.T) {
	tests := []struct {
		name string
		doer HTTPDoer
	}{
		{name: "transport error", doer: doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })},
		{name: "nil response", doer: doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil })},
		{name: "nil body", doer: doerFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: http.StatusOK}, nil })},
		{name: "non success status", doer: doerFunc(func(*http.Request) (*http.Response, error) {
			return jsonProviderResponse(http.StatusServiceUnavailable, `{"success":true}`), nil
		})},
		{name: "invalid json", doer: doerFunc(func(*http.Request) (*http.Response, error) { return jsonProviderResponse(http.StatusOK, `{`), nil })},
		{name: "panic", doer: doerFunc(func(*http.Request) (*http.Response, error) { panic("boom") })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := dispatchCaptcha(t, testDispatcher(t, Options{
				Provider: CloudflareTurnstile, SecretKey: "secret",
				Runtime: Runtime{HTTPClient: test.doer},
			}), context.Background(), http.MethodPost, "/api/auth/sign-in/email", captchaHeaders("token"))
			if response.Status() != http.StatusInternalServerError ||
				string(response.Body()) != `{"message":"Something went wrong","code":"UNKNOWN_ERROR"}` {
				t.Fatalf("response = %d %s", response.Status(), response.Body())
			}
		})
	}
}

func TestProviderRequestUsesSharedTimeoutAndParentCancellation(t *testing.T) {
	var sawDeadline atomic.Bool
	doer := doerFunc(func(request *http.Request) (*http.Response, error) {
		deadline, ok := request.Context().Deadline()
		if ok {
			remaining := time.Until(deadline)
			if remaining > 0 && remaining <= VerifyTimeout {
				sawDeadline.Store(true)
			}
		}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	dispatcher := testDispatcher(t, Options{
		Provider: CloudflareTurnstile, SecretKey: "secret",
		Runtime: Runtime{HTTPClient: doer},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	response := dispatchCaptcha(t, dispatcher, ctx, http.MethodPost, "/api/auth/sign-in/email", captchaHeaders("token"))
	if response.Status() != http.StatusInternalServerError || !sawDeadline.Load() {
		t.Fatalf("status=%d sawDeadline=%t", response.Status(), sawDeadline.Load())
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("parent cancellation took %s", elapsed)
	}
}

func TestEveryProviderFailsClosedOnServiceErrorAndCancellation(t *testing.T) {
	providers := []struct {
		name     string
		provider Provider
		siteKey  string
	}{
		{name: "cloudflare-turnstile", provider: CloudflareTurnstile},
		{name: "google-recaptcha", provider: GoogleRecaptcha},
		{name: "hcaptcha", provider: HCaptcha, siteKey: "site"},
		{name: "captchafox", provider: CaptchaFox, siteKey: "site"},
	}
	for _, provider := range providers {
		t.Run(provider.name+"/service-error", func(t *testing.T) {
			response := dispatchCaptcha(t, testDispatcher(t, Options{
				Provider: provider.provider, SecretKey: "secret", SiteKey: provider.siteKey,
				Runtime: Runtime{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
					return jsonProviderResponse(http.StatusServiceUnavailable, `{"success":true}`), nil
				})},
			}), context.Background(), http.MethodPost, "/api/auth/sign-in/email", captchaHeaders("token"))
			if response.Status() != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s", response.Status(), response.Body())
			}
		})

		t.Run(provider.name+"/cancellation", func(t *testing.T) {
			var deadlineSeen atomic.Bool
			dispatcher := testDispatcher(t, Options{
				Provider: provider.provider, SecretKey: "secret", SiteKey: provider.siteKey,
				Runtime: Runtime{HTTPClient: doerFunc(func(request *http.Request) (*http.Response, error) {
					if _, ok := request.Context().Deadline(); ok {
						deadlineSeen.Store(true)
					}
					<-request.Context().Done()
					return nil, request.Context().Err()
				})},
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
			defer cancel()
			response := dispatchCaptcha(t, dispatcher, ctx, http.MethodPost, "/api/auth/sign-in/email", captchaHeaders("token"))
			if response.Status() != http.StatusInternalServerError || !deadlineSeen.Load() {
				t.Fatalf("status=%d deadline=%t", response.Status(), deadlineSeen.Load())
			}
		})
	}
}

func TestUnknownProviderAndDirectInvocationBypassVerification(t *testing.T) {
	var calls atomic.Int64
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return jsonProviderResponse(http.StatusOK, `{"success":false}`), nil
	})
	unknown := testDispatcher(t, Options{
		Provider: Provider("unknown"), SecretKey: "secret", Runtime: Runtime{HTTPClient: doer},
	})
	response := dispatchCaptcha(t, unknown, context.Background(), http.MethodPost, "/api/auth/sign-in/email", captchaHeaders("token"))
	if response.Status() != http.StatusNoContent || calls.Load() != 0 {
		t.Fatalf("unknown provider status=%d calls=%d", response.Status(), calls.Load())
	}

	direct := testDispatcher(t, Options{
		Provider: CloudflareTurnstile, SecretKey: "secret", Runtime: Runtime{HTTPClient: doer},
	})
	response, err := direct.Invoke("captchaPassThrough", engine.DirectInput{
		Request: contract.NewRequest(http.MethodPost, "/sign-in/email", contract.RequestOptions{}),
	})
	if err != nil || response.Status() != http.StatusNoContent || calls.Load() != 0 {
		t.Fatalf("direct response=%d err=%v calls=%d", response.Status(), err, calls.Load())
	}
}

func jsonProviderResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}
