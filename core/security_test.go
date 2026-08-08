package core

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func securityBool(value bool) *bool { return &value }

func securityProbeEndpoint(name, path string) engine.Endpoint {
	return engine.Endpoint{
		Name: name, Path: path, Methods: []string{http.MethodPost},
		Handler: func(*engine.Context) (contract.Response, error) {
			return jsonResponse(contract.StatusOK, map[string]any{"ok": true})
		},
	}
}

func dispatchSecurityRequest(
	t *testing.T,
	auth *Auth,
	method, target string,
	body []byte,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	auth.ServeHTTP(recorder, request)
	return recorder
}

func TestStaticBaseURLDoesNotTrustAttackerControlledHost(t *testing.T) {
	auth := MustNew(Options{
		BaseURL: "https://auth.example",
		Endpoints: []engine.Endpoint{
			securityProbeEndpoint("securityProbe", "/security-probe"),
		},
	})

	blocked := dispatchSecurityRequest(t, auth, http.MethodPost,
		"https://evil.example/api/auth/security-probe", []byte(`{}`), map[string]string{
			"Cookie": "session=fake", "Origin": "https://evil.example",
		})
	if blocked.Code != contract.StatusForbidden || !bytes.Contains(blocked.Body.Bytes(), []byte(ErrorInvalidOrigin)) {
		t.Fatalf("attacker-controlled host response = %d %s", blocked.Code, blocked.Body.String())
	}

	allowed := dispatchSecurityRequest(t, auth, http.MethodPost,
		"https://evil.example/api/auth/security-probe", []byte(`{}`), map[string]string{
			"Cookie": "session=fake", "Origin": "https://auth.example",
		})
	if allowed.Code != contract.StatusOK {
		t.Fatalf("configured origin response = %d %s", allowed.Code, allowed.Body.String())
	}
}

func TestOriginValidationSkipsSafeMethodsButEndpointUseStillProtectsRedirect(t *testing.T) {
	auth := MustNew(Options{
		BaseURL:        "https://auth.example",
		TrustedOrigins: []string{"https://app.example"},
	})

	globalSafe := dispatchSecurityRequest(t, auth, http.MethodGet,
		"https://auth.example/api/auth/ok?callbackURL=https://evil.example", nil, nil)
	if globalSafe.Code != contract.StatusOK {
		t.Fatalf("safe global request = %d %s", globalSafe.Code, globalSafe.Body.String())
	}

	protected := dispatchSecurityRequest(t, auth, http.MethodGet,
		"https://auth.example/api/auth/verify-email?token=bad&callbackURL=https://evil.example", nil, nil)
	if protected.Code != contract.StatusForbidden || !bytes.Contains(protected.Body.Bytes(), []byte(ErrorInvalidCallbackURL)) {
		t.Fatalf("endpoint redirect validation = %d %s", protected.Code, protected.Body.String())
	}
}

func TestOriginCheckRejectsNonStringRedirectInputs(t *testing.T) {
	auth := MustNew(Options{
		BaseURL: "http://localhost:3000",
		Endpoints: []engine.Endpoint{
			securityProbeEndpoint("redirectProbe", "/redirect-probe"),
		},
	})

	object := dispatchSecurityRequest(t, auth, http.MethodPost,
		"http://localhost:3000/api/auth/redirect-probe", []byte(`{"callbackURL":{"nested":true}}`), nil)
	if object.Code != contract.StatusBadRequest || !bytes.Contains(object.Body.Bytes(), []byte("Invalid callbackURL: expected a string")) {
		t.Fatalf("object callback = %d %s", object.Code, object.Body.String())
	}

	duplicate := dispatchSecurityRequest(t, auth, http.MethodPost,
		"http://localhost:3000/api/auth/redirect-probe?callbackURL=/a&callbackURL=/b", []byte(`{}`), nil)
	if duplicate.Code != contract.StatusBadRequest || !bytes.Contains(duplicate.Body.Bytes(), []byte("Invalid callbackURL: expected a string")) {
		t.Fatalf("duplicate callback = %d %s", duplicate.Code, duplicate.Body.String())
	}

	redirectObject := dispatchSecurityRequest(t, auth, http.MethodPost,
		"http://localhost:3000/api/auth/redirect-probe", []byte(`{"redirectTo":{"nested":true}}`), nil)
	if redirectObject.Code != contract.StatusBadRequest || !bytes.Contains(redirectObject.Body.Bytes(), []byte("Invalid redirectURL: expected a string")) {
		t.Fatalf("object redirect = %d %s", redirectObject.Code, redirectObject.Body.String())
	}
}

func TestSkipOriginCheckPathsUsesSlashBoundaries(t *testing.T) {
	auth := MustNew(Options{
		BaseURL: "https://auth.example",
		Advanced: AdvancedOptions{
			SkipOriginCheckPaths: []string{"/public/data/"},
		},
		Endpoints: []engine.Endpoint{
			securityProbeEndpoint("publicData", "/public/data"),
			securityProbeEndpoint("publicDataChild", "/public/data/child"),
			securityProbeEndpoint("publicDatabase", "/public/database"),
		},
	})
	body := []byte(`{"callbackURL":"https://evil.example"}`)
	for _, path := range []string{"/public/data", "/public/data/child"} {
		response := dispatchSecurityRequest(t, auth, http.MethodPost,
			"https://auth.example/api/auth"+path, body, map[string]string{
				"Cookie": "x=1", "Origin": "https://evil.example",
			})
		if response.Code != contract.StatusOK {
			t.Fatalf("skipped path %s = %d %s", path, response.Code, response.Body.String())
		}
	}
	sibling := dispatchSecurityRequest(t, auth, http.MethodPost,
		"https://auth.example/api/auth/public/database", body, nil)
	if sibling.Code != contract.StatusForbidden || !bytes.Contains(sibling.Body.Bytes(), []byte(ErrorInvalidCallbackURL)) {
		t.Fatalf("prefix sibling = %d %s", sibling.Code, sibling.Body.String())
	}
}

func TestDisableCSRFAndOriginOptionsAreIndependent(t *testing.T) {
	csrfDisabled := MustNew(Options{
		BaseURL: "https://auth.example",
		Advanced: AdvancedOptions{
			DisableCSRFCheck:   securityBool(true),
			DisableOriginCheck: securityBool(false),
		},
		Endpoints: []engine.Endpoint{securityProbeEndpoint("csrfDisabled", "/csrf-disabled")},
	})
	allowedHeader := dispatchSecurityRequest(t, csrfDisabled, http.MethodPost,
		"https://auth.example/api/auth/csrf-disabled", []byte(`{"callbackURL":"/dashboard"}`), map[string]string{
			"Cookie": "x=1", "Origin": "https://evil.example",
		})
	if allowedHeader.Code != contract.StatusOK {
		t.Fatalf("disabled CSRF response = %d %s", allowedHeader.Code, allowedHeader.Body.String())
	}
	blockedRedirect := dispatchSecurityRequest(t, csrfDisabled, http.MethodPost,
		"https://auth.example/api/auth/csrf-disabled", []byte(`{"callbackURL":"https://evil.example"}`), nil)
	if blockedRedirect.Code != contract.StatusForbidden {
		t.Fatalf("origin validation with CSRF disabled = %d %s", blockedRedirect.Code, blockedRedirect.Body.String())
	}

	originDisabled := MustNew(Options{
		BaseURL: "https://auth.example",
		Advanced: AdvancedOptions{
			DisableCSRFCheck:   securityBool(false),
			DisableOriginCheck: securityBool(true),
		},
		Endpoints: []engine.Endpoint{securityProbeEndpoint("originDisabled", "/origin-disabled")},
	})
	allAllowed := dispatchSecurityRequest(t, originDisabled, http.MethodPost,
		"https://auth.example/api/auth/origin-disabled", []byte(`{"callbackURL":"https://evil.example"}`), map[string]string{
			"Cookie": "x=1", "Origin": "https://evil.example",
		})
	if allAllowed.Code != contract.StatusOK {
		t.Fatalf("disabled origin response = %d %s", allAllowed.Code, allAllowed.Body.String())
	}
}

func TestDynamicBaseURLResolutionAndAllAllowedHostsAreTrusted(t *testing.T) {
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{
			AllowedHosts: []string{"tenant-a.example.com", "tenant-b.example.com", "localhost:*"},
			Protocol:     "auto",
		},
		Endpoints: []engine.Endpoint{securityProbeEndpoint("dynamicProbe", "/dynamic-probe")},
	})

	request := contract.NewRequest(http.MethodGet, "/api/auth/ok", contract.RequestOptions{
		Scheme: "http", Host: "localhost:3000",
		Headers: contract.NewHeaders(
			contract.HeaderField{Name: "X-Forwarded-Host", Value: "tenant-a.example.com"},
			contract.HeaderField{Name: "X-Forwarded-Proto", Value: "https"},
		),
	})
	resolved, err := auth.ResolveBaseURL(request)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "https://tenant-a.example.com/api/auth" {
		t.Fatalf("resolved base URL = %q", resolved)
	}

	// upstream implementation trusts every allowed host, not just the host selected for this
	// request. This is important for multi-tenant callback redirects.
	response := dispatchSecurityRequest(t, auth, http.MethodPost,
		"http://localhost:3000/api/auth/dynamic-probe", []byte(`{"callbackURL":"https://tenant-b.example.com/dashboard"}`), map[string]string{
			"X-Forwarded-Host":  "tenant-a.example.com",
			"X-Forwarded-Proto": "https",
		})
	if response.Code != contract.StatusOK {
		t.Fatalf("allowed tenant redirect = %d %s", response.Code, response.Body.String())
	}
}

func TestDynamicBaseURLProxyTrustAndFallback(t *testing.T) {
	withoutProxy := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"example.com"}},
		Advanced:       AdvancedOptions{TrustedProxyHeaders: securityBool(false)},
	})
	request := contract.NewRequest(http.MethodGet, "/api/auth/ok", contract.RequestOptions{
		Scheme: "http", Host: "localhost:3000",
		Headers: contract.NewHeaders(contract.HeaderField{Name: "X-Forwarded-Host", Value: "example.com"}),
	})
	if _, err := withoutProxy.ResolveBaseURL(request); err == nil {
		t.Fatal("untrusted forwarded host unexpectedly resolved")
	}

	withFallback := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{
			AllowedHosts: []string{"example.com"}, Fallback: "https://fallback.example/custom/auth",
		},
	})
	disallowedRequest := request.WithHeader("X-Forwarded-Host", "evil.example")
	resolved, err := withFallback.ResolveBaseURL(disallowedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != "https://fallback.example/custom/auth" {
		t.Fatalf("fallback = %q", resolved)
	}
}

func TestDynamicTrustedOriginResolverIsRequestScoped(t *testing.T) {
	auth := MustNew(Options{
		BaseURL: "https://auth.example",
		ResolveTrustedOrigins: func(_ context.Context, request contract.Request) ([]string, error) {
			tenant, _ := request.Headers().Get("X-Tenant")
			return []string{"https://" + tenant + ".example"}, nil
		},
		Endpoints: []engine.Endpoint{securityProbeEndpoint("tenantProbe", "/tenant-probe")},
	})

	type outcome struct {
		tenant string
		code   int
	}
	results := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, tenant := range []string{"a", "b"} {
		tenant := tenant
		go func() {
			start.Wait()
			origin := "https://" + tenant + ".example"
			if tenant == "a" {
				origin = "https://b.example"
			}
			response := dispatchSecurityRequest(t, auth, http.MethodPost,
				"https://auth.example/api/auth/tenant-probe", []byte(`{}`), map[string]string{
					"Cookie": "x=1", "Origin": origin, "X-Tenant": tenant,
				})
			results <- outcome{tenant: tenant, code: response.Code}
		}()
	}
	start.Done()
	got := make(map[string]int)
	for range 2 {
		result := <-results
		got[result.tenant] = result.code
	}
	if got["a"] != contract.StatusForbidden || got["b"] != contract.StatusOK {
		t.Fatalf("request-scoped outcomes = %#v", got)
	}
}

func TestTrustedOriginsEnvironmentAndResolverFailure(t *testing.T) {
	t.Setenv("SINGLE_AUTH_TRUSTED_ORIGINS", "https://env.example")
	auth := MustNew(Options{
		BaseURL:   "https://auth.example",
		Endpoints: []engine.Endpoint{securityProbeEndpoint("envProbe", "/env-probe")},
	})
	response := dispatchSecurityRequest(t, auth, http.MethodPost,
		"https://auth.example/api/auth/env-probe", []byte(`{}`), map[string]string{
			"Cookie": "x=1", "Origin": "https://env.example",
		})
	if response.Code != contract.StatusOK {
		t.Fatalf("environment origin = %d %s", response.Code, response.Body.String())
	}

	failing := MustNew(Options{
		BaseURL: "https://auth.example",
		ResolveTrustedOrigins: func(context.Context, contract.Request) ([]string, error) {
			return nil, errors.New("resolver failed")
		},
		Endpoints: []engine.Endpoint{securityProbeEndpoint("failingResolver", "/failing-resolver")},
	})
	failure := dispatchSecurityRequest(t, failing, http.MethodPost,
		"https://auth.example/api/auth/failing-resolver", []byte(`{}`), map[string]string{
			"Cookie": "x=1", "Origin": "https://auth.example",
		})
	if failure.Code != contract.StatusInternalServerError {
		t.Fatalf("resolver failure = %d %s", failure.Code, failure.Body.String())
	}
}

func TestDynamicTrustedOriginExpansion(t *testing.T) {
	tests := []struct {
		name     string
		config   DynamicBaseURLOptions
		expected []string
	}{
		{
			name: "http", config: DynamicBaseURLOptions{
				AllowedHosts: []string{"staging.example.com", "dev.example.local"},
				Protocol:     "http", Fallback: "https://app.example.com",
			},
			expected: []string{"http://staging.example.com", "http://dev.example.local", "https://app.example.com"},
		},
		{
			name: "https with loopback", config: DynamicBaseURLOptions{
				AllowedHosts: []string{"staging.example.com", "localhost:3000", "127.0.0.1:8080"},
				Protocol:     "https",
			},
			expected: []string{
				"https://staging.example.com",
				"https://localhost:3000", "http://localhost:3000",
				"https://127.0.0.1:8080", "http://127.0.0.1:8080",
			},
		},
		{
			name: "auto and explicit", config: DynamicBaseURLOptions{
				AllowedHosts: []string{"staging.example.com", "http://specified.example.com"},
				Protocol:     "auto",
			},
			expected: []string{"https://staging.example.com", "http://staging.example.com", "http://specified.example.com"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := dynamicTrustedOrigins(test.config)
			sort.Strings(got)
			want := append([]string(nil), test.expected...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("origins = %#v, want %#v", got, want)
			}
		})
	}
}

func TestMatchesOriginPatternBehavior(t *testing.T) {
	tests := []struct {
		name          string
		candidate     string
		pattern       string
		allowRelative bool
		want          bool
	}{
		{"exact", "https://trusted.com/path", "https://trusted.com", false, true},
		{"malicious prefix", "https://trusted.com.evil.example", "https://trusted.com", false, false},
		{"host wildcard", "https://sub.my-site.com/callback", "*.my-site.com", false, true},
		{"protocol wildcard", "https://api.protocol-site.com", "https://*.protocol-site.com", false, true},
		{"protocol mismatch", "http://api.protocol-site.com", "https://*.protocol-site.com", false, false},
		{"wildcard query attack", "malicious.com?.example.com", "*.example.com", false, false},
		{"custom scheme", "exp://10.0.0.29:8081/--/", "exp://10.0.0.*:*/*", false, true},
		{"relative", "/dashboard?email=123@email.com", "https://unused.example", true, true},
		{"relative disabled", "/dashboard", "https://unused.example", false, false},
		{"scheme relative", "//evil.example", "https://unused.example", true, false},
		{"encoded slash", "/..%2F..%2Fevil.example", "https://unused.example", true, false},
		{"encoded backslash", "/%5C/evil.example", "https://unused.example", true, false},
		{"literal backslash", `/\\/evil.example`, "https://unused.example", true, false},
		{"javascript", "javascript:alert('xss')", "javascript:", true, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchesOriginPattern(test.candidate, test.pattern, test.allowRelative); got != test.want {
				t.Fatalf("matchesOriginPattern(%q, %q, %v) = %v, want %v", test.candidate, test.pattern, test.allowRelative, got, test.want)
			}
		})
	}
}
