package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

type authFullErrorCodeObservation struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type authFullObservation struct {
	AuthConstructed        bool                          `json:"authConstructed,omitempty"`
	ErrorCode              *authFullErrorCodeObservation `json:"errorCode,omitempty"`
	ResponseMessage        string                        `json:"responseMessage,omitempty"`
	BaseURLs               []string                      `json:"baseURLs,omitempty"`
	OptionsBaseURLs        []string                      `json:"optionsBaseURLs,omitempty"`
	ErrorMessage           string                        `json:"errorMessage,omitempty"`
	TrustedOrigins         []string                      `json:"trustedOrigins,omitempty"`
	CookieDomains          []string                      `json:"cookieDomains,omitempty"`
	InternalAdapterDefined bool                          `json:"internalAdapterDefined,omitempty"`
}

type authFullVector struct {
	Suite       string
	Title       string
	Observation authFullObservation
}

type authFullFixture struct {
	Tests []authFullVector
}

func TestFullAuthScenarios(t *testing.T) {
	fixture := loadAuthFullFixture(t)
	cases := authFullCases()
	for _, vector := range fixture.Tests {
		vector := vector
		t.Run(vector.Suite+"/"+vector.Title, func(t *testing.T) {
			action, exists := cases[authFullCaseKey(vector.Suite, vector.Title)]
			if !exists {
				t.Fatalf("unhandled full-auth scenario %q / %q", vector.Suite, vector.Title)
			}
			actual := action(t)
			if !reflect.DeepEqual(actual, vector.Observation) {
				t.Fatalf("auth/full observation mismatch\nactual: %#v\nwant:   %#v", actual, vector.Observation)
			}
		})
	}
}

func authFullCases() map[string]func(*testing.T) authFullObservation {
	const typeSuite = "auth type"
	const proxySuite = "auth with trusted proxy headers"
	const dynamicSuite = "auth with dynamic baseURL (allowedHosts)"
	return map[string]func(*testing.T) authFullObservation{
		authFullCaseKey(typeSuite, "default auth type should be okay"): func(t *testing.T) authFullObservation {
			clearAuthFullBaseURLEnvironment(t)
			auth, err := New(Options{})
			return authFullObservation{AuthConstructed: err == nil && auth != nil && auth.Registry() != nil}
		},
		authFullCaseKey(typeSuite, "$ERROR_CODES in auth"): func(t *testing.T) authFullObservation {
			clearAuthFullBaseURLEnvironment(t)
			auth := MustNew(Options{Plugins: []engine.Plugin{{
				ID: "custom-plugin",
				ErrorCodes: map[string]engine.ErrorDefinition{
					"CUSTOM_ERROR": {Message: "Custom error message"},
				},
			}}})
			definition := auth.ErrorCodes()["CUSTOM_ERROR"]
			return authFullObservation{ErrorCode: &authFullErrorCodeObservation{
				Code: definition.Code, Message: definition.Message,
			}}
		},
		authFullCaseKey(typeSuite, "plugin endpoints"): func(t *testing.T) authFullObservation {
			auth := MustNew(Options{
				BaseURL: "http://localhost:3000",
				Plugins: []engine.Plugin{{
					ID: "custom-plugin",
					Endpoints: []engine.Endpoint{{
						Name: "getSession", Path: "/get-session", Methods: []string{http.MethodGet}, Override: true,
						Handler: func(*engine.Context) (contract.Response, error) {
							return jsonResponse(contract.StatusOK, map[string]any{
								"data": map[string]any{"message": "Hello, World!"},
							})
						},
					}},
				}},
			})
			response, err := auth.Invoke("getSession", engine.DirectInput{
				Request: authFullRequest("localhost:3000", "", "", "/get-session"),
			})
			if err != nil {
				t.Fatal(err)
			}
			var body struct {
				Data struct {
					Message string `json:"message"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body(), &body); err != nil {
				t.Fatal(err)
			}
			return authFullObservation{ResponseMessage: body.Data.Message}
		},
		authFullCaseKey(proxySuite, "shouldn't infer base url from proxy headers if trusted"): func(t *testing.T) authFullObservation {
			return runAuthFullProxyCase(t, true)
		},
		authFullCaseKey(proxySuite, "shouldn't infer base url from proxy headers if not trusted"): func(t *testing.T) authFullObservation {
			return runAuthFullProxyCase(t, false)
		},
		authFullCaseKey(dynamicSuite, "should throw error for empty allowedHosts array"): func(t *testing.T) authFullObservation {
			clearAuthFullBaseURLEnvironment(t)
			_, err := New(Options{DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{}}})
			if err == nil {
				t.Fatal("empty allowedHosts unexpectedly accepted")
			}
			return authFullObservation{ErrorMessage: err.Error()}
		},
		authFullCaseKey(dynamicSuite, "should resolve baseURL from allowed host"):                              runAuthFullAllowedHostCase,
		authFullCaseKey(dynamicSuite, "should reject disallowed host and throw error"):                         runAuthFullRejectedHostCase,
		authFullCaseKey(dynamicSuite, "should use fallback for disallowed host"):                               runAuthFullFallbackCase,
		authFullCaseKey(dynamicSuite, "should respect protocol config"):                                        runAuthFullProtocolCase,
		authFullCaseKey(dynamicSuite, "should work with wildcard patterns for Vercel deployments"):             runAuthFullWildcardCase,
		authFullCaseKey(dynamicSuite, "should isolate per-request context for concurrent requests"):            runAuthFullConcurrentCase,
		authFullCaseKey(dynamicSuite, "should include all allowedHosts in trustedOrigins"):                     runAuthFullTrustedOriginsCase,
		authFullCaseKey(dynamicSuite, "should set cookie domain dynamically with crossSubDomainCookies"):       runAuthFullCookieDomainCase,
		authFullCaseKey(dynamicSuite, "create a auth context per request which contains the internal adapter"): runAuthFullInternalAdapterCase,
	}
}

func authFullCaseKey(suite, title string) string { return suite + "\x00" + title }

func runAuthFullProxyCase(t *testing.T, trusted bool) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var captured []string
	auth := MustNew(Options{
		Advanced: AdvancedOptions{TrustedProxyHeaders: authFullBool(trusted)},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			captured = append(captured, snapshot.BaseURL)
		}),
	})
	authFullDispatchOK(t, auth, authFullRequest("localhost:3000", "localhost:3001", "http", "/api/auth/ok"))
	return authFullObservation{BaseURLs: captured}
}

func runAuthFullAllowedHostCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var baseURLs, optionsBaseURLs []string
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"myapp.com", "*.vercel.app", "localhost:*"}},
		Advanced:       AdvancedOptions{TrustedProxyHeaders: authFullBool(true)},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			baseURLs = append(baseURLs, snapshot.BaseURL)
			optionsBaseURLs = append(optionsBaseURLs, snapshot.Options.BaseURL)
		}),
	})
	authFullDispatchOK(t, auth, authFullRequest("localhost:3000", "preview-123.vercel.app", "https", "/api/auth/ok"))
	return authFullObservation{BaseURLs: baseURLs, OptionsBaseURLs: optionsBaseURLs}
}

func runAuthFullRejectedHostCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"myapp.com"}},
		Advanced:       AdvancedOptions{TrustedProxyHeaders: authFullBool(true)},
	})
	_, err := auth.Dispatch(authFullRequest("localhost:3000", "evil.com", "https", "/api/auth/ok"))
	if err == nil {
		t.Fatal("disallowed host unexpectedly accepted")
	}
	return authFullObservation{ErrorMessage: err.Error()}
}

func runAuthFullFallbackCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var baseURLs []string
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{
			AllowedHosts: []string{"myapp.com"}, Fallback: "https://myapp.com",
		},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			baseURLs = append(baseURLs, snapshot.BaseURL)
		}),
	})
	authFullDispatchOK(t, auth, authFullRequest("localhost:3000", "evil.com", "https", "/api/auth/ok"))
	return authFullObservation{BaseURLs: baseURLs}
}

func runAuthFullProtocolCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var baseURLs []string
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"myapp.com"}, Protocol: "https"},
		Advanced:       AdvancedOptions{TrustedProxyHeaders: authFullBool(true)},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			baseURLs = append(baseURLs, snapshot.BaseURL)
		}),
	})
	authFullDispatchOK(t, auth, authFullRequest("localhost:3000", "myapp.com", "http", "/api/auth/ok"))
	return authFullObservation{BaseURLs: baseURLs}
}

func runAuthFullWildcardCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var baseURLs []string
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{
			"myapp.com", "www.myapp.com", "*.vercel.app", "preview-*.myapp.com",
		}},
		Advanced: AdvancedOptions{TrustedProxyHeaders: authFullBool(true)},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			baseURLs = append(baseURLs, snapshot.BaseURL)
		}),
	})
	for _, host := range []string{"my-app-abc123-team.vercel.app", "preview-feature-branch.myapp.com"} {
		authFullDispatchOK(t, auth, authFullRequest("localhost:3000", host, "https", "/api/auth/ok"))
	}
	return authFullObservation{BaseURLs: baseURLs}
}

func runAuthFullConcurrentCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var mutex sync.Mutex
	var baseURLs []string
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"tenant-a.example.com", "tenant-b.example.com"}},
		Advanced:       AdvancedOptions{TrustedProxyHeaders: authFullBool(true)},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			mutex.Lock()
			baseURLs = append(baseURLs, snapshot.BaseURL)
			mutex.Unlock()
		}),
	})
	var group sync.WaitGroup
	errors := make(chan error, 2)
	for _, host := range []string{"tenant-a.example.com", "tenant-b.example.com"} {
		host := host
		group.Add(1)
		go func() {
			defer group.Done()
			response, err := auth.Dispatch(authFullRequest("localhost:3000", host, "https", "/api/auth/ok"))
			if err != nil {
				errors <- err
				return
			}
			if response.Status() != contract.StatusOK {
				errors <- fmt.Errorf("host %s status %d", host, response.Status())
			}
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(baseURLs)
	return authFullObservation{BaseURLs: baseURLs}
}

func runAuthFullTrustedOriginsCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var trustedOrigins []string
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{
			AllowedHosts: []string{"myapp.com", "*.vercel.app", "localhost:3000"},
			Fallback:     "https://fallback.example.com",
		},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			trustedOrigins = append([]string(nil), snapshot.TrustedOrigins...)
		}),
	})
	authFullDispatchOK(t, auth, authFullRequest("localhost:3000", "myapp.com", "https", "/api/auth/ok"))
	return authFullObservation{TrustedOrigins: trustedOrigins}
}

func runAuthFullCookieDomainCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var domains []string
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{
			AllowedHosts: []string{"auth.example1.com", "auth.example2.com"}, Protocol: "https",
		},
		Advanced: AdvancedOptions{
			CrossSubDomainCookies: CrossSubDomainCookieOptions{Enabled: true},
			TrustedProxyHeaders:   authFullBool(true),
		},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			domains = append(domains, snapshot.AuthCookies.SessionToken.Attributes.Domain)
		}),
	})
	for _, host := range []string{"auth.example1.com", "auth.example2.com"} {
		authFullDispatchOK(t, auth, authFullRequest("localhost:3000", host, "https", "/api/auth/ok"))
	}
	return authFullObservation{CookieDomains: domains}
}

func runAuthFullInternalAdapterCase(t *testing.T) authFullObservation {
	clearAuthFullBaseURLEnvironment(t)
	var baseURLs, optionsBaseURLs []string
	internalAdapterDefined := false
	endpoint := engine.Endpoint{
		Name: "validateContext", Path: "/validate-context", Methods: []string{http.MethodGet},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			snapshot, exists := RequestContextFromEndpoint(ctx)
			internalAdapterDefined = exists && snapshot.InternalAdapter.valid()
			return jsonResponse(contract.StatusOK, map[string]any{"message": "Hello, World!"})
		},
	}
	auth := MustNew(Options{
		DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"myapp.com", "*.vercel.app", "localhost:*"}},
		Advanced:       AdvancedOptions{TrustedProxyHeaders: authFullBool(true)},
		Hooks: authFullCaptureHooks(func(snapshot RequestAuthContext) {
			baseURLs = append(baseURLs, snapshot.BaseURL)
			optionsBaseURLs = append(optionsBaseURLs, snapshot.Options.BaseURL)
		}),
		Plugins: []engine.Plugin{{ID: "custom-plugin", Endpoints: []engine.Endpoint{endpoint}}},
	})
	authFullDispatchOK(t, auth, authFullRequest("localhost:3000", "preview-123.vercel.app", "https", "/api/auth/validate-context"))
	return authFullObservation{
		BaseURLs: baseURLs, OptionsBaseURLs: optionsBaseURLs,
		InternalAdapterDefined: internalAdapterDefined,
	}
}

func authFullCaptureHooks(capture func(RequestAuthContext)) engine.Hooks {
	return engine.Hooks{Before: []engine.BeforeHook{{
		Name: "auth-full-context-capture",
		Handler: func(ctx *engine.Context) (*contract.Response, error) {
			snapshot, exists := RequestContextFromEndpoint(ctx)
			if !exists {
				return nil, fmt.Errorf("request auth context is missing")
			}
			capture(snapshot)
			return nil, nil
		},
	}}}
}

func authFullDispatchOK(t *testing.T, auth *Auth, request contract.Request) {
	t.Helper()
	response, err := auth.Dispatch(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status() != contract.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Status(), response.Body())
	}
}

func authFullRequest(host, forwardedHost, forwardedProto, path string) contract.Request {
	headers := contract.NewHeaders()
	if forwardedHost != "" {
		headers.Set("X-Forwarded-Host", forwardedHost)
	}
	if forwardedProto != "" {
		headers.Set("X-Forwarded-Proto", forwardedProto)
	}
	return contract.NewRequest(http.MethodGet, path, contract.RequestOptions{
		Scheme: "http", Host: host, Headers: headers,
	})
}

func clearAuthFullBaseURLEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"SINGLE_AUTH_URL", "NEXT_PUBLIC_SINGLE_AUTH_URL", "PUBLIC_SINGLE_AUTH_URL",
		"NUXT_PUBLIC_SINGLE_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL",
		"SINGLE_AUTH_TRUSTED_ORIGINS",
	} {
		t.Setenv(name, "")
	}
}

func authFullBool(value bool) *bool { return &value }

func loadAuthFullFixture(t *testing.T) authFullFixture {
	t.Helper()
	const typeSuite = "auth type"
	const proxySuite = "auth with trusted proxy headers"
	const dynamicSuite = "auth with dynamic baseURL (allowedHosts)"
	fixture := authFullFixture{Tests: []authFullVector{
		{Suite: typeSuite, Title: "$ERROR_CODES in auth", Observation: authFullObservation{
			ErrorCode: &authFullErrorCodeObservation{Code: "CUSTOM_ERROR", Message: "Custom error message"},
		}},
		{Suite: typeSuite, Title: "default auth type should be okay", Observation: authFullObservation{AuthConstructed: true}},
		{Suite: typeSuite, Title: "plugin endpoints", Observation: authFullObservation{ResponseMessage: "Hello, World!"}},
		{Suite: dynamicSuite, Title: "create a auth context per request which contains the internal adapter", Observation: authFullObservation{
			BaseURLs:               []string{"https://preview-123.vercel.app/api/auth"},
			OptionsBaseURLs:        []string{"https://preview-123.vercel.app"},
			InternalAdapterDefined: true,
		}},
		{Suite: dynamicSuite, Title: "should include all allowedHosts in trustedOrigins", Observation: authFullObservation{
			TrustedOrigins: []string{
				"https://myapp.com", "https://*.vercel.app", "https://localhost:3000",
				"http://localhost:3000", "https://fallback.example.com",
			},
		}},
		{Suite: dynamicSuite, Title: "should isolate per-request context for concurrent requests", Observation: authFullObservation{
			BaseURLs: []string{"https://tenant-a.example.com/api/auth", "https://tenant-b.example.com/api/auth"},
		}},
		{Suite: dynamicSuite, Title: "should reject disallowed host and throw error", Observation: authFullObservation{
			ErrorMessage: "Host \"evil.com\" is not in the allowed hosts list. Allowed hosts: myapp.com. Add this host to your allowedHosts config or provide a fallback URL.",
		}},
		{Suite: dynamicSuite, Title: "should resolve baseURL from allowed host", Observation: authFullObservation{
			BaseURLs:        []string{"https://preview-123.vercel.app/api/auth"},
			OptionsBaseURLs: []string{"https://preview-123.vercel.app"},
		}},
		{Suite: dynamicSuite, Title: "should respect protocol config", Observation: authFullObservation{
			BaseURLs: []string{"https://myapp.com/api/auth"},
		}},
		{Suite: dynamicSuite, Title: "should set cookie domain dynamically with crossSubDomainCookies", Observation: authFullObservation{
			CookieDomains: []string{"auth.example1.com", "auth.example2.com"},
		}},
		{Suite: dynamicSuite, Title: "should throw error for empty allowedHosts array", Observation: authFullObservation{
			ErrorMessage: "baseURL.allowedHosts cannot be empty",
		}},
		{Suite: dynamicSuite, Title: "should use fallback for disallowed host", Observation: authFullObservation{
			BaseURLs: []string{"https://myapp.com/api/auth"},
		}},
		{Suite: dynamicSuite, Title: "should work with wildcard patterns for Vercel deployments", Observation: authFullObservation{
			BaseURLs: []string{
				"https://my-app-abc123-team.vercel.app/api/auth",
				"https://preview-feature-branch.myapp.com/api/auth",
			},
		}},
		{Suite: proxySuite, Title: "shouldn't infer base url from proxy headers if not trusted", Observation: authFullObservation{
			BaseURLs: []string{"http://localhost:3000/api/auth"},
		}},
		{Suite: proxySuite, Title: "shouldn't infer base url from proxy headers if trusted", Observation: authFullObservation{
			BaseURLs: []string{"http://localhost:3001/api/auth"},
		}},
	}}
	if len(fixture.Tests) != 15 {
		t.Fatalf("full-auth scenarios=%d, want 15", len(fixture.Tests))
	}
	caseMap := authFullCases()
	seen := make(map[string]struct{}, 15)
	for index, vector := range fixture.Tests {
		if vector.Suite == "" || vector.Title == "" {
			t.Fatalf("invalid full-auth scenario %d: suite=%q title=%q", index, vector.Suite, vector.Title)
		}
		key := authFullCaseKey(vector.Suite, vector.Title)
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("duplicate full-auth scenario %q / %q", vector.Suite, vector.Title)
		}
		seen[key] = struct{}{}
		if _, exists := caseMap[key]; !exists {
			t.Fatalf("fixture lacks Go scenario %q / %q", vector.Suite, vector.Title)
		}
	}
	if len(caseMap) != len(seen) {
		t.Fatalf("Go scenario inventory = %d, fixture inventory = %d", len(caseMap), len(seen))
	}
	return fixture
}
