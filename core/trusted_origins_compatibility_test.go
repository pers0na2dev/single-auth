package core

import (
	"context"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	frozenTrustedOriginsTestCount  = 25
	frozenTrustedOriginsCheckCount = 46
)

type trustedOriginsCase struct {
	Name    string
	Setup   trustedOriginsSetup
	Origins []string
	Checks  []trustedOriginsCheck
}

type trustedOriginsSetup struct {
	BaseURL        string
	Inferred       bool
	DynamicBaseURL *DynamicBaseURLOptions
	TrustedOrigins []string
	Resolver       string
}

type trustedOriginsCheck struct {
	URL                string
	AllowRelativePaths bool
	Result             bool
}

type trustedOriginsFixtureFactory struct {
	id     string
	plugin engine.Plugin
}

func (factory trustedOriginsFixtureFactory) PluginID() string { return factory.id }
func (factory trustedOriginsFixtureFactory) Schema() (storage.Schema, error) {
	return storage.Schema{}, nil
}
func (factory trustedOriginsFixtureFactory) Build(PluginHost) (engine.Plugin, error) {
	return factory.plugin, nil
}

func TestTrustedOriginsScenarios(t *testing.T) {
	t.Setenv("SINGLE_AUTH_TRUSTED_ORIGINS", "")
	for _, testCase := range trustedOriginsCases() {
		testCase := testCase
		t.Run(testCase.Name, func(t *testing.T) {
			origins := executeTrustedOriginsCase(t, testCase)
			if !reflect.DeepEqual(origins, testCase.Origins) {
				t.Fatalf("trusted origins = %#v, want %#v", origins, testCase.Origins)
			}
			for index, check := range testCase.Checks {
				allowRelative := check.AllowRelativePaths
				actual := false
				for _, pattern := range origins {
					if matchesOriginPattern(check.URL, pattern, allowRelative) {
						actual = true
						break
					}
				}
				if actual != check.Result {
					t.Fatalf("check %d candidate %q allowRelative=%t = %t, want %t", index, check.URL, allowRelative, actual, check.Result)
				}
			}
		})
	}
}

func executeTrustedOriginsCase(t *testing.T, testCase trustedOriginsCase) []string {
	t.Helper()
	if testCase.Setup.DynamicBaseURL != nil {
		return dynamicTrustedOrigins(*testCase.Setup.DynamicBaseURL)
	}
	options := Options{
		BaseURL:        testCase.Setup.BaseURL,
		TrustedOrigins: append([]string(nil), testCase.Setup.TrustedOrigins...),
	}
	if !testCase.Setup.Inferred && options.BaseURL == "" {
		options.BaseURL = "http://localhost:3000"
	}
	switch testCase.Setup.Resolver {
	case "":
	case "candidate-origin":
		options.ResolveTrustedOrigins = func(_ context.Context, request contract.Request) ([]string, error) {
			query, err := request.Query()
			if err != nil {
				return nil, err
			}
			candidate, err := url.Parse(query.Get("url"))
			if err != nil {
				return nil, err
			}
			return []string{candidate.Scheme + "://" + candidate.Host}, nil
		}
	case "empty":
		options.ResolveTrustedOrigins = func(context.Context, contract.Request) ([]string, error) {
			return nil, nil
		}
	case "plugin-merge":
		options.ResolveTrustedOrigins = func(context.Context, contract.Request) ([]string, error) {
			return []string{"https://user-dynamic.com"}, nil
		}
		options.PluginFactories = []PluginFactory{
			trustedOriginsFixtureFactory{
				id: "plugin-a",
				plugin: engine.Plugin{
					ID: "plugin-a", TrustedOrigins: []string{"https://plugin-static.com"},
				},
			},
			trustedOriginsFixtureFactory{
				id: "plugin-b",
				plugin: engine.Plugin{
					ID: "plugin-b",
					ResolveTrustedOrigins: func(context.Context, contract.Request) ([]string, error) {
						return []string{"https://plugin-fn.com"}, nil
					},
				},
			},
		}
	default:
		t.Fatalf("unknown trusted-origin resolver scenario %q", testCase.Setup.Resolver)
	}
	auth, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	rawQuery := ""
	if len(testCase.Checks) > 0 {
		rawQuery = "url=" + url.QueryEscape(testCase.Checks[0].URL)
	}
	request := contract.NewRequest(http.MethodGet, "/api/auth/test-trusted-origin", contract.RequestOptions{
		Scheme: "http", Host: "localhost:3000", RawQuery: rawQuery,
	})
	origins, err := auth.trustedOrigins(request)
	if err != nil {
		t.Fatal(err)
	}
	return origins
}

func TestTrustedOriginsScenarioDefinitions(t *testing.T) {
	cases := trustedOriginsCases()
	if len(cases) != frozenTrustedOriginsTestCount {
		t.Fatalf("trusted-origin scenarios=%d, want %d", len(cases), frozenTrustedOriginsTestCount)
	}
	seen := make(map[string]struct{}, len(cases))
	checkCount := 0
	for _, testCase := range cases {
		if testCase.Name == "" {
			t.Fatal("trusted-origin scenario has an empty name")
		}
		if _, exists := seen[testCase.Name]; exists {
			t.Fatalf("duplicate trusted-origin scenario %q", testCase.Name)
		}
		seen[testCase.Name] = struct{}{}
		checkCount += len(testCase.Checks)
		if len(testCase.Checks) == 0 {
			checkCount++
		}
	}
	if checkCount != frozenTrustedOriginsCheckCount {
		t.Fatalf("trusted-origin checks=%d, want %d", checkCount, frozenTrustedOriginsCheckCount)
	}
}

func trustedOriginsCases() []trustedOriginsCase {
	return []trustedOriginsCase{
		{Name: "trusted origins/dynamic baseURL protocol option/should add both http:// and https:// origins when protocol is 'auto'", Setup: trustedOriginsSetup{DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"staging.example.com"}, Protocol: "auto"}}, Origins: []string{"https://staging.example.com", "http://staging.example.com"}, Checks: []trustedOriginsCheck{}},
		{Name: "trusted origins/dynamic baseURL protocol option/should add http:// for loopback hosts even when protocol is 'https'", Setup: trustedOriginsSetup{DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"localhost:3000", "127.0.0.1:8080"}, Protocol: "https"}}, Origins: []string{"https://localhost:3000", "http://localhost:3000", "https://127.0.0.1:8080", "http://127.0.0.1:8080"}, Checks: []trustedOriginsCheck{}},
		{Name: "trusted origins/dynamic baseURL protocol option/should add http:// origins when protocol is 'http'", Setup: trustedOriginsSetup{DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"staging.example.com", "dev.example.local"}, Protocol: "http", Fallback: "https://app.example.com"}}, Origins: []string{"http://staging.example.com", "http://dev.example.local", "https://app.example.com"}, Checks: []trustedOriginsCheck{}},
		{Name: "trusted origins/dynamic baseURL protocol option/should add only https:// origins when protocol is 'https'", Setup: trustedOriginsSetup{DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"staging.example.com", "app.example.com"}, Protocol: "https"}}, Origins: []string{"https://staging.example.com", "https://app.example.com"}, Checks: []trustedOriginsCheck{}},
		{Name: "trusted origins/dynamic baseURL protocol option/should default to https:// with http:// for loopback when protocol is undefined", Setup: trustedOriginsSetup{DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"staging.example.com", "localhost:3000"}}}, Origins: []string{"https://staging.example.com", "https://localhost:3000", "http://localhost:3000"}, Checks: []trustedOriginsCheck{}},
		{Name: "trusted origins/dynamic baseURL protocol option/should still allow hosts with explicit protocol in the host string", Setup: trustedOriginsSetup{DynamicBaseURL: &DynamicBaseURLOptions{AllowedHosts: []string{"http://already-specified.example.com", "staging.example.com"}, Protocol: "http"}}, Origins: []string{"http://already-specified.example.com", "http://staging.example.com"}, Checks: []trustedOriginsCheck{}},
		{Name: "trusted origins/dynamic trusted origins/should allow dynamically computed trusted origins", Setup: trustedOriginsSetup{Resolver: "candidate-origin"}, Origins: []string{"http://localhost:3000", "http://localhost:5000"}, Checks: []trustedOriginsCheck{{URL: "http://localhost:5000/callback", Result: true}}},
		{Name: "trusted origins/dynamic trusted origins/should not allow dynamically computed trusted origins", Setup: trustedOriginsSetup{Resolver: "empty"}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "http://localhost:5000/callback", Result: false}}},
		{Name: "trusted origins/relative paths support/should allow relative paths", Setup: trustedOriginsSetup{}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "/", AllowRelativePaths: true, Result: true}, {URL: "/dashboard", AllowRelativePaths: true, Result: true}}},
		{Name: "trusted origins/relative paths support/should allow relative paths with plus signs", Setup: trustedOriginsSetup{}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "/dashboard+page?test=123+456", AllowRelativePaths: true, Result: true}}},
		{Name: "trusted origins/relative paths support/should allow relative paths with query params", Setup: trustedOriginsSetup{}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "/dashboard?email=123@email.com", AllowRelativePaths: true, Result: true}}},
		{Name: "trusted origins/relative paths support/should reject relative paths by default", Setup: trustedOriginsSetup{}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "/", Result: false}, {URL: "/some-absolute-url", Result: false}}},
		{Name: "trusted origins/relative paths support/should reject urls with double dash", Setup: trustedOriginsSetup{}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "//evil.com", AllowRelativePaths: true, Result: false}}},
		{Name: "trusted origins/relative paths support/should reject urls with encoded malicious content", Setup: trustedOriginsSetup{}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "/%5C/evil.com", AllowRelativePaths: true, Result: false}, {URL: "/\\/\\/evil.com", AllowRelativePaths: true, Result: false}, {URL: "/%5C/evil.com", AllowRelativePaths: true, Result: false}, {URL: "/..%2F..%2Fevil.com", AllowRelativePaths: true, Result: false}, {URL: "javascript:alert('xss')", AllowRelativePaths: true, Result: false}, {URL: "data:text/html,<script>alert('xss')</script>", AllowRelativePaths: true, Result: false}}},
		{Name: "trusted origins/trusted origins list support/should allow origins that directly match a trusted origin", Setup: trustedOriginsSetup{TrustedOrigins: []string{"https://trusted.com"}}, Origins: []string{"http://localhost:3000", "https://trusted.com"}, Checks: []trustedOriginsCheck{{URL: "https://trusted.com", Result: true}, {URL: "https://trusted.com/some/path", Result: true}}},
		{Name: "trusted origins/trusted origins list support/should always allow the app's origin", Setup: trustedOriginsSetup{}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "http://localhost:3000", Result: true}, {URL: "http://localhost:3000/some/path", Result: true}}},
		{Name: "trusted origins/trusted origins list support/should always allow the app's origin (even if context is updated)", Setup: trustedOriginsSetup{Inferred: true}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "http://localhost:3000", Result: true}, {URL: "http://localhost:3000/some/path", Result: true}}},
		{Name: "trusted origins/trusted origins list support/should always allow the app's origin (inferred from baseURL)", Setup: trustedOriginsSetup{Inferred: true}, Origins: []string{"http://localhost:3000"}, Checks: []trustedOriginsCheck{{URL: "http://localhost:3000", Result: true}, {URL: "http://localhost:3000/some/path", Result: true}}},
		{Name: "trusted origins/trusted origins list support/should reject origins that start with a trusted origin", Setup: trustedOriginsSetup{TrustedOrigins: []string{"https://trusted.com"}}, Origins: []string{"http://localhost:3000", "https://trusted.com"}, Checks: []trustedOriginsCheck{{URL: "https://trusted.com.malicious.com", Result: false}}},
		{Name: "trusted origins/trusted origins list support/should reject untrusted origin subdomains", Setup: trustedOriginsSetup{TrustedOrigins: []string{"https://trusted.com"}}, Origins: []string{"http://localhost:3000", "https://trusted.com"}, Checks: []trustedOriginsCheck{{URL: "http://sub-domain.trusted.com", Result: false}}},
		{Name: "trusted origins/wildcards support/should allow origins that match a wildcard trusted origin", Setup: trustedOriginsSetup{TrustedOrigins: []string{"*.my-site.com"}}, Origins: []string{"http://localhost:3000", "*.my-site.com"}, Checks: []trustedOriginsCheck{{URL: "https://sub-domain.my-site.com", Result: true}, {URL: "https://sub-domain.my-site.com/callback", Result: true}, {URL: "https://another-sub.my-site.com", Result: true}, {URL: "https://another-sub.my-site.com/callback", Result: true}}},
		{Name: "trusted origins/wildcards support/should reject urls with malicious domain with wildcard trusted origins", Setup: trustedOriginsSetup{TrustedOrigins: []string{"*.example.com"}}, Origins: []string{"http://localhost:3000", "*.example.com"}, Checks: []trustedOriginsCheck{{URL: "malicious.com?.example.com", Result: false}}},
		{Name: "trusted origins/wildcards support/should work with custom scheme wildcards", Setup: trustedOriginsSetup{TrustedOrigins: []string{"exp://10.0.0.*:*/*", "exp://192.168.*.*:*/*", "exp://172.*.*.*:*/*"}}, Origins: []string{"http://localhost:3000", "exp://10.0.0.*:*/*", "exp://192.168.*.*:*/*", "exp://172.*.*.*:*/*"}, Checks: []trustedOriginsCheck{{URL: "exp://10.0.0.29:8081/--/", Result: true}, {URL: "exp://192.168.1.100:8081/--/", Result: true}, {URL: "exp://172.16.0.1:8081/--/", Result: true}, {URL: "exp://203.0.113.0:8081/--/", Result: false}}},
		{Name: "trusted origins/wildcards support/should work with protocol-specific wildcard trusted origins", Setup: trustedOriginsSetup{TrustedOrigins: []string{"https://*.protocol-site.com"}}, Origins: []string{"http://localhost:3000", "https://*.protocol-site.com"}, Checks: []trustedOriginsCheck{{URL: "https://api.protocol-site.com", Result: true}, {URL: "http://api.protocol-site.com", Result: false}}},
		{Name: "trusted origins/should merge plugin and user-configured origins", Setup: trustedOriginsSetup{Resolver: "plugin-merge"}, Origins: []string{"http://localhost:3000", "https://plugin-static.com", "https://user-dynamic.com", "https://plugin-fn.com"}, Checks: []trustedOriginsCheck{{URL: "https://user-dynamic.com", Result: true}, {URL: "https://plugin-static.com", Result: true}, {URL: "https://plugin-fn.com", Result: true}, {URL: "https://unknown.com", Result: false}}},
	}
}
