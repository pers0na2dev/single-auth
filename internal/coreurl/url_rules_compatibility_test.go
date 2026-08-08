package coreurl

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestURLResolutionRules(t *testing.T) {
	clearURLRuleEnvironment(t)
	for index, testCase := range urlRuleCases {
		t.Run(fmt.Sprintf("%s/%d", testCase.operation, index), func(t *testing.T) {
			request := requestFromURLRuleSpec(t, testCase.request)
			var actual any
			var err error
			switch testCase.operation {
			case "trimTrailingSlashes":
				actual = TrimTrailingSlashes(testCase.first)
			case "getBaseURL":
				options := GetBaseURLOptions{URL: testCase.first, Request: request, LoadEnvironment: testCase.loadEnvironment, TrustedProxyHeaders: testCase.trusted}
				if testCase.pathSet {
					options.Path = &testCase.path
				}
				actual, err = GetBaseURL(options)
			case "matchesHostPattern":
				actual = MatchesHostPattern(testCase.first, testCase.second)
			case "getHostFromSource":
				actual = GetHostFromSource(*request, testCase.trusted)
			case "getProtocolFromSource":
				actual = GetProtocolFromSource(*request, testCase.first, testCase.trusted)
			case "isDynamicBaseURLConfig":
				actual = IsDynamicBaseURLConfig(testCase.config)
			case "resolveDynamicBaseURL":
				actual, err = ResolveDynamicBaseURL(testCase.config.(DynamicBaseURLConfig), *request, testCase.path, testCase.trusted)
			case "resolveBaseURL":
				actual, err = ResolveBaseURL(testCase.config, testCase.path, request, testCase.loadEnvironment, testCase.trusted)
			default:
				t.Fatalf("unknown URL rule operation %q", testCase.operation)
			}

			if testCase.wantError != "" {
				if err == nil || err.Error() != testCase.wantError {
					t.Fatalf("error = %v, want %q", err, testCase.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if testCase.wantString != nil {
				if got, ok := actual.(string); !ok || got != *testCase.wantString {
					t.Fatalf("result = %#v, want %q", actual, *testCase.wantString)
				}
				return
			}
			if testCase.wantBool != nil {
				if got, ok := actual.(bool); !ok || got != *testCase.wantBool {
					t.Fatalf("result = %#v, want %t", actual, *testCase.wantBool)
				}
				return
			}
			t.Fatal("URL rule case has no expected result")
		})
	}
}

func requestFromURLRuleSpec(t *testing.T, spec *urlRequestSpec) *contract.Request {
	t.Helper()
	if spec == nil {
		return nil
	}
	parsed, err := url.Parse(spec.URL)
	if err != nil {
		t.Fatal(err)
	}
	fields := make([]contract.HeaderField, 0, len(spec.Headers))
	for name, value := range spec.Headers {
		fields = append(fields, contract.HeaderField{Name: name, Value: value})
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	request := contract.NewRequest("GET", path, contract.RequestOptions{
		Scheme: parsed.Scheme, Host: parsed.Host, RawQuery: parsed.RawQuery,
		Headers: contract.NewHeaders(fields...),
	})
	return &request
}

func clearURLRuleEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"SINGLE_AUTH_URL", "NEXT_PUBLIC_SINGLE_AUTH_URL", "PUBLIC_SINGLE_AUTH_URL",
		"NUXT_PUBLIC_SINGLE_AUTH_URL", "NUXT_PUBLIC_AUTH_URL", "BASE_URL",
	} {
		t.Setenv(name, "")
	}
}
