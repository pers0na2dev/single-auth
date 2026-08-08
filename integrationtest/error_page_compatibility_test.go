package singleauth_test

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	singleauth "github.com/pers0na2dev/single-auth"
)

type errorPageCase struct {
	Suite       string
	Title       string
	Observation errorPageObservation
}

type errorPageObservation struct {
	ContainsRawScript     bool `json:"containsRawScript"`
	ContainsEscapedScript bool `json:"containsEscapedScript"`
	ContainsUnknown       bool `json:"containsUnknown"`
}

func TestErrorPageHTTPBehavior(t *testing.T) {
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000",
		Secret:  "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range errorPageCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			target := errorPageTarget(t, vector.Title)
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				exchange := newSignOutExchange(t, transportName, auth)
				status, headers, body, err := exchange(http.MethodGet, target, nil, nil)
				if err != nil || status != http.StatusOK {
					t.Fatalf("%s: error page status=%d body=%s err=%v", transportName, status, body, err)
				}
				if !strings.HasPrefix(headers.Get("Content-Type"), "text/html") {
					t.Fatalf("%s: content type = %q", transportName, headers.Get("Content-Type"))
				}
				text := string(body)
				actual := errorPageObservation{
					ContainsRawScript:     strings.Contains(text, "<script>"),
					ContainsEscapedScript: strings.Contains(text, "&lt;script&gt;"),
					ContainsUnknown:       strings.Contains(text, "UNKNOWN"),
				}
				if !reflect.DeepEqual(actual, vector.Observation) {
					t.Fatalf("%s: error page observation = %#v, want %#v", transportName, actual, vector.Observation)
				}
			}
		})
	}
}

func errorPageTarget(t *testing.T, title string) string {
	t.Helper()
	switch title {
	case "should sanitize error description to prevent XSS":
		return "/api/auth/error?error=TEST&error_description=" + url.QueryEscape("<script>alert(1)</script>")
	case "should sanitize code parameter":
		return "/api/auth/error?error=" + url.QueryEscape("<script>")
	default:
		t.Fatalf("unknown error-page scenario %q", title)
		return ""
	}
}

func TestErrorPageScenarioDefinitions(t *testing.T) {
	cases := errorPageCases()
	if len(cases) != 2 {
		t.Fatalf("error-page scenarios=%d, want 2", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, vector := range cases {
		name := vector.Suite + "::" + vector.Title
		if vector.Suite == "" || vector.Title == "" {
			t.Fatalf("invalid error-page scenario: %#v", vector)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate error-page scenario %q", name)
		}
		seen[name] = struct{}{}
	}
}

func errorPageCases() []errorPageCase {
	return []errorPageCase{
		{
			Suite:       "error page security",
			Title:       "should sanitize code parameter",
			Observation: errorPageObservation{ContainsUnknown: true},
		},
		{
			Suite:       "error page security",
			Title:       "should sanitize error description to prevent XSS",
			Observation: errorPageObservation{ContainsEscapedScript: true},
		},
	}
}
