package oauthprovider

import (
	"net/url"
	"reflect"
	"testing"
)

type signedQueryCase struct {
	Title       string
	Observation signedQueryObservation
}

type signedQueryObservation struct {
	Operation string            `json:"operation"`
	Input     signedQueryInput  `json:"input"`
	Output    signedQueryOutput `json:"output"`
}

type signedQueryInput struct {
	BaseEntries [][]string `json:"baseEntries"`
	Entries     [][]string `json:"entries"`
	Search      string     `json:"search"`
}

type signedQueryOutput struct {
	SignedParameterNames               []string `json:"signedParameterNames"`
	Result                             string   `json:"result"`
	Defined                            bool     `json:"defined"`
	CustomAuthorizationContext         *string  `json:"customAuthorizationContext"`
	Resource                           *string  `json:"resource"`
	UTMEmail                           *string  `json:"utmEmail"`
	DeclaresCustomAuthorizationContext bool     `json:"declaresCustomAuthorizationContext"`
}

func TestSignedOAuthQueryRuntime(t *testing.T) {
	for _, vector := range signedQueryCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			switch vector.Observation.Operation {
			case "build":
				params := signedQueryValues(t, vector.Observation.Input.BaseEntries)
				SetSignedOAuthQueryParameterNames(params)
				if !reflect.DeepEqual(params[SignedQueryParameterNameParam], vector.Observation.Output.SignedParameterNames) {
					t.Fatalf("signed parameter names=%q want=%q", params[SignedQueryParameterNameParam], vector.Observation.Output.SignedParameterNames)
				}
				result, ok := BuildSignedOAuthQuery(vector.Observation.Input.Search)
				if !ok || result != vector.Observation.Output.Result {
					t.Fatalf("BuildSignedOAuthQuery = %q, %t; want %q, true", result, ok, vector.Observation.Output.Result)
				}
				parsed, err := url.ParseQuery(result)
				if err != nil {
					t.Fatal(err)
				}
				assertSignedQueryOptionalString(t, "custom_authorization_context", parsed.Get("custom_authorization_context"), vector.Observation.Output.CustomAuthorizationContext)
				assertSignedQueryOptionalString(t, "resource", parsed.Get("resource"), vector.Observation.Output.Resource)
				if vector.Observation.Output.UTMEmail != nil || parsed.Has("utm_email") {
					t.Fatalf("utm_email=%q want absent", parsed.Get("utm_email"))
				}
				declares := false
				for _, name := range parsed[SignedQueryParameterNameParam] {
					if name == "custom_authorization_context" {
						declares = true
					}
				}
				if declares != vector.Observation.Output.DeclaresCustomAuthorizationContext {
					t.Fatalf("declares custom authorization context=%t", declares)
				}
			case "canonicalize":
				actual := CanonicalizeOAuthQueryParams(signedQueryValues(t, vector.Observation.Input.Entries))
				if actual != vector.Observation.Output.Result {
					t.Fatalf("canonical query=%q want=%q", actual, vector.Observation.Output.Result)
				}
			case "legacy":
				result, defined := BuildSignedOAuthQuery(vector.Observation.Input.Search)
				if defined != vector.Observation.Output.Defined || result != "" {
					t.Fatalf("legacy signed query=%q, %t", result, defined)
				}
			default:
				t.Fatalf("unknown signed-query operation %q", vector.Observation.Operation)
			}
		})
	}
}

func signedQueryValues(t *testing.T, entries [][]string) url.Values {
	t.Helper()
	values := make(url.Values)
	for _, entry := range entries {
		if len(entry) != 2 {
			t.Fatalf("invalid signed-query entry %q", entry)
		}
		values.Add(entry[0], entry[1])
	}
	return values
}

func assertSignedQueryOptionalString(t *testing.T, field, actual string, expected *string) {
	t.Helper()
	if expected == nil || actual != *expected {
		t.Fatalf("%s=%q want=%#v", field, actual, expected)
	}
}
