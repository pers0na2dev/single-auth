package singleauth_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type endpointMethodVector struct {
	Suite          string
	Title          string
	Mode           string
	ExpectedStdout string
}

func TestEndpointMethodCompileTimeBehavior(t *testing.T) {
	for _, vector := range endpointMethodCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			command := exec.CommandContext(
				ctx, "go", "run", "-mod=readonly", "./endpoint-method/"+vector.Mode,
			)
			command.Dir = "../testdata/typecheck-smoke/consumers"
			command.Env = append(os.Environ(), "GOWORK=off")
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("endpoint-method consumer %s timed out: %v", vector.Mode, ctx.Err())
			}
			if err != nil {
				t.Fatalf("endpoint-method consumer %s failed: %v\n%s", vector.Mode, err, output)
			}
			if got := strings.TrimSpace(string(output)); got != vector.ExpectedStdout {
				t.Fatalf("endpoint-method consumer %s output=%q, want %q", vector.Mode, got, vector.ExpectedStdout)
			}
		})
	}
}

func TestEndpointMethodScenarioDefinitions(t *testing.T) {
	cases := endpointMethodCases()
	if len(cases) != 9 {
		t.Fatalf("endpoint-method scenarios=%d, want 9", len(cases))
	}
	seenModes := make(map[string]struct{}, len(cases))
	for _, scenario := range cases {
		if scenario.Suite == "" || scenario.Title == "" || scenario.Mode == "" ||
			scenario.ExpectedStdout != "ok:endpoint-method-"+scenario.Mode {
			t.Fatalf("invalid endpoint-method scenario: %#v", scenario)
		}
		if _, duplicate := seenModes[scenario.Mode]; duplicate {
			t.Fatalf("duplicate endpoint-method mode %q", scenario.Mode)
		}
		seenModes[scenario.Mode] = struct{}{}
	}
}

func endpointMethodCases() []endpointMethodVector {
	return []endpointMethodVector{
		{Suite: "Server getSession return type", Title: "server-side getSession return type is not any with custom session", Mode: "server-not-any", ExpectedStdout: "ok:endpoint-method-server-not-any"},
		{Suite: "Endpoint method types", Title: "createAuthEndpoint normalizes array methods to mutable array", Mode: "endpoint-array", ExpectedStdout: "ok:endpoint-method-endpoint-array"},
		{Suite: "Endpoint method types", Title: "createAuthEndpoint preserves literal method for GET", Mode: "endpoint-get", ExpectedStdout: "ok:endpoint-method-endpoint-get"},
		{Suite: "Endpoint method types", Title: "createAuthEndpoint preserves literal method for POST", Mode: "endpoint-post", ExpectedStdout: "ok:endpoint-method-endpoint-post"},
		{Suite: "Endpoint method types", Title: "path-less overload preserves method type", Mode: "endpoint-pathless", ExpectedStdout: "ok:endpoint-method-endpoint-pathless"},
		{Suite: "Plugin endpoint override types", Title: "$Infer.Session reflects custom session return type", Mode: "infer-session", ExpectedStdout: "ok:endpoint-method-infer-session"},
		{Suite: "Plugin endpoint override types", Title: "plugin overriding getSession replaces base type cleanly", Mode: "override-clean", ExpectedStdout: "ok:endpoint-method-override-clean"},
		{Suite: "Plugin endpoint override types", Title: "plugin with custom endpoints preserves base api methods", Mode: "plugin-base-api", ExpectedStdout: "ok:endpoint-method-plugin-base-api"},
		{Suite: "Plugin endpoint override types", Title: "server-side Auth api reflects custom session plugin override", Mode: "server-custom-session-api", ExpectedStdout: "ok:endpoint-method-server-custom-session-api"},
	}
}
