package singleauth_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

type typesCompileVector struct {
	Suite          string
	Title          string
	Mode           string
	ExpectedStdout string
}

func TestTypesCompileTimeBehavior(t *testing.T) {
	for _, vector := range typesCompileCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			command := exec.CommandContext(
				ctx, "go", "run", "-mod=readonly", "./types-types/"+vector.Mode,
			)
			command.Dir = "../testdata/typecheck-smoke/consumers"
			command.Env = append(os.Environ(), "GOWORK=off")
			output, err := command.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("types consumer %s timed out: %v", vector.Mode, ctx.Err())
			}
			if err != nil {
				t.Fatalf("types consumer %s failed: %v\n%s", vector.Mode, err, output)
			}
			if got := strings.TrimSpace(string(output)); got != vector.ExpectedStdout {
				t.Fatalf("types consumer %s output=%q, want %q", vector.Mode, got, vector.ExpectedStdout)
			}
		})
	}
}

func TestTypesScenarioDefinitions(t *testing.T) {
	cases := typesCompileCases()
	if len(cases) != 18 {
		t.Fatalf("types scenarios=%d, want 18", len(cases))
	}
	seenModes := make(map[string]struct{}, len(cases))
	for _, scenario := range cases {
		if scenario.Suite == "" || scenario.Title == "" || scenario.Mode == "" ||
			scenario.ExpectedStdout != "ok:types-types-"+scenario.Mode {
			t.Fatalf("invalid types scenario: %#v", scenario)
		}
		if _, duplicate := seenModes[scenario.Mode]; duplicate {
			t.Fatalf("duplicate types mode %q", scenario.Mode)
		}
		seenModes[scenario.Mode] = struct{}{}
	}
}

func typesCompileCases() []typesCompileVector {
	return []typesCompileVector{
		{Suite: "Required key detection", Title: "returns false for unconstrained values", Mode: "required-any", ExpectedStdout: "ok:types-types-required-any"},
		{Suite: "Required key detection", Title: "returns false for objects with only optional keys", Mode: "required-optional", ExpectedStdout: "ok:types-types-required-optional"},
		{Suite: "Required key detection", Title: "returns true for objects with required keys", Mode: "required-present", ExpectedStdout: "ok:types-types-required-present"},
		{Suite: "Type-safety guards", Title: "request context preserves query when body is unconstrained", Mode: "infer-ctx", ExpectedStdout: "ok:types-types-infer-ctx"},
		{Suite: "Type-safety guards", Title: "error codes remain typed with an untyped plugin", Mode: "poison-error-codes", ExpectedStdout: "ok:types-types-poison-error-codes"},
		{Suite: "Type-safety guards", Title: "inferred data remains typed with an untyped plugin", Mode: "poison-infer", ExpectedStdout: "ok:types-types-poison-infer"},
		{Suite: "General types", Title: "plugin override drives the API type", Mode: "override-base", ExpectedStdout: "ok:types-types-override-base"},
		{Suite: "General types", Title: "infers additional fields from plugins", Mode: "additional-fields", ExpectedStdout: "ok:types-types-additional-fields"},
		{Suite: "General types", Title: "infers the base session", Mode: "base-session", ExpectedStdout: "ok:types-types-base-session"},
		{Suite: "General types", Title: "infers plugin context from initialization", Mode: "init-context", ExpectedStdout: "ok:types-types-init-context"},
		{Suite: "General types", Title: "empty plugins match omitted plugins", Mode: "empty-plugins", ExpectedStdout: "ok:types-types-empty-plugins"},
		{Suite: "General types", Title: "infers server-scoped endpoints", Mode: "server-scoped", ExpectedStdout: "ok:types-types-server-scoped"},
		{Suite: "General types", Title: "generic options preserve session access", Mode: "generic-get-session", ExpectedStdout: "ok:types-types-generic-get-session"},
		{Suite: "General types", Title: "matches plugin types", Mode: "plugin-match", ExpectedStdout: "ok:types-types-plugin-match"},
		{Suite: "Plugin factory types", Title: "preserves error codes through a factory", Mode: "factory-error-codes", ExpectedStdout: "ok:types-types-factory-error-codes"},
		{Suite: "Plugin factory types", Title: "preserves endpoint types through a factory", Mode: "factory-return", ExpectedStdout: "ok:types-types-factory-return"},
		{Suite: "Plugin factory types", Title: "preserves endpoint types with stored options", Mode: "options-variable", ExpectedStdout: "ok:types-types-options-variable"},
		{Suite: "Plugin factory types", Title: "preserves endpoint types with mixed-shape plugins", Mode: "mixed-shape", ExpectedStdout: "ok:types-types-mixed-shape"},
	}
}
