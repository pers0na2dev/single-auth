package singleauth_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	typecheckSmokeConsumersDir = "../testdata/typecheck-smoke/consumers"
)

type typecheckSmokeVector struct {
	Name           string
	Fixture        string
	ExpectedStdout string
}

func TestExportedAPISignatures(t *testing.T) {
	runTypecheckSmokeConsumer(t, 0)
}

func TestOptionalConfigurationStates(t *testing.T) {
	runTypecheckSmokeConsumer(t, 1)
}

func TestCrossPackagePluginComposition(t *testing.T) {
	runTypecheckSmokeConsumer(t, 2)
}

func TestExplicitModuleAndHTTPImports(t *testing.T) {
	runTypecheckSmokeConsumer(t, 3)
}

func TestTypecheckSmokeFixtureIntegrity(t *testing.T) {
	vectors := typecheckSmokeCases()
	if len(vectors) != 4 {
		t.Fatalf("typecheck-smoke vectors=%d, want 4", len(vectors))
	}
	seen := make(map[string]struct{}, len(vectors))
	for _, vector := range vectors {
		if vector.Fixture == "" || vector.Name == "" ||
			vector.ExpectedStdout != "ok:"+vector.Fixture {
			t.Fatalf("invalid typecheck-smoke vector: %#v", vector)
		}
		if _, duplicate := seen[vector.Name]; duplicate {
			t.Fatalf("duplicate typecheck-smoke name %q", vector.Name)
		}
		seen[vector.Name] = struct{}{}
		mainPath := typecheckSmokeConsumersDir + "/" + vector.Fixture + "/main.go"
		if info, err := os.Stat(mainPath); err != nil || info.IsDir() {
			t.Fatalf("external consumer fixture %q is missing: %v", mainPath, err)
		}
	}
}

func runTypecheckSmokeConsumer(t *testing.T, index int) {
	t.Helper()
	vectors := typecheckSmokeCases()
	if index < 0 || index >= len(vectors) {
		t.Fatalf("typecheck-smoke vector index %d is missing", index)
	}
	selected := &vectors[index]

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", "-mod=readonly", "./"+selected.Fixture)
	command.Dir = typecheckSmokeConsumersDir
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("external typecheck-smoke consumer %q timed out: %v", selected.Fixture, ctx.Err())
	}
	if err != nil {
		t.Fatalf("external typecheck-smoke consumer %q failed: %v\n%s", selected.Fixture, err, output)
	}
	if got := strings.TrimSpace(string(output)); got != selected.ExpectedStdout {
		t.Fatalf("external typecheck-smoke consumer %q output=%q, want %q", selected.Fixture, got, selected.ExpectedStdout)
	}
}

func typecheckSmokeCases() []typecheckSmokeVector {
	return []typecheckSmokeVector{
		{Name: "exported API signatures", Fixture: "tsconfig-declaration", ExpectedStdout: "ok:tsconfig-declaration"},
		{Name: "optional configuration states", Fixture: "tsconfig-exact-optional-property-types", ExpectedStdout: "ok:tsconfig-exact-optional-property-types"},
		{Name: "cross-package plugin composition", Fixture: "tsconfig-isolated-module-bundler", ExpectedStdout: "ok:tsconfig-isolated-module-bundler"},
		{Name: "explicit module and HTTP imports", Fixture: "tsconfig-verbatim-module-syntax-node10", ExpectedStdout: "ok:tsconfig-verbatim-module-syntax-node10"},
	}
}
