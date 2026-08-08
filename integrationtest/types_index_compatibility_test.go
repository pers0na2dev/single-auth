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
	typesIndexInferUserTitle = "infer user type correctly"
)

type typesIndexCase struct {
	Title          string
	Fixture        string
	ExpectedStdout string
}

func TestTypesIndexInferUserCompileBehavior(t *testing.T) {
	runTypesIndexExternalConsumer(t, typesIndexInferUserTitle)
}

func TestTypesIndexScenarioDefinitions(t *testing.T) {
	cases := typesIndexCases()
	if len(cases) != 1 {
		t.Fatalf("types/index scenarios=%d, want 1", len(cases))
	}
	for _, scenario := range cases {
		if scenario.Title == "" || scenario.Fixture == "" || scenario.ExpectedStdout == "" {
			t.Fatalf("invalid types/index scenario: %#v", scenario)
		}
		if info, err := os.Stat("../testdata/typecheck-smoke/consumers/" + scenario.Fixture + "/main.go"); err != nil || info.IsDir() {
			t.Fatalf("types/index external consumer %q is missing: %v", scenario.Fixture, err)
		}
	}
}

func runTypesIndexExternalConsumer(t *testing.T, title string) {
	t.Helper()
	cases := typesIndexCases()
	var selected *typesIndexCase
	for index := range cases {
		if cases[index].Title == title {
			selected = &cases[index]
			break
		}
	}
	if selected == nil {
		t.Fatalf("types/index fixture scenario %q is missing", title)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(
		ctx, "go", "run", "-mod=readonly", "./"+selected.Fixture,
	)
	command.Dir = "../testdata/typecheck-smoke/consumers"
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("types/index external consumer timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("types/index external consumer failed: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != selected.ExpectedStdout {
		t.Fatalf(
			"types/index external consumer output=%q, want %q",
			got, selected.ExpectedStdout,
		)
	}
}

func typesIndexCases() []typesIndexCase {
	return []typesIndexCase{
		{Title: typesIndexInferUserTitle, Fixture: "types-index-infer-user", ExpectedStdout: "ok:types-index-infer-user"},
	}
}
