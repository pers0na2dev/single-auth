package singleauth_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var dbTypesTitles = []string{
	"Account with additionalFields",
	"Account with plugin fields",
	"Schema without additionalFields should work",
	"Session with additionalFields",
	"Session with plugin fields",
	"User with additionalFields",
	"User with both additionalFields and plugin fields",
	"User with different field types",
	"User with plugin fields",
	"Verification with additionalFields",
}

type dbTypesCase struct {
	Title          string
	Argument       string
	ExpectedStdout string
}

func TestDBTypeAccountAdditionalFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[0])
}

func TestDBTypeAccountPluginFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[1])
}

func TestDBTypeDefaultSchemaCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[2])
}

func TestDBTypeSessionAdditionalFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[3])
}

func TestDBTypeSessionPluginFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[4])
}

func TestDBTypeUserAdditionalFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[5])
}

func TestDBTypeUserCombinedFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[6])
}

func TestDBTypeUserFieldKindsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[7])
}

func TestDBTypeUserPluginFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[8])
}

func TestDBTypeVerificationAdditionalFieldsCompileBehavior(t *testing.T) {
	runDBTypesExternalConsumer(t, dbTypesTitles[9])
}

func TestDBTypesScenarioDefinitions(t *testing.T) {
	cases := dbTypesCases()
	if len(cases) != len(dbTypesTitles) {
		t.Fatalf("db-types scenarios=%d, want %d", len(cases), len(dbTypesTitles))
	}
	seen := make(map[string]struct{}, len(cases))
	for index, scenario := range cases {
		if scenario.Title != dbTypesTitles[index] || scenario.Argument == "" ||
			scenario.ExpectedStdout != "ok:db-types-"+scenario.Argument {
			t.Fatalf("invalid db-types scenario: %#v", scenario)
		}
		if _, duplicate := seen[scenario.Argument]; duplicate {
			t.Fatalf("duplicate db-types argument %q", scenario.Argument)
		}
		seen[scenario.Argument] = struct{}{}
	}
}

func runDBTypesExternalConsumer(t *testing.T, title string) {
	t.Helper()
	cases := dbTypesCases()
	var selected *dbTypesCase
	for index := range cases {
		if cases[index].Title == title {
			selected = &cases[index]
			break
		}
	}
	if selected == nil {
		t.Fatalf("db-types fixture scenario %q is missing or invalid", title)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	arguments := []string{
		"run", "-mod=readonly", "./db-types",
	}
	arguments = append(arguments, selected.Argument)
	command := exec.CommandContext(ctx, "go", arguments...)
	command.Dir = "../testdata/typecheck-smoke/consumers"
	command.Env = append(os.Environ(), "GOWORK=off")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("db-types external consumer timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("db-types external consumer failed: %v\n%s", err, output)
	}
	if got := strings.TrimSpace(string(output)); got != selected.ExpectedStdout {
		t.Fatalf("db-types external consumer output=%q, want %q", got, selected.ExpectedStdout)
	}
}

func dbTypesCases() []dbTypesCase {
	arguments := []string{
		"account-additional-fields",
		"account-plugin-fields",
		"schema-without-additional-fields",
		"session-additional-fields",
		"session-plugin-fields",
		"user-additional-fields",
		"user-both-additional-plugin-fields",
		"user-different-field-types",
		"user-plugin-fields",
		"verification-additional-fields",
	}
	cases := make([]dbTypesCase, len(arguments))
	for index, argument := range arguments {
		cases[index] = dbTypesCase{
			Title:          dbTypesTitles[index],
			Argument:       argument,
			ExpectedStdout: "ok:db-types-" + argument,
		}
	}
	return cases
}
