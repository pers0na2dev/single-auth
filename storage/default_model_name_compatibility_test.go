package storage

import (
	"errors"
	"testing"
)

type defaultModelNameOracleTest struct {
	Suite           string
	Title           string
	Initializations []defaultModelNameOracleInitialization
	Resolutions     []defaultModelNameOracleResolution
}

type defaultModelNameOracleInitialization struct {
	UsePlural  bool
	ModelNames map[string]string
}

type defaultModelNameOracleResolution struct {
	Model     string
	Result    string
	HasResult bool
	Error     *defaultModelNameOracleError
}

type defaultModelNameOracleError struct {
	Message string
}

func TestDefaultModelNameBehavior(t *testing.T) {
	if len(defaultModelNameScenarios) != 7 {
		t.Fatalf("model-name scenarios=%d, want 7", len(defaultModelNameScenarios))
	}
	for _, scenario := range defaultModelNameScenarios {
		scenario := scenario
		t.Run(scenario.Suite+"::"+scenario.Title, func(t *testing.T) {
			t.Parallel()
			runDefaultModelNameScenario(t, scenario)
		})
	}
}

func runDefaultModelNameScenario(t *testing.T, scenario defaultModelNameOracleTest) {
	t.Helper()
	if len(scenario.Initializations) != 1 {
		t.Fatalf("initializations=%d, want 1", len(scenario.Initializations))
	}
	initialization := scenario.Initializations[0]
	schema := Schema{Models: make(map[string]ModelSchema, len(initialization.ModelNames))}
	for canonical, modelName := range initialization.ModelNames {
		schema.Models[canonical] = ModelSchema{ModelName: modelName}
	}
	resolver := InitGetDefaultModelName(DefaultModelNameOptions{
		Schema: schema, UsePlural: initialization.UsePlural,
	})

	for index, expected := range scenario.Resolutions {
		actual, err := resolver(expected.Model)
		switch {
		case expected.Error != nil:
			if err == nil || err.Error() != expected.Error.Message || !errors.Is(err, ErrModelNotFound) {
				t.Fatalf("resolution %d model %q error=%v, want %q", index+1, expected.Model, err, expected.Error.Message)
			}
			var resolutionError *ModelResolutionError
			if !errors.As(err, &resolutionError) || resolutionError.Model != expected.Model {
				t.Fatalf("resolution %d error type/model=%T %#v", index+1, err, resolutionError)
			}
		case expected.HasResult:
			if err != nil || actual != expected.Result {
				t.Fatalf("resolution %d model %q=%q err=%v, want %q", index+1, expected.Model, actual, err, expected.Result)
			}
		default:
			t.Fatalf("resolution %d has neither result nor error", index+1)
		}
	}
}
