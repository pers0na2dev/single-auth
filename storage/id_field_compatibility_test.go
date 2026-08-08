package storage

import (
	"bytes"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	frozenIDFieldTestCount        = 20
	frozenIDFieldObservationCount = 40
)

var frozenIDFieldOperationCounts = map[string]int{
	"field":        20,
	"defaultValue": 5,
	"input":        10,
	"output":       5,
}

var (
	idFieldOracleUUID      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	idFieldOracleDefaultID = regexp.MustCompile(`^[a-zA-Z0-9]{32}$`)
)

type idFieldOracle struct {
	Cases []idFieldOracleCase
}

type idFieldOracleCase struct {
	ID           string                     `json:"id"`
	Observations []idFieldOracleObservation `json:"observations"`
}

type idFieldOracleObservation struct {
	Operation     string
	Config        idFieldConfig
	Value         idFieldValue
	ExpectedField *idFieldResult
	ExpectedValue *idFieldValue
}

type idFieldConfig struct {
	UsePlural           bool   `json:"usePlural"`
	DisableIDGeneration bool   `json:"disableIDGeneration"`
	GenerateID          string `json:"generateID"`
	HasCustomGenerator  bool   `json:"hasCustomIDGenerator"`
	SupportsUUIDs       bool   `json:"supportsUUIDs"`
	CustomModelName     string `json:"customModelName"`
	ForceAllowID        bool   `json:"forceAllowID"`
}

type idFieldResult struct {
	Type            string `json:"type"`
	Required        bool   `json:"required"`
	HasDefaultValue bool   `json:"hasDefaultValue"`
}

type idFieldValue struct {
	Kind  string `json:"kind"`
	Value any    `json:"value"`
}

func TestGetIDFieldRuntimeBehavior(t *testing.T) {
	oracle := loadIDFieldOracle(t)
	for _, testCase := range oracle.Cases {
		testCase := testCase
		t.Run(idFieldCaseName(testCase.ID), func(t *testing.T) {
			t.Parallel()
			runIDFieldOracleCase(t, testCase)
		})
	}
}

func idFieldCaseName(id string) string {
	if separator := strings.Index(id, "::"); separator >= 0 {
		return id[separator+2:]
	}
	return id
}

func runIDFieldOracleCase(t *testing.T, testCase idFieldOracleCase) {
	t.Helper()
	if len(testCase.Observations) == 0 || testCase.Observations[0].Operation != "field" {
		t.Fatal("scenario does not start with a field observation")
	}
	fieldObservation := testCase.Observations[0]
	if fieldObservation.ExpectedField == nil {
		t.Fatal("field scenario has no expected field")
	}
	expectedField := *fieldObservation.ExpectedField

	config := fieldObservation.Config
	options := IDFieldFactoryOptions{
		Schema: Schema{Models: map[string]ModelSchema{
			"user": {
				ModelName: "user",
				Fields: map[string]FieldAttribute{
					"name":  {Type: FieldString},
					"email": {Type: FieldString},
				},
			},
		}},
		UsePlural:           config.UsePlural,
		DisableIDGeneration: config.DisableIDGeneration,
		SupportsUUIDs:       config.SupportsUUIDs,
		Random:              bytes.NewReader(bytes.Repeat([]byte{0x23}, 4096)),
	}
	switch config.GenerateID {
	case "default":
		options.GenerateID = IDGenerationDefault
	case "none":
		options.GenerateID = IDGenerationNone
	case "serial":
		options.GenerateID = IDGenerationSerial
	case "uuid":
		options.GenerateID = IDGenerationUUID
	case "function":
		options.GenerateIDFunc = func(model string) (any, error) {
			if model != "user" {
				t.Fatalf("generateId model = %q, want user", model)
			}
			return "fn-id", nil
		}
	default:
		t.Fatalf("unknown frozen generateID mode %q", config.GenerateID)
	}
	if config.HasCustomGenerator {
		options.CustomIDGenerator = func(model string) (any, error) {
			if model != "user" {
				t.Fatalf("custom generator model = %q, want user", model)
			}
			return "adapter-id", nil
		}
	}

	factory := InitGetIDField(options)
	field, err := factory(IDFieldOptions{
		CustomModelName: config.CustomModelName,
		ForceAllowID:    config.ForceAllowID,
	})
	if err != nil {
		t.Fatal(err)
	}
	actualField := idFieldResult{
		Type:            string(field.Type),
		Required:        field.IsRequired(),
		HasDefaultValue: field.DefaultValue != nil,
	}
	if !reflect.DeepEqual(actualField, expectedField) {
		t.Fatalf("field = %#v, want %#v", actualField, expectedField)
	}

	for index, observation := range testCase.Observations[1:] {
		if observation.ExpectedValue == nil {
			t.Fatalf("observation %d has no expected value", index+1)
		}
		expected := *observation.ExpectedValue
		var actual any
		switch observation.Operation {
		case "defaultValue":
			if field.DefaultValue == nil {
				t.Fatalf("observation %d calls a missing defaultValue", index+1)
			}
			actual, err = field.DefaultValue(ValueContext{})
		case "input":
			if field.Transform.Input == nil {
				t.Fatalf("observation %d calls a missing input transform", index+1)
			}
			actual, err = field.Transform.Input(decodeIDFieldValue(observation.Value))
		case "output":
			if field.Transform.Output == nil {
				t.Fatalf("observation %d calls a missing output transform", index+1)
			}
			actual, err = field.Transform.Output(decodeIDFieldValue(observation.Value))
		default:
			t.Fatalf("unknown frozen operation %q", observation.Operation)
		}
		if err != nil {
			t.Fatalf("observation %d %s: %v", index+1, observation.Operation, err)
		}
		assertIDFieldValue(t, normalizeIDFieldValue(actual), expected, index+1, observation.Operation)
	}
}

func loadIDFieldOracle(t *testing.T) idFieldOracle {
	t.Helper()
	oracle := idFieldOracle{Cases: idFieldScenarios}
	if len(oracle.Cases) != frozenIDFieldTestCount {
		t.Fatalf("ID-field scenarios=%d, want %d", len(oracle.Cases), frozenIDFieldTestCount)
	}

	observationCount := 0
	operationCounts := map[string]int{}
	for _, testCase := range oracle.Cases {
		observationCount += len(testCase.Observations)
		for _, observation := range testCase.Observations {
			operationCounts[observation.Operation]++
		}
	}
	if observationCount != frozenIDFieldObservationCount ||
		!reflect.DeepEqual(operationCounts, frozenIDFieldOperationCounts) {
		t.Fatalf(
			"observation inventory = total %d counts %#v, want %d %#v",
			observationCount, operationCounts, frozenIDFieldObservationCount, frozenIDFieldOperationCounts,
		)
	}
	return oracle
}

func decodeIDFieldValue(value idFieldValue) any {
	switch value.Kind {
	case "undefined", "null":
		return nil
	case "uuid":
		return "550e8400-e29b-41d4-a716-446655440000"
	case "default-id":
		return "0123456789abcdefghijklmnopqrstuv"
	case "value":
		return value.Value
	default:
		return nil
	}
}

func normalizeIDFieldValue(value any) idFieldValue {
	if value == nil {
		return idFieldValue{Kind: "undefined"}
	}
	if text, ok := value.(string); ok {
		switch {
		case idFieldOracleUUID.MatchString(text):
			return idFieldValue{Kind: "uuid"}
		case idFieldOracleDefaultID.MatchString(text):
			return idFieldValue{Kind: "default-id"}
		}
	}
	return idFieldValue{Kind: "value", Value: value}
}

func assertIDFieldValue(t *testing.T, actual, expected idFieldValue, index int, operation string) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("observation %d %s result=%#v, want %#v", index, operation, actual, expected)
	}
}
