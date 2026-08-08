package storage

import (
	"reflect"
	"testing"
)

type recordSchemaOracleTest struct {
	Title       string
	Observation map[string]any
}

func TestRecordSchemaBehavior(t *testing.T) {
	if len(recordSchemaScenarios) != 4 {
		t.Fatalf("record schema scenarios=%d, want 4", len(recordSchemaScenarios))
	}
	for _, scenario := range recordSchemaScenarios {
		scenario := scenario
		t.Run(scenario.Title, func(t *testing.T) {
			actual := runRecordSchemaScenario(t, scenario.Title)
			if !reflect.DeepEqual(actual, scenario.Observation) {
				t.Fatalf("record schema observation=%#v, want %#v", actual, scenario.Observation)
			}
		})
	}
}

func runRecordSchemaScenario(t *testing.T, title string) map[string]any {
	t.Helper()
	switch title {
	case "should include fields with returned: false in input schema (isClientSide: true)":
		schema := ToRecordSchema(map[string]FieldAttribute{
			"name": {Type: FieldString}, "secretField": {Type: FieldString, Returned: Bool(false)},
		}, true)
		return map[string]any{"fields": stringSliceToAny(schema.FieldNames())}
	case "should exclude fields with returned: false from output schema (isClientSide: false)":
		schema := ToRecordSchema(map[string]FieldAttribute{
			"name": {Type: FieldString}, "secretField": {Type: FieldString, Returned: Bool(false)},
		}, false)
		return map[string]any{"fields": stringSliceToAny(schema.FieldNames())}
	case "should accept null, undefined, and a value for an optional field":
		schema := ToRecordSchema(map[string]FieldAttribute{"logo": {Type: FieldString, Required: Bool(false)}}, true)
		nullRecord, nullErr := schema.Parse(Record{"logo": nil})
		_, undefinedErr := schema.Parse(Record{})
		absent, absentErr := schema.Parse(Record{})
		valueRecord, valueErr := schema.Parse(Record{"logo": "value"})
		if nullErr != nil || undefinedErr != nil || absentErr != nil || valueErr != nil {
			t.Fatalf("optional record parse errors: null=%v undefined=%v absent=%v value=%v", nullErr, undefinedErr, absentErr, valueErr)
		}
		return map[string]any{
			"nullValue": nullRecord["logo"], "undefinedSuccess": true,
			"absent": map[string]any(absent), "value": valueRecord["logo"],
		}
	case "should reject null for a required field":
		schema := ToRecordSchema(map[string]FieldAttribute{"name": {Type: FieldString}}, true)
		_, err := schema.Parse(Record{"name": nil})
		return map[string]any{"success": err == nil}
	default:
		t.Fatalf("unsupported record schema scenario %q", title)
		return nil
	}
}

func stringSliceToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}
