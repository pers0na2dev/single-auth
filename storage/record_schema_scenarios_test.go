package storage

var recordSchemaScenarios = []recordSchemaOracleTest{
	{Title: "should accept null, undefined, and a value for an optional field", Observation: map[string]any{"nullValue": nil, "undefinedSuccess": true, "absent": map[string]any{}, "value": "value"}},
	{Title: "should reject null for a required field", Observation: map[string]any{"success": false}},
	{Title: "should exclude fields with returned: false from output schema (isClientSide: false)", Observation: map[string]any{"fields": []any{"name"}}},
	{Title: "should include fields with returned: false in input schema (isClientSide: true)", Observation: map[string]any{"fields": []any{"name", "secretField"}}},
}
