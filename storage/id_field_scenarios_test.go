package storage

var idFieldScenarios = []idFieldOracleCase{
	{ID: "defaultValue priority::should fall back to default id generation", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "default", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "defaultValue", ExpectedValue: &idFieldValue{Kind: "default-id"}},
	}},
	{ID: "defaultValue priority::should return undefined when disableIdGeneration is true", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: true, GenerateID: "default", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: false, HasDefaultValue: false}},
	}},
	{ID: "defaultValue priority::should return undefined when generateId is 'serial'", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "serial", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "number", Required: false, HasDefaultValue: false}},
	}},
	{ID: "defaultValue priority::should return undefined when generateId is false", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "none", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "defaultValue", ExpectedValue: &idFieldValue{Kind: "undefined"}},
	}},
	{ID: "defaultValue priority::should use 'uuid' over customIdGenerator", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "uuid", HasCustomGenerator: true, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "defaultValue", ExpectedValue: &idFieldValue{Kind: "uuid"}},
	}},
	{ID: "defaultValue priority::should use customIdGenerator when generateId is not set", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "default", HasCustomGenerator: true, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "defaultValue", ExpectedValue: &idFieldValue{Kind: "value", Value: "adapter-id"}},
	}},
	{ID: "defaultValue priority::should use generateId function over 'uuid' and customIdGenerator", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "function", HasCustomGenerator: true, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "defaultValue", ExpectedValue: &idFieldValue{Kind: "value", Value: "fn-id"}},
	}},
	{ID: "transform.input > serial::should convert string to number", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "serial", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "number", Required: false, HasDefaultValue: false}},
		{Operation: "input", Value: idFieldValue{Kind: "value", Value: "42"}, ExpectedValue: &idFieldValue{Kind: "value", Value: float64(42)}},
	}},
	{ID: "transform.input > serial::should return undefined for non-numeric string", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "serial", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "number", Required: false, HasDefaultValue: false}},
		{Operation: "input", Value: idFieldValue{Kind: "value", Value: "not-a-number"}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
	}},
	{ID: "transform.input > uuid::should accept valid UUID when forceAllowId is true", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "uuid", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: true}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "input", Value: idFieldValue{Kind: "uuid", Value: nil}, ExpectedValue: &idFieldValue{Kind: "uuid"}},
	}},
	{ID: "transform.input > uuid::should generate new UUID for non-string value when DB doesn't support UUIDs", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "uuid", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: true}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "input", Value: idFieldValue{Kind: "value", Value: float64(123)}, ExpectedValue: &idFieldValue{Kind: "uuid"}},
	}},
	{ID: "transform.input > uuid::should return undefined when supportsUUIDs (DB handles it)", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "uuid", HasCustomGenerator: false, SupportsUUIDs: true, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: false, HasDefaultValue: false}},
		{Operation: "input", Value: idFieldValue{Kind: "value", Value: "some-value"}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
	}},
	{ID: "transform.input > uuid::should return value as-is when shouldGenerateId and not forceAllowId", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "uuid", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "input", Value: idFieldValue{Kind: "uuid", Value: nil}, ExpectedValue: &idFieldValue{Kind: "uuid"}},
	}},
	{ID: "transform.input::should return undefined for falsy value", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "default", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "input", Value: idFieldValue{Kind: "undefined", Value: nil}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
		{Operation: "input", Value: idFieldValue{Kind: "null", Value: nil}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
		{Operation: "input", Value: idFieldValue{Kind: "value", Value: ""}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
	}},
	{ID: "transform.input::should return value as-is by default", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "default", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "input", Value: idFieldValue{Kind: "value", Value: "some-id"}, ExpectedValue: &idFieldValue{Kind: "value", Value: "some-id"}},
	}},
	{ID: "transform.output::should convert value to string", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "default", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "output", Value: idFieldValue{Kind: "value", Value: float64(123)}, ExpectedValue: &idFieldValue{Kind: "value", Value: "123"}},
		{Operation: "output", Value: idFieldValue{Kind: "value", Value: "abc"}, ExpectedValue: &idFieldValue{Kind: "value", Value: "abc"}},
	}},
	{ID: "transform.output::should return undefined for falsy value", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "default", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
		{Operation: "output", Value: idFieldValue{Kind: "undefined", Value: nil}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
		{Operation: "output", Value: idFieldValue{Kind: "null", Value: nil}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
		{Operation: "output", Value: idFieldValue{Kind: "value", Value: ""}, ExpectedValue: &idFieldValue{Kind: "undefined"}},
	}},
	{ID: "type and required::should have type 'number' when generateId is 'serial'", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "serial", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "number", Required: false, HasDefaultValue: false}},
	}},
	{ID: "type and required::should have type 'string' by default", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "default", HasCustomGenerator: false, SupportsUUIDs: false, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: true, HasDefaultValue: true}},
	}},
	{ID: "type and required::should not generate id when useUUIDs and supportsUUIDs", Observations: []idFieldOracleObservation{
		{Operation: "field", Config: idFieldConfig{UsePlural: false, DisableIDGeneration: false, GenerateID: "uuid", HasCustomGenerator: false, SupportsUUIDs: true, CustomModelName: "user", ForceAllowID: false}, ExpectedField: &idFieldResult{Type: "string", Required: false, HasDefaultValue: false}},
	}},
}
