package storage

import (
	"reflect"
	"testing"
	"time"
)

func TestCoreSchemaMatchesBaseModels(t *testing.T) {
	t.Parallel()
	schema := CoreSchema()
	for _, model := range []string{"user", "session", "account", "verification", "rateLimit"} {
		if _, exists := schema.Models[model]; !exists {
			t.Errorf("core schema is missing %q", model)
		}
	}
	if reference := schema.Models["session"].Fields["userId"].References; reference == nil || reference.Model != "user" || reference.Field != "id" || reference.OnDelete != Cascade {
		t.Fatalf("session.userId reference = %#v", reference)
	}
	if schema.Models["account"].Fields["password"].IsReturned() {
		t.Fatal("account password must be marked not returned")
	}
}

func TestSchemaMergeAndAliasResolution(t *testing.T) {
	t.Parallel()
	base := CoreSchema()
	merged, err := base.Merge(Schema{Models: map[string]ModelSchema{
		"user": {
			ModelName: "member",
			Fields: map[string]FieldAttribute{
				"role": {Type: FieldString, Required: Bool(false), FieldName: "access_role"},
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, canonical, err := merged.ResolveModel("member")
	if err != nil || canonical != "user" {
		t.Fatalf("model alias resolved to %q, %v", canonical, err)
	}
	field, canonicalField, err := merged.ResolveField("user", "access_role")
	if err != nil || canonicalField != "role" || field.FieldName != "access_role" {
		t.Fatalf("field alias resolved to %q %#v, %v", canonicalField, field, err)
	}
	if _, exists := base.Models["user"].Fields["role"]; exists {
		t.Fatal("Merge mutated its base schema")
	}
}

func TestCapabilityConversions(t *testing.T) {
	t.Parallel()
	capabilities := NativeCapabilities()
	capabilities.JSON = false
	capabilities.Arrays = false
	capabilities.Dates = false
	capabilities.Booleans = false
	date := time.Date(2026, 8, 8, 10, 0, 0, 123, time.UTC)
	tests := []struct {
		field FieldAttribute
		value any
	}{
		{FieldAttribute{Type: FieldJSON}, map[string]any{"ok": true}},
		{FieldAttribute{Type: FieldStringArray}, []string{"a", "b"}},
		{FieldAttribute{Type: FieldNumberArray}, []float64{1, 2}},
		{FieldAttribute{Type: FieldDate}, date},
		{FieldAttribute{Type: FieldBoolean}, true},
	}
	for _, test := range tests {
		encoded, err := EncodeValue(capabilities, test.field, test.value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeValue(capabilities, test.field, encoded)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, test.value) {
			t.Errorf("%s round trip = %#v (%T), want %#v (%T)", test.field.Type, decoded, decoded, test.value, test.value)
		}
	}
}

func TestWhereNormalizeRejectsInvalidInOperand(t *testing.T) {
	t.Parallel()
	_, err := (Where{Field: "id", Operator: OpIn, Value: "not-an-array"}).Normalize()
	if err == nil {
		t.Fatal("in accepted a scalar operand")
	}
}
