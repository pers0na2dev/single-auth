package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValuePreservesAbsentNullAndPresent(t *testing.T) {
	t.Parallel()

	absent := Absent[string]()
	if absent.IsSet() || absent.IsNull() {
		t.Fatal("absent value reported as set")
	}

	null := Null[string]()
	if !null.IsSet() || !null.IsNull() {
		t.Fatal("null value did not retain explicit-null state")
	}

	present := Present("")
	value, ok := present.Get()
	if !ok || value != "" {
		t.Fatal("present zero value was mistaken for absent")
	}
}

func TestUserJSONFlattensAdditionalFieldsAndPreservesOptionalState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	user := User{
		Core:             Core{ID: "u1", CreatedAt: now, UpdatedAt: now},
		Name:             "User",
		Email:            "user@example.com",
		AdditionalFields: Fields{"role": Present[any]("admin"), "nullable": Null[any]()},
	}
	encoded, err := json.Marshal(user)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(encoded)
	if strings.Contains(jsonText, `"image"`) {
		t.Fatalf("absent optional field was emitted: %s", jsonText)
	}
	if !strings.Contains(jsonText, `"role":"admin"`) || !strings.Contains(jsonText, `"nullable":null`) {
		t.Fatalf("additional fields were not flattened: %s", jsonText)
	}

	var decoded User
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Image.IsSet() {
		t.Fatal("missing image did not stay absent")
	}
	if role, ok := decoded.AdditionalFields["role"].Get(); !ok || role != "admin" {
		t.Fatalf("additional role = %#v, %v", role, ok)
	}
	if !decoded.AdditionalFields["nullable"].IsNull() {
		t.Fatal("additional null did not stay null")
	}
}

func TestValueJSONDistinguishesNullFromValue(t *testing.T) {
	t.Parallel()

	var null Value[string]
	if err := json.Unmarshal([]byte("null"), &null); err != nil {
		t.Fatal(err)
	}
	if !null.IsNull() {
		t.Fatal("JSON null was not retained")
	}

	var present Value[string]
	if err := json.Unmarshal([]byte(`""`), &present); err != nil {
		t.Fatal(err)
	}
	if value, ok := present.Get(); !ok || value != "" {
		t.Fatal("JSON zero value was not retained as present")
	}
}

func TestFieldsApplyOmitsAbsentAndKeepsNull(t *testing.T) {
	t.Parallel()

	fields := Fields{
		"absent": Absent[any](),
		"null":   Null[any](),
		"zero":   Present[any](0),
	}
	record := Record{}
	fields.Apply(record)

	if _, exists := record["absent"]; exists {
		t.Fatal("absent field was emitted")
	}
	if value, exists := record["null"]; !exists || value != nil {
		t.Fatal("explicit null field was not emitted as nil")
	}
	if value, exists := record["zero"]; !exists || value != 0 {
		t.Fatal("present zero field was lost")
	}
}
