package mssql

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestMSSQLScalarCodecs(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"parent": {Fields: map[string]storage.FieldAttribute{}},
		"scalar": {Fields: map[string]storage.FieldAttribute{
			"active":   {Type: storage.FieldBoolean, Required: storage.Bool(false)},
			"count":    {Type: storage.FieldNumber, Required: storage.Bool(false)},
			"created":  {Type: storage.FieldDate, Required: storage.Bool(false)},
			"labels":   {Type: storage.FieldStringArray, Required: storage.Bool(false)},
			"metadata": {Type: storage.FieldJSON, Required: storage.Bool(false)},
			"parentId": {Type: storage.FieldString, Required: storage.Bool(false), References: &storage.Reference{Model: "parent", Field: "id"}},
			"scores":   {Type: storage.FieldNumberArray, Required: storage.Bool(false)},
			"transformed": {
				Type: storage.FieldString, Required: storage.Bool(false),
				Transform: storage.FieldTransform{
					Input:  func(value any) (any, error) { return strings.ToUpper(value.(string)), nil },
					Output: func(value any) (any, error) { return "decoded:" + value.(string), nil },
				},
			},
		}},
	}}
	configuration, err := normalizeOptions(Options{Schema: schema, IDType: SerialID})
	if err != nil {
		t.Fatal(err)
	}
	model, err := resolveModel(&configuration, "scalar")
	if err != nil {
		t.Fatal(err)
	}
	field := func(name string) resolvedField {
		t.Helper()
		resolved, resolveErr := resolveField(&configuration, model, name)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		return resolved
	}

	instant := time.Date(2026, 8, 8, 12, 30, 0, 123_000_000, time.FixedZone("plus-two", 2*60*60))
	encodeChecks := []struct {
		name  string
		value any
		want  any
	}{
		{"active", true, int64(1)},
		{"count", 7, int64(7)},
		{"created", instant, "2026-08-08T10:30:00.123Z"},
		{"labels", []string{"one", "two"}, `["one","two"]`},
		{"metadata", map[string]any{"enabled": true}, `{"enabled":true}`},
		{"parentId", "42", int64(42)},
		{"scores", []float64{1, 2.5}, `[1,2.5]`},
		{"transformed", "mixed", "MIXED"},
	}
	for _, check := range encodeChecks {
		got, err := encodeValue(&configuration, field(check.name), check.value)
		if err != nil {
			t.Fatalf("encode %s: %v", check.name, err)
		}
		if !reflect.DeepEqual(got, check.want) {
			t.Fatalf("encode %s = %#v, want %#v", check.name, got, check.want)
		}
	}

	decodeChecks := []struct {
		name  string
		value any
		want  any
	}{
		{"active", []byte("1"), true},
		{"count", []byte("7"), 7},
		{"created", []byte("2026-08-08 10:30:00.1234567"), time.Date(2026, 8, 8, 10, 30, 0, 123_456_700, time.UTC)},
		{"labels", []byte(`["one","two"]`), []string{"one", "two"}},
		{"metadata", []byte(`{"enabled":true}`), map[string]any{"enabled": true}},
		{"parentId", int64(42), "42"},
		{"scores", []byte(`[1,2.5]`), []float64{1, 2.5}},
		{"transformed", []byte("MIXED"), "decoded:MIXED"},
	}
	for _, check := range decodeChecks {
		got, err := decodeValue(&configuration, field(check.name), check.value)
		if err != nil {
			t.Fatalf("decode %s: %v", check.name, err)
		}
		if !reflect.DeepEqual(got, check.want) {
			t.Fatalf("decode %s = %#v, want %#v", check.name, got, check.want)
		}
	}
}

func TestMSSQLCodecRejectsMalformedDriverValues(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"scalar": {Fields: map[string]storage.FieldAttribute{
			"active": {Type: storage.FieldBoolean}, "created": {Type: storage.FieldDate}, "metadata": {Type: storage.FieldJSON},
		}},
	}}
	configurationValue, err := normalizeOptions(Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	configuration := &configurationValue
	model, err := resolveModel(configuration, "scalar")
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		name  string
		value any
	}{
		{"active", "maybe"},
		{"created", "not-a-date"},
		{"metadata", "{"},
	} {
		field, err := resolveField(configuration, model, check.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeValue(configuration, field, check.value); err == nil {
			t.Fatalf("decode %s unexpectedly succeeded", check.name)
		}
	}
}
