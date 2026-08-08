package mysql

import (
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestBuildWhereGolden(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	where, args, err := buildWhere(configuration, model, []storage.Where{
		{Field: "count", Operator: storage.OpGTE, Value: 2},
		{Field: "name", Operator: storage.OpContains, Value: "needle", Connector: storage.Or},
		{Field: "note", Operator: storage.OpNotIn, Value: []any{nil, "hidden"}, Connector: storage.And},
	}, 4)
	if err != nil {
		t.Fatal(err)
	}
	want := "((`count` >= ? AND (BINARY `note` NOT IN (BINARY ?) AND `note` IS NOT NULL)) AND LOCATE(BINARY ?, BINARY `name`) > 0)"
	if where != want || !reflect.DeepEqual(args, []any{int64(2), "hidden", "needle"}) {
		t.Fatalf("where=%q args=%#v, want %q", where, args, want)
	}
	assertPlaceholderCount(t, where, args)
}

func TestAllWhereOperatorsGolden(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		name  string
		where storage.Where
		want  string
		args  []any
	}{
		{"eq", storage.Where{Field: "name", Value: "one"}, "BINARY `name` = BINARY ?", []any{"one"}},
		{"eq-null", storage.Where{Field: "note", Value: nil}, "`note` IS NULL", nil},
		{"ne", storage.Where{Field: "name", Operator: storage.OpNe, Value: "one"}, "(`name` IS NULL OR BINARY `name` <> BINARY ?)", []any{"one"}},
		{"ne-null", storage.Where{Field: "note", Operator: storage.OpNe, Value: nil}, "`note` IS NOT NULL", nil},
		{"lt", storage.Where{Field: "count", Operator: storage.OpLt, Value: 2}, "`count` < ?", []any{int64(2)}},
		{"lte", storage.Where{Field: "count", Operator: storage.OpLTE, Value: 2}, "`count` <= ?", []any{int64(2)}},
		{"gt", storage.Where{Field: "count", Operator: storage.OpGt, Value: 2}, "`count` > ?", []any{int64(2)}},
		{"gte", storage.Where{Field: "count", Operator: storage.OpGTE, Value: 2}, "`count` >= ?", []any{int64(2)}},
		{"in", storage.Where{Field: "name", Operator: storage.OpIn, Value: []string{"a", "b"}}, "(BINARY `name` IN (BINARY ?, BINARY ?))", []any{"a", "b"}},
		{"not-in", storage.Where{Field: "name", Operator: storage.OpNotIn, Value: []string{"a"}}, "(BINARY `name` NOT IN (BINARY ?) OR `name` IS NULL)", []any{"a"}},
		{"contains", storage.Where{Field: "name", Operator: storage.OpContains, Value: ".*"}, "LOCATE(BINARY ?, BINARY `name`) > 0", []any{".*"}},
		{"starts", storage.Where{Field: "name", Operator: storage.OpStartsWith, Value: "pre"}, "LOCATE(BINARY ?, BINARY `name`) = 1", []any{"pre"}},
		{"ends", storage.Where{Field: "name", Operator: storage.OpEndsWith, Value: "post"}, "LOCATE(REVERSE(BINARY ?), REVERSE(BINARY `name`)) = 1", []any{"post"}},
		{"insensitive", storage.Where{Field: "name", Value: "Case", Mode: storage.Insensitive}, "LOWER(`name`) = LOWER(?)", []any{"Case"}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			where, args, err := buildWhere(configuration, model, []storage.Where{check.where}, 1)
			if err != nil {
				t.Fatal(err)
			}
			if where != check.want || !reflect.DeepEqual(args, check.args) {
				t.Fatalf("where=%q args=%#v, want %q %#v", where, args, check.want, check.args)
			}
			assertPlaceholderCount(t, where, args)
		})
	}
}

func TestMembershipNullAndEmptyGolden(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		name     string
		operator storage.Operator
		value    []any
		want     string
		args     []any
	}{
		{"empty-in", storage.OpIn, []any{}, "FALSE", nil},
		{"empty-not-in", storage.OpNotIn, []any{}, "TRUE", nil},
		{"null-in", storage.OpIn, []any{nil, "x"}, "(BINARY `note` IN (BINARY ?) OR `note` IS NULL)", []any{"x"}},
		{"null-not-in", storage.OpNotIn, []any{nil, "x"}, "(BINARY `note` NOT IN (BINARY ?) AND `note` IS NOT NULL)", []any{"x"}},
		{"nonnull-not-in", storage.OpNotIn, []any{"x"}, "(BINARY `note` NOT IN (BINARY ?) OR `note` IS NULL)", []any{"x"}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			where, args, err := buildWhere(configuration, model, []storage.Where{{Field: "note", Operator: check.operator, Value: check.value}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			if where != check.want || !reflect.DeepEqual(args, check.args) {
				t.Fatalf("where=%q args=%#v, want %q %#v", where, args, check.want, check.args)
			}
			assertPlaceholderCount(t, where, args)
		})
	}
}

func TestJSONContainsGoldenAndPlaceholderBehavior(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		name  string
		where storage.Where
		want  string
		args  []any
	}{
		{
			"string-array-insensitive",
			storage.Where{Field: "labels", Operator: storage.OpContains, Value: "ADMIN", Mode: storage.Insensitive},
			"JSON_CONTAINS(LOWER(CAST(`labels` AS CHAR)), JSON_QUOTE(LOWER(?)), '$') = 1",
			[]any{"ADMIN"},
		},
		{
			"string-array-sensitive",
			storage.Where{Field: "labels", Operator: storage.OpContains, Value: "Admin"},
			"JSON_CONTAINS(`labels`, ?, '$') = 1",
			[]any{`"Admin"`},
		},
		{
			"number-array",
			storage.Where{Field: "scores", Operator: storage.OpContains, Value: 2.5},
			"JSON_CONTAINS(`scores`, ?, '$') = 1",
			[]any{"2.5"},
		},
		{
			"json-string-insensitive",
			storage.Where{Field: "data", Operator: storage.OpContains, Value: "Admin", Mode: storage.Insensitive},
			"((JSON_TYPE(`data`) = 'STRING' AND LOCATE(LOWER(?), LOWER(JSON_UNQUOTE(`data`))) > 0) OR (JSON_TYPE(`data`) = 'ARRAY' AND JSON_CONTAINS(`data`, JSON_QUOTE(LOWER(?)), '$') = 1))",
			[]any{"Admin", "Admin"},
		},
		{
			"json-number",
			storage.Where{Field: "data", Operator: storage.OpContains, Value: 3},
			"(JSON_TYPE(`data`) = 'ARRAY' AND JSON_CONTAINS(`data`, ?, '$') = 1)",
			[]any{"3"},
		},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			where, args, err := buildWhere(configuration, model, []storage.Where{check.where}, 1)
			if err != nil {
				t.Fatal(err)
			}
			if where != check.want || !reflect.DeepEqual(args, check.args) {
				t.Fatalf("where=%q args=%#v, want %q %#v", where, args, check.want, check.args)
			}
			assertPlaceholderCount(t, where, args)
		})
	}
}

func TestPhysicalAliasCollisionUsesPhysicalReverseResolution(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {Fields: map[string]storage.FieldAttribute{
			"first": {Type: storage.FieldString, FieldName: "second"}, "second": {Type: storage.FieldString, FieldName: "stored_second"},
		}},
	}}
	configuration, model := testConfiguration(t, schema)
	mutation, err := encodeCreate(configuration, model, storage.Record{"id": "one", "first": "first-value", "second": "second-value"}, true)
	if err != nil {
		t.Fatal(err)
	}
	assignments, args, err := mutationAssignments(configuration, model, mutation, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"`id` = ?", "`second` = ?", "`__single_present__first` = TRUE", "`stored_second` = ?", "`__single_present__second` = TRUE",
	}
	if !reflect.DeepEqual(assignments, want) || !reflect.DeepEqual(args, []any{"one", "first-value", "second-value"}) {
		t.Fatalf("assignments=%#v args=%#v", assignments, args)
	}
}

func TestUUIDPredicatesRemainDriverNeutralText(t *testing.T) {
	configuration, err := normalizeOptions(Options{Schema: querySchema(), IDType: UUIDID})
	if err != nil {
		t.Fatal(err)
	}
	model, err := resolveModel(&configuration, "thing")
	if err != nil {
		t.Fatal(err)
	}
	values := []string{"018fca23-7b2f-4cc0-98c5-001122334455", "018fca23-7b2f-4cc0-98c5-001122334456"}
	where, args, err := buildWhere(&configuration, model, []storage.Where{{Field: "id", Operator: storage.OpIn, Value: values}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := "(BINARY `id` IN (BINARY ?, BINARY ?))"
	if where != want || !reflect.DeepEqual(args, []any{values[0], values[1]}) {
		t.Fatalf("where=%q args=%#v", where, args)
	}
}

func querySchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {ModelName: "thing", Fields: map[string]storage.FieldAttribute{
			"count": {Type: storage.FieldNumber, Required: storage.Bool(false)}, "data": {Type: storage.FieldJSON, Required: storage.Bool(false)},
			"labels": {Type: storage.FieldStringArray, Required: storage.Bool(false)}, "name": {Type: storage.FieldString},
			"note": {Type: storage.FieldString, Required: storage.Bool(false)}, "scores": {Type: storage.FieldNumberArray, Required: storage.Bool(false)},
		}},
	}}
}

func testConfiguration(t *testing.T, schema storage.Schema) (*config, resolvedModel) {
	t.Helper()
	configuration, err := normalizeOptions(Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	model, err := resolveModel(&configuration, "thing")
	if err != nil {
		t.Fatal(err)
	}
	return &configuration, model
}

func assertPlaceholderCount(t *testing.T, query string, args []any) {
	t.Helper()
	if count := strings.Count(query, "?"); count != len(args) {
		t.Fatalf("query has %d placeholders for %d args: %s", count, len(args), query)
	}
}
