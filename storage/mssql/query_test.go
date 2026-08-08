package mssql

import (
	"reflect"
	"regexp"
	"strconv"
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
	want := "(([count] >= @p4 AND ([note] COLLATE Latin1_General_100_BIN2 NOT IN (@p5 COLLATE Latin1_General_100_BIN2) AND [note] IS NOT NULL)) AND CHARINDEX(@p6 COLLATE Latin1_General_100_BIN2, [name] COLLATE Latin1_General_100_BIN2) > 0)"
	if where != want || !reflect.DeepEqual(args, []any{int64(2), "hidden", "needle"}) {
		t.Fatalf("where=%q args=%#v, want %q", where, args, want)
	}
	assertParameterSequence(t, where, 4, args)
}

func TestAllWhereOperatorsGolden(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		name  string
		where storage.Where
		want  string
		args  []any
	}{
		{"eq", storage.Where{Field: "name", Value: "one"}, "[name] COLLATE Latin1_General_100_BIN2 = @p1 COLLATE Latin1_General_100_BIN2", []any{"one"}},
		{"eq-null", storage.Where{Field: "note", Value: nil}, "[note] IS NULL", nil},
		{"ne", storage.Where{Field: "name", Operator: storage.OpNe, Value: "one"}, "([name] IS NULL OR [name] COLLATE Latin1_General_100_BIN2 <> @p1 COLLATE Latin1_General_100_BIN2)", []any{"one"}},
		{"ne-null", storage.Where{Field: "note", Operator: storage.OpNe, Value: nil}, "[note] IS NOT NULL", nil},
		{"lt", storage.Where{Field: "count", Operator: storage.OpLt, Value: 2}, "[count] < @p1", []any{int64(2)}},
		{"lte", storage.Where{Field: "count", Operator: storage.OpLTE, Value: 2}, "[count] <= @p1", []any{int64(2)}},
		{"gt", storage.Where{Field: "count", Operator: storage.OpGt, Value: 2}, "[count] > @p1", []any{int64(2)}},
		{"gte", storage.Where{Field: "count", Operator: storage.OpGTE, Value: 2}, "[count] >= @p1", []any{int64(2)}},
		{"in", storage.Where{Field: "name", Operator: storage.OpIn, Value: []string{"a", "b"}}, "([name] COLLATE Latin1_General_100_BIN2 IN (@p1 COLLATE Latin1_General_100_BIN2, @p2 COLLATE Latin1_General_100_BIN2))", []any{"a", "b"}},
		{"not-in", storage.Where{Field: "name", Operator: storage.OpNotIn, Value: []string{"a"}}, "([name] COLLATE Latin1_General_100_BIN2 NOT IN (@p1 COLLATE Latin1_General_100_BIN2) OR [name] IS NULL)", []any{"a"}},
		{"contains", storage.Where{Field: "name", Operator: storage.OpContains, Value: ".*"}, "CHARINDEX(@p1 COLLATE Latin1_General_100_BIN2, [name] COLLATE Latin1_General_100_BIN2) > 0", []any{".*"}},
		{"starts", storage.Where{Field: "name", Operator: storage.OpStartsWith, Value: "pre"}, "CHARINDEX(@p1 COLLATE Latin1_General_100_BIN2, [name] COLLATE Latin1_General_100_BIN2) = 1", []any{"pre"}},
		{"ends", storage.Where{Field: "name", Operator: storage.OpEndsWith, Value: "post"}, "CHARINDEX(REVERSE(@p1 COLLATE Latin1_General_100_BIN2), REVERSE([name] COLLATE Latin1_General_100_BIN2)) = 1", []any{"post"}},
		{"insensitive", storage.Where{Field: "name", Value: "Case", Mode: storage.Insensitive}, "LOWER([name]) = LOWER(@p1)", []any{"Case"}},
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
			assertParameterSequence(t, where, 1, args)
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
		{"empty-in", storage.OpIn, []any{}, "1 = 0", nil},
		{"empty-not-in", storage.OpNotIn, []any{}, "1 = 1", nil},
		{"null-in", storage.OpIn, []any{nil, "x"}, "([note] COLLATE Latin1_General_100_BIN2 IN (@p1 COLLATE Latin1_General_100_BIN2) OR [note] IS NULL)", []any{"x"}},
		{"null-not-in", storage.OpNotIn, []any{nil, "x"}, "([note] COLLATE Latin1_General_100_BIN2 NOT IN (@p1 COLLATE Latin1_General_100_BIN2) AND [note] IS NOT NULL)", []any{"x"}},
		{"nonnull-not-in", storage.OpNotIn, []any{"x"}, "([note] COLLATE Latin1_General_100_BIN2 NOT IN (@p1 COLLATE Latin1_General_100_BIN2) OR [note] IS NULL)", []any{"x"}},
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
			assertParameterSequence(t, where, 1, args)
		})
	}
}

func TestJSONAndArrayContainsGolden(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	arrayDocument := "CASE WHEN ISJSON([labels]) = 1 AND LEFT(LTRIM([labels]), 1) = '[' THEN [labels] ELSE '[]' END"
	scoreDocument := "CASE WHEN ISJSON([scores]) = 1 AND LEFT(LTRIM([scores]), 1) = '[' THEN [scores] ELSE '[]' END"
	dataDocument := "CASE WHEN ISJSON([data]) = 1 AND LEFT(LTRIM([data]), 1) = '[' THEN [data] ELSE '[]' END"
	checks := []struct {
		name  string
		where storage.Where
		want  string
		args  []any
	}{
		{
			"string-array-insensitive",
			storage.Where{Field: "labels", Operator: storage.OpContains, Value: "ADMIN", Mode: storage.Insensitive},
			"EXISTS (SELECT 1 FROM OPENJSON(" + arrayDocument + ") AS [single_item] WHERE [single_item].[type] = 1 AND LOWER([single_item].[value]) = LOWER(@p1))",
			[]any{"ADMIN"},
		},
		{
			"string-array-sensitive",
			storage.Where{Field: "labels", Operator: storage.OpContains, Value: "Admin"},
			"EXISTS (SELECT 1 FROM OPENJSON(" + arrayDocument + ") AS [single_item] WHERE [single_item].[type] = 1 AND [single_item].[value] COLLATE Latin1_General_100_BIN2 = @p1 COLLATE Latin1_General_100_BIN2)",
			[]any{"Admin"},
		},
		{
			"number-array",
			storage.Where{Field: "scores", Operator: storage.OpContains, Value: 2.5},
			"EXISTS (SELECT 1 FROM OPENJSON(" + scoreDocument + ") AS [single_item] WHERE [single_item].[type] = 2 AND TRY_CONVERT(float, [single_item].[value]) = @p1)",
			[]any{2.5},
		},
		{
			"json-string-insensitive-reuses-parameter",
			storage.Where{Field: "data", Operator: storage.OpContains, Value: "Admin", Mode: storage.Insensitive},
			"(CHARINDEX(LOWER(@p1), LOWER(JSON_VALUE(CASE WHEN ISJSON([data]) = 1 THEN [data] ELSE 'null' END, '$'))) > 0 OR EXISTS (SELECT 1 FROM OPENJSON(" + dataDocument + ") AS [single_item] WHERE [single_item].[type] = 1 AND LOWER([single_item].[value]) = LOWER(@p1)))",
			[]any{"Admin"},
		},
		{
			"json-number",
			storage.Where{Field: "data", Operator: storage.OpContains, Value: 3},
			"EXISTS (SELECT 1 FROM OPENJSON(" + dataDocument + ") AS [single_item] WHERE [single_item].[type] = 2 AND TRY_CONVERT(float, [single_item].[value]) = @p1)",
			[]any{int64(3)},
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
			assertParameterSequence(t, where, 1, args)
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
	want := []string{"[id] = @p1", "[second] = @p2", "[__single_present__first] = 1", "[stored_second] = @p3", "[__single_present__second] = 1"}
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
	want := "([id] COLLATE Latin1_General_100_BIN2 IN (@p1 COLLATE Latin1_General_100_BIN2, @p2 COLLATE Latin1_General_100_BIN2))"
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

var parameterPattern = regexp.MustCompile(`@p([0-9]+)`)

func assertParameterSequence(t *testing.T, query string, start int, args []any) {
	t.Helper()
	seen := map[int]bool{}
	for _, match := range parameterPattern.FindAllStringSubmatch(query, -1) {
		index, err := strconv.Atoi(match[1])
		if err != nil {
			t.Fatal(err)
		}
		seen[index] = true
	}
	for index := start; index < start+len(args); index++ {
		if !seen[index] {
			t.Fatalf("query is missing @p%d for args %#v: %s", index, args, query)
		}
	}
	for index := range seen {
		if index < start || index >= start+len(args) {
			t.Fatalf("query has out-of-range @p%d for args %#v: %s", index, args, query)
		}
	}
}
