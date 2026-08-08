package postgres

import (
	"reflect"
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
	want := `(("count" >= $4 AND ("note" NOT IN ($5) AND "note" IS NOT NULL)) AND "name" LIKE $6)`
	if where != want {
		t.Fatalf("where:\n%s\nwant:\n%s", where, want)
	}
	if !reflect.DeepEqual(args, []any{int64(2), "hidden", "%needle%"}) {
		t.Fatalf("args = %#v", args)
	}
}

func TestBuildMembershipNullAndEmptyGolden(t *testing.T) {
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
		{"null-in", storage.OpIn, []any{nil, "x"}, `("note" IN ($1) OR "note" IS NULL)`, []any{"x"}},
		{"null-not-in", storage.OpNotIn, []any{nil, "x"}, `("note" NOT IN ($1) AND "note" IS NOT NULL)`, []any{"x"}},
		{"nonnull-not-in", storage.OpNotIn, []any{"x"}, `("note" NOT IN ($1) OR "note" IS NULL)`, []any{"x"}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			where, args, err := buildWhere(configuration, model, []storage.Where{{
				Field: "note", Operator: check.operator, Value: check.value,
			}}, 1)
			if err != nil {
				t.Fatal(err)
			}
			if where != check.want || !reflect.DeepEqual(args, check.args) {
				t.Fatalf("where=%q args=%#v, want %q %#v", where, args, check.want, check.args)
			}
		})
	}
}

func TestAllWhereOperatorsGolden(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		name  string
		where storage.Where
		want  string
		args  []any
	}{
		{"eq", storage.Where{Field: "name", Value: "one"}, `"name" = $1`, []any{"one"}},
		{"eq-null", storage.Where{Field: "note", Value: nil}, `"note" IS NULL`, nil},
		{"ne", storage.Where{Field: "name", Operator: storage.OpNe, Value: "one"}, `("name" IS NULL OR "name" <> $1)`, []any{"one"}},
		{"ne-null", storage.Where{Field: "note", Operator: storage.OpNe, Value: nil}, `"note" IS NOT NULL`, nil},
		{"lt", storage.Where{Field: "count", Operator: storage.OpLt, Value: 2}, `"count" < $1`, []any{int64(2)}},
		{"lte", storage.Where{Field: "count", Operator: storage.OpLTE, Value: 2}, `"count" <= $1`, []any{int64(2)}},
		{"gt", storage.Where{Field: "count", Operator: storage.OpGt, Value: 2}, `"count" > $1`, []any{int64(2)}},
		{"gte", storage.Where{Field: "count", Operator: storage.OpGTE, Value: 2}, `"count" >= $1`, []any{int64(2)}},
		{"in", storage.Where{Field: "name", Operator: storage.OpIn, Value: []string{"a", "b"}}, `("name" IN ($1, $2))`, []any{"a", "b"}},
		{"not-in", storage.Where{Field: "name", Operator: storage.OpNotIn, Value: []string{"a"}}, `("name" NOT IN ($1) OR "name" IS NULL)`, []any{"a"}},
		{"contains", storage.Where{Field: "name", Operator: storage.OpContains, Value: ".*"}, `"name" LIKE $1`, []any{"%.*%"}},
		{"starts", storage.Where{Field: "name", Operator: storage.OpStartsWith, Value: "pre"}, `"name" LIKE $1`, []any{"pre%"}},
		{"ends", storage.Where{Field: "name", Operator: storage.OpEndsWith, Value: "post"}, `"name" LIKE $1`, []any{"%post"}},
		{"insensitive", storage.Where{Field: "name", Value: "Case", Mode: storage.Insensitive}, `LOWER("name") = LOWER($1)`, []any{"Case"}},
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
		})
	}
}

func TestInsensitivePatternOperatorsUsePostgresILIKEWithoutEscapingWildcards(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		operator storage.Operator
		value    string
		wantArg  string
	}{
		{storage.OpContains, `%min_`, `%%min_%`},
		{storage.OpStartsWith, `adm_n%`, `adm_n%%`},
		{storage.OpEndsWith, `%OWNER_`, `%%OWNER_`},
	}
	for _, check := range checks {
		where, args, err := buildWhere(configuration, model, []storage.Where{{
			Field: "name", Operator: check.operator, Value: check.value, Mode: storage.Insensitive,
		}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if where != `"name" ILIKE $1` || !reflect.DeepEqual(args, []any{check.wantArg}) {
			t.Fatalf("%s: where=%q args=%#v", check.operator, where, args)
		}
	}
}

func TestBuildJSONBArrayContainsGolden(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		field string
		value any
		mode  storage.ComparisonMode
		want  string
		args  []any
	}{
		{
			field: "labels", value: "ADMIN", mode: storage.Insensitive,
			want: `EXISTS (SELECT 1 FROM jsonb_array_elements_text("labels") AS item(value) WHERE LOWER(item.value) = LOWER($1))`,
			args: []any{"ADMIN"},
		},
		{
			field: "scores", value: 2.5,
			want: `EXISTS (SELECT 1 FROM jsonb_array_elements("scores") AS item(value) WHERE item.value = to_jsonb($1::double precision))`,
			args: []any{2.5},
		},
	}
	for _, check := range checks {
		where, args, err := buildWhere(configuration, model, []storage.Where{{
			Field: check.field, Operator: storage.OpContains, Value: check.value, Mode: check.mode,
		}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		if where != check.want || !reflect.DeepEqual(args, check.args) {
			t.Fatalf("%s: where=%q args=%#v", check.field, where, args)
		}
	}
}

func TestJSONBEqualityAndArrayMutationsCastDriverNeutralJSONText(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	checks := []struct {
		field string
		value any
		want  any
	}{
		{"data", map[string]any{"enabled": true}, `{"enabled":true}`},
		{"labels", []string{"admin", "member"}, `["admin","member"]`},
		{"scores", []float64{1, 2.5}, `[1,2.5]`},
	}
	for _, check := range checks {
		where, args, err := buildWhere(configuration, model, []storage.Where{{Field: check.field, Value: check.value}}, 1)
		if err != nil {
			t.Fatal(err)
		}
		wantWhere := quoteIdentifier(check.field) + ` = $1::jsonb`
		if where != wantWhere || !reflect.DeepEqual(args, []any{check.want}) {
			t.Fatalf("%s: where=%q args=%#v", check.field, where, args)
		}
	}

	mutation, err := encodeUpdate(configuration, model, storage.Record{
		"labels": []string{"owner"}, "scores": []float64{3.5},
	})
	if err != nil {
		t.Fatal(err)
	}
	assignments, args, err := mutationAssignments(configuration, model, mutation, 1)
	if err != nil {
		t.Fatal(err)
	}
	wantAssignments := []string{
		`"labels" = $1::jsonb`, `"__single_present__labels" = TRUE`,
		`"scores" = $2::jsonb`, `"__single_present__scores" = TRUE`,
	}
	if !reflect.DeepEqual(assignments, wantAssignments) || !reflect.DeepEqual(args, []any{`["owner"]`, `[3.5]`}) {
		t.Fatalf("assignments=%#v args=%#v", assignments, args)
	}
}

func TestBuildJSONContainsPreservesJSONValueTypes(t *testing.T) {
	configuration, model := testConfiguration(t, querySchema())
	where, args, err := buildWhere(configuration, model, []storage.Where{{
		Field: "data", Operator: storage.OpContains, Value: "Admin", Mode: storage.Insensitive,
	}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := `((jsonb_typeof("data") = 'string' AND POSITION(LOWER($1) IN LOWER(("data" #>> '{}'))) > 0) OR (jsonb_typeof("data") = 'array' AND EXISTS (SELECT 1 FROM jsonb_array_elements("data") AS item(value) WHERE jsonb_typeof(item.value) = 'string' AND LOWER(item.value #>> '{}') = LOWER($1))))`
	if where != want || !reflect.DeepEqual(args, []any{"Admin"}) {
		t.Fatalf("where=%q args=%#v", where, args)
	}
}

func TestPhysicalAliasCollisionUsesPhysicalReverseResolution(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {Fields: map[string]storage.FieldAttribute{
			"first":  {Type: storage.FieldString, FieldName: "second"},
			"second": {Type: storage.FieldString, FieldName: "stored_second"},
		}},
	}}
	configuration, model := testConfiguration(t, schema)
	mutation, err := encodeCreate(configuration, model, storage.Record{
		"id": "one", "first": "first-value", "second": "second-value",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	assignments, args, err := mutationAssignments(configuration, model, mutation, 1)
	if err != nil {
		t.Fatal(err)
	}
	wantAssignments := []string{
		`"id" = $1`,
		`"second" = $2`, `"__single_present__first" = TRUE`,
		`"stored_second" = $3`, `"__single_present__second" = TRUE`,
	}
	if !reflect.DeepEqual(assignments, wantAssignments) || !reflect.DeepEqual(args, []any{"one", "first-value", "second-value"}) {
		t.Fatalf("assignments=%#v args=%#v", assignments, args)
	}
}

func TestUUIDPredicatesCastThroughTextForDriverPortability(t *testing.T) {
	configuration, err := normalizeOptions(Options{Schema: querySchema(), IDType: UUIDID})
	if err != nil {
		t.Fatal(err)
	}
	model, err := resolveModel(&configuration, "thing")
	if err != nil {
		t.Fatal(err)
	}
	values := []string{
		"018fca23-7b2f-4cc0-98c5-001122334455",
		"018fca23-7b2f-4cc0-98c5-001122334456",
	}
	where, args, err := buildWhere(&configuration, model, []storage.Where{{
		Field: "id", Operator: storage.OpIn, Value: values,
	}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := `("id" IN ($1::text::uuid, $2::text::uuid))`
	if where != want || !reflect.DeepEqual(args, []any{values[0], values[1]}) {
		t.Fatalf("where=%q args=%#v", where, args)
	}
}

func querySchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {
			ModelName: "thing",
			Fields: map[string]storage.FieldAttribute{
				"count":  {Type: storage.FieldNumber, Required: storage.Bool(false)},
				"data":   {Type: storage.FieldJSON, Required: storage.Bool(false)},
				"labels": {Type: storage.FieldStringArray, Required: storage.Bool(false)},
				"name":   {Type: storage.FieldString},
				"note":   {Type: storage.FieldString, Required: storage.Bool(false)},
				"scores": {Type: storage.FieldNumberArray, Required: storage.Bool(false)},
			},
		},
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
