package mongodb

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestPlanSchemaGolden(t *testing.T) {
	plan, err := PlanSchema(storage.CoreSchema())
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "schema.golden.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.JavaScript(); got != string(golden) {
		t.Fatalf("schema artifact mismatch\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}
	if len(plan.Collections) != 5 || plan.Collections[0].Name != "rateLimit" {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestPlanSchemaAliasesPluralAndDisabled(t *testing.T) {
	schema := storage.Schema{UsePlural: true, Models: map[string]storage.ModelSchema{
		"widget": {
			ModelName: "thing",
			Fields: map[string]storage.FieldAttribute{
				"slug": {Type: storage.FieldString, FieldName: "handle", Unique: true},
			},
		},
		"disabled": {DisableMigrations: true, Fields: map[string]storage.FieldAttribute{
			"value": {Type: storage.FieldString},
		}},
	}}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	want := SchemaPlan{Collections: []CollectionPlan{{
		Model: "widget", Name: "things", Indexes: []IndexPlan{{
			Name: "single_things_handle_idx", Field: "handle", Unique: true,
		}},
	}}}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("plan = %#v\nwant = %#v", plan, want)
	}
}
