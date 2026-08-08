package postgres

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestPlanSchemaPostgresTypesIndexesAndDeferredForeignKeys(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"parent": {
			Order: 1,
			Fields: map[string]storage.FieldAttribute{
				"active":   {Type: storage.FieldBoolean},
				"created":  {Type: storage.FieldDate},
				"email":    {Type: storage.FieldString, Unique: true},
				"labels":   {Type: storage.FieldStringArray, Required: storage.Bool(false)},
				"metadata": {Type: storage.FieldJSON, Required: storage.Bool(false)},
				"role":     {Type: storage.FieldEnum, Enum: []string{"member", "owner"}},
			},
		},
		"child": {
			Order: 2,
			Fields: map[string]storage.FieldAttribute{
				"parentId": {
					Type: storage.FieldString, Index: true,
					References: &storage.Reference{Model: "parent", Field: "id", OnDelete: storage.Cascade},
				},
				"score": {Type: storage.FieldNumber},
			},
		},
	}}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan, repeated) {
		t.Fatal("schema plan is not deterministic")
	}
	code := plan.SQL()
	for _, expected := range []string{
		`"active" BOOLEAN NOT NULL`,
		`"created" TIMESTAMPTZ NOT NULL`,
		`"labels" JSONB`,
		`"metadata" JSONB`,
		`"score" INTEGER NOT NULL`,
		`CHECK ("role" IN ('member', 'owner'))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS "single_parent_email_idx"`,
		`CREATE INDEX IF NOT EXISTS "single_child_parentId_idx"`,
		`FROM pg_constraint`,
		`CREATE TABLE IF NOT EXISTS "public"."parent"`,
		`ALTER TABLE "public"."child" ADD CONSTRAINT "single_child_parentId_fk"`,
		`REFERENCES "public"."parent" ("id") ON DELETE CASCADE`,
	} {
		if !strings.Contains(code, expected) {
			t.Fatalf("schema is missing %q:\n%s", expected, code)
		}
	}
	firstForeignKey := strings.Index(code, "ALTER TABLE")
	lastCreateTable := strings.LastIndex(code, "CREATE TABLE")
	lastIndex := strings.LastIndex(code, "CREATE INDEX")
	if firstForeignKey < lastCreateTable || firstForeignKey < lastIndex {
		t.Fatalf("foreign key was not deferred:\n%s", code)
	}
}

func TestPlanSchemaQuotesDatabaseSchemaAndTableSeparately(t *testing.T) {
	schema := relationSchema()
	child := schema.Models["child"]
	parentID := child.Fields["parentId"]
	parentID.Index = true
	child.Fields["parentId"] = parentID
	schema.Models["child"] = child
	plan, err := PlanSchemaWithDatabaseSchema(schema, TextID, `auth"tenant`)
	if err != nil {
		t.Fatal(err)
	}
	code := plan.SQL()
	for _, expected := range []string{
		`CREATE TABLE IF NOT EXISTS "auth""tenant"."parent"`,
		`ON "auth""tenant"."child" ("parentId")`,
		`to_regclass('"auth""tenant"."child"')`,
		`ALTER TABLE "auth""tenant"."child"`,
		`REFERENCES "auth""tenant"."parent" ("id")`,
	} {
		if !strings.Contains(code, expected) {
			t.Fatalf("schema is missing %q:\n%s", expected, code)
		}
	}
	if strings.Contains(code, `"auth""tenant.child"`) {
		t.Fatalf("schema and table were quoted as one identifier:\n%s", code)
	}
}

func TestSchemaQualifiedModelNamesOverrideConfiguredDatabaseSchema(t *testing.T) {
	schema := relationSchema()
	parent := schema.Models["parent"]
	parent.ModelName = `internal.parents`
	schema.Models["parent"] = parent
	child := schema.Models["child"]
	child.ModelName = `internal.children`
	schema.Models["child"] = child

	plan, err := PlanSchemaWithDatabaseSchema(schema, TextID, "ignored_default")
	if err != nil {
		t.Fatal(err)
	}
	code := plan.SQL()
	for _, expected := range []string{
		`CREATE TABLE IF NOT EXISTS "internal"."parents"`,
		`CREATE TABLE IF NOT EXISTS "internal"."children"`,
		`ALTER TABLE "internal"."children"`,
		`REFERENCES "internal"."parents" ("id")`,
	} {
		if !strings.Contains(code, expected) {
			t.Fatalf("schema is missing %q:\n%s", expected, code)
		}
	}
	if strings.Contains(code, `"ignored_default"`) || strings.Contains(code, `"internal.parents"`) {
		t.Fatalf("qualified model name was not split correctly:\n%s", code)
	}
}

func TestSchemaQualifiedModelNameRejectsAmbiguousParts(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {ModelName: "catalog.internal.things", Fields: map[string]storage.FieldAttribute{}},
	}}
	_, err := PlanSchema(schema)
	if !errors.Is(err, storage.ErrInvalidQuery) {
		t.Fatalf("ambiguous qualified model error = %v", err)
	}
}

func TestPlanSchemaSupportsCyclicReferences(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"left": {Fields: map[string]storage.FieldAttribute{
			"rightId": {Type: storage.FieldString, References: &storage.Reference{Model: "right", Field: "id"}},
		}},
		"right": {Fields: map[string]storage.FieldAttribute{
			"leftId": {Type: storage.FieldString, References: &storage.Reference{Model: "left", Field: "id"}},
		}},
	}}
	plan, err := PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	code := plan.SQL()
	if strings.Count(code, "ALTER TABLE") != 2 || strings.Count(code, "CREATE TABLE") != 2 {
		t.Fatalf("cyclic plan:\n%s", code)
	}
}

func TestPostgresObjectNamesRespectIdentifierLimit(t *testing.T) {
	name := postgresObjectName("idx", strings.Repeat("table", 12), strings.Repeat("field", 12))
	if len(name) > 63 {
		t.Fatalf("object name has %d bytes: %q", len(name), name)
	}
	if name != postgresObjectName("idx", strings.Repeat("table", 12), strings.Repeat("field", 12)) {
		t.Fatal("object name is not deterministic")
	}
}

func TestPlanSchemaIDTypesPropagateToReferences(t *testing.T) {
	schema := relationSchema()
	checks := []struct {
		idType IDType
		idDDL  string
		fkDDL  string
	}{
		{TextID, `"id" TEXT NOT NULL PRIMARY KEY`, `"parentId" TEXT NOT NULL`},
		{UUIDID, `"id" UUID DEFAULT pg_catalog.gen_random_uuid() NOT NULL PRIMARY KEY`, `"parentId" UUID NOT NULL`},
		{SerialID, `"id" INTEGER GENERATED BY DEFAULT AS IDENTITY NOT NULL PRIMARY KEY`, `"parentId" INTEGER NOT NULL`},
	}
	for _, check := range checks {
		plan, err := PlanSchemaWithIDType(schema, check.idType)
		if err != nil {
			t.Fatal(err)
		}
		code := plan.SQL()
		if !strings.Contains(code, check.idDDL) || !strings.Contains(code, check.fkDDL) {
			t.Fatalf("%s ID schema:\n%s", check.idType, code)
		}
	}
}

func TestCoreDateFactoriesReceiveDatabaseDefaults(t *testing.T) {
	plan, err := PlanSchema(storage.CoreSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.SQL(), `"createdAt" TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL`) {
		t.Fatalf("core schema lacks timestamp default:\n%s", plan.SQL())
	}
}

func TestPlanSchemaRejectsIdentifiersPostgresWouldTruncate(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		strings.Repeat("model", 20): {Fields: map[string]storage.FieldAttribute{}},
	}}
	_, err := PlanSchema(schema)
	if !errors.Is(err, storage.ErrInvalidQuery) {
		t.Fatalf("long identifier error = %v", err)
	}
}
