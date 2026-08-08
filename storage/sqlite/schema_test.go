package sqlite_test

import (
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"
)

func TestPlanSchemaUsesPhysicalNamesConstraintsAndPresenceColumns(t *testing.T) {
	schema := adaptertest.ContractSchema()
	schema.UsePlural = true
	user := schema.Models["user"]
	user.ModelName = "member"
	email := user.Fields["email"]
	email.FieldName = "email_address"
	user.Fields["email"] = email
	schema.Models["user"] = user

	plan, err := sqliteadapter.PlanSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	code := plan.SQL()
	for _, expected := range []string{
		`CREATE TABLE IF NOT EXISTS "members"`,
		`"email_address" TEXT NOT NULL`,
		`"__single_present__email" INTEGER NOT NULL DEFAULT 0`,
		`CREATE UNIQUE INDEX IF NOT EXISTS "single_members_email_address"`,
		`REFERENCES "members" ("id") ON DELETE CASCADE`,
	} {
		if !strings.Contains(code, expected) {
			t.Fatalf("schema plan is missing %q:\n%s", expected, code)
		}
	}
}

func TestEnsureSchemaIsIdempotent(t *testing.T) {
	db := openDatabase(t)
	adapter, err := sqliteadapter.New(db, sqliteadapter.Options{Schema: storage.CoreSchema()})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureSchemaReconcilesAdditiveFieldThenNoops(t *testing.T) {
	database, trace := openTracedSQLiteDatabase(t)
	if _, err := database.ExecContext(t.Context(), `CREATE TABLE "parent" ("id" TEXT NOT NULL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(), `CREATE TABLE "child" ("id" TEXT NOT NULL PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"child": {Fields: map[string]storage.FieldAttribute{
			"parentId": {
				Type:       storage.FieldString,
				Required:   storage.Bool(false),
				Index:      true,
				References: &storage.Reference{Model: "parent", Field: "id", OnDelete: storage.Cascade},
			},
		}},
		"parent": {Fields: map[string]storage.FieldAttribute{}},
	}}
	adapter, err := sqliteadapter.New(database, sqliteadapter.Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	trace.Reset()
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	first := trace.Snapshot()
	foundAlter, foundIndex := false, false
	for _, statement := range first {
		foundAlter = foundAlter || strings.HasPrefix(statement.SQL, "ALTER TABLE")
		foundIndex = foundIndex || strings.HasPrefix(statement.SQL, "CREATE INDEX")
	}
	if !foundAlter || !foundIndex {
		t.Fatalf("additive migration SQL = %#v", first)
	}

	trace.Reset()
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, statement := range trace.Snapshot() {
		upper := strings.ToUpper(strings.TrimSpace(statement.SQL))
		if strings.HasPrefix(upper, "ALTER ") || strings.HasPrefix(upper, "CREATE ") || strings.HasPrefix(upper, "DROP ") {
			t.Fatalf("second EnsureSchema emitted DDL: %q", statement.SQL)
		}
	}
}
