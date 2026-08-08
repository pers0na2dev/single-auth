package sqlite_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"
)

func TestSQLiteMutationsBindPredicatesAndUseSingleStatements(t *testing.T) {
	adapter, statements := newMutationAdapter(t)

	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "users",
		Data:  storage.Record{"name": "alice", "value": "first"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created == nil || fmt.Sprint(created["id"]) == "" {
		t.Fatalf("created row has no generated id: %#v", created)
	}
	assertSingleSQLiteCommand(t, statements.Snapshot(), "insert")

	statements.Reset()
	found, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "users",
		Where: []storage.Where{
			{Field: "name", Value: "alice"},
			{Field: "value", Value: "first"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMutationFields(t, found, "alice", "first")
	lookup := assertSingleSQLiteCommand(t, statements.Snapshot(), "select")
	whereIndex := strings.Index(strings.ToLower(lookup.SQL), " where ")
	if whereIndex < 0 {
		t.Fatalf("lookup has no WHERE clause: %s", lookup.SQL)
	}
	predicate := strings.ToLower(lookup.SQL[whereIndex+len(" where "):])
	if limitIndex := strings.Index(predicate, " limit "); limitIndex >= 0 {
		predicate = predicate[:limitIndex]
	}
	if placeholders := strings.Count(predicate, "?"); placeholders != 2 || lookup.ArgumentCount < placeholders {
		t.Fatalf("lookup predicate placeholders = %d, arguments = %d, want two bound predicates", placeholders, lookup.ArgumentCount)
	}

	statements.Reset()
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model:  "users",
		Where:  []storage.Where{{Field: "name", Value: "alice"}},
		Update: storage.Record{"value": "second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMutationFields(t, updated, "alice", "second")
	update := assertSingleSQLiteCommand(t, statements.Snapshot(), "update")
	if !strings.Contains(strings.ToLower(update.SQL), " returning ") {
		t.Fatalf("update does not return the mutated row: %s", update.SQL)
	}

	statements.Reset()
	if err := adapter.Delete(t.Context(), storage.DeleteParams{
		Model: "users",
		Where: []storage.Where{{Field: "name", Value: "alice"}},
	}); err != nil {
		t.Fatal(err)
	}
	assertSingleSQLiteCommand(t, statements.Snapshot(), "delete")

	remaining, err := adapter.Count(t.Context(), storage.CountParams{Model: "users"})
	if err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("remaining rows = %d, want 0", remaining)
	}
}

func TestSQLiteCreateReturnsPersistedRowWithReturning(t *testing.T) {
	adapter, statements := newMutationAdapter(t)

	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "users",
		Data:  storage.Record{"name": "bob", "value": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMutationFields(t, created, "bob", "x")
	insert := assertSingleSQLiteCommand(t, statements.Snapshot(), "insert")
	if !strings.Contains(strings.ToLower(insert.SQL), " returning ") {
		t.Fatalf("insert does not return the created row: %s", insert.SQL)
	}

	persisted, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "users", Where: []storage.Where{{Field: "id", Value: created["id"]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertMutationFields(t, persisted, "bob", "x")
}

func mutationSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"users": {
			ModelName: "users",
			Fields: map[string]storage.FieldAttribute{
				"name":  {Type: storage.FieldString},
				"value": {Type: storage.FieldString},
			},
		},
	}}
}

func newMutationAdapter(t *testing.T) (*sqliteadapter.Adapter, *sqliteTraceLog) {
	t.Helper()
	database, statements := openTracedSQLiteDatabase(t)
	adapter, err := sqliteadapter.New(database, sqliteadapter.Options{
		Schema: mutationSchema(),
		IDGenerator: func(string) (any, error) {
			return "generated-id", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	statements.Reset()
	return adapter, statements
}

func assertSingleSQLiteCommand(
	t *testing.T,
	statements []sqliteTraceStatement,
	command string,
) sqliteTraceStatement {
	t.Helper()
	matches := make([]sqliteTraceStatement, 0, 1)
	for _, statement := range statements {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(statement.SQL)), command) {
			matches = append(matches, statement)
		}
	}
	if len(matches) != 1 || len(statements) != 1 {
		t.Fatalf("%s statements = %#v, want exactly one statement", command, statements)
	}
	return matches[0]
}

func assertMutationFields(t *testing.T, record storage.Record, name, value string) {
	t.Helper()
	if record == nil || record["name"] != name || record["value"] != value {
		t.Fatalf("mutation row = %#v, want name=%q value=%q", record, name, value)
	}
}
