package sqlite_test

import (
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"
)

func TestIncrementOneAppliesDeltasAtomicallyAndReturnsUpdatedRow(t *testing.T) {
	adapter, statements := newIncrementOneAdapter(t)
	createCounter(t, adapter, "a", "alpha", 3, 0, "open")

	statements.Reset()
	result, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "counters",
		Where: []storage.Where{{Field: "name", Value: "alpha"}},
		Increment: map[string]float64{
			"remaining": -1,
			"used":      1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCounterFields(t, result, storage.Record{"remaining": 2, "used": 1})

	queries := statements.Snapshot()
	if len(queries) != 1 {
		t.Fatalf("IncrementOne statements = %#v, want one atomic statement", queries)
	}
	normalized := strings.ToLower(strings.TrimSpace(queries[0].SQL))
	for _, fragment := range []string{
		"update \"counters\"",
		"\"remaining\" = coalesce(\"remaining\", 0) + ?",
		"\"used\" = coalesce(\"used\", 0) + ?",
		" returning ",
	} {
		if !strings.Contains(normalized, fragment) {
			t.Fatalf("IncrementOne SQL %q does not contain %q", queries[0].SQL, fragment)
		}
	}
	if queries[0].ArgumentCount != 3 {
		t.Fatalf("IncrementOne bound arguments = %d, want 3", queries[0].ArgumentCount)
	}

	stored := findCounter(t, adapter, "alpha")
	assertCounterFields(t, stored, storage.Record{"remaining": 2, "used": 1})
}

func TestIncrementOneCombinesSetAndDeltas(t *testing.T) {
	adapter, _ := newIncrementOneAdapter(t)
	createCounter(t, adapter, "b", "beta", 5, 2, "open")

	result, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "counters",
		Where:     []storage.Where{{Field: "name", Value: "beta"}},
		Increment: map[string]float64{"remaining": -1},
		Set:       storage.Record{"status": "closed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCounterFields(t, result, storage.Record{"remaining": 4, "status": "closed"})
}

func TestIncrementOneMutatesExactlyOneMatchingRow(t *testing.T) {
	adapter, _ := newIncrementOneAdapter(t)
	for _, id := range []string{"d1", "d2", "d3"} {
		createCounter(t, adapter, id, "shared", 5, 0, "open")
	}

	result, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "counters",
		Where: []storage.Where{
			{Field: "name", Value: "shared"},
			{Field: "remaining", Operator: storage.OpGt, Value: 0},
		},
		Increment: map[string]float64{"remaining": -1, "used": 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("IncrementOne returned nil for a matching guard")
	}

	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model:  "counters",
		Where:  []storage.Where{{Field: "name", Value: "shared"}},
		SortBy: &storage.Sort{Field: "id", Direction: storage.Ascending},
	})
	if err != nil {
		t.Fatal(err)
	}
	mutated := 0
	untouched := 0
	for _, row := range rows {
		switch {
		case row["remaining"] == 4 && row["used"] == 1:
			mutated++
			if row["id"] != result["id"] {
				t.Fatalf("returned row id = %#v, mutated row id = %#v", result["id"], row["id"])
			}
		case row["remaining"] == 5 && row["used"] == 0:
			untouched++
		default:
			t.Fatalf("unexpected counter state: %#v", row)
		}
	}
	if mutated != 1 || untouched != 2 {
		t.Fatalf("mutated rows = %d, untouched rows = %d", mutated, untouched)
	}
}

func TestIncrementOneGuardMissLeavesRowUnchanged(t *testing.T) {
	adapter, _ := newIncrementOneAdapter(t)
	createCounter(t, adapter, "c", "gamma", 0, 4, "open")

	result, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "counters",
		Where: []storage.Where{
			{Field: "name", Value: "gamma"},
			{Field: "remaining", Operator: storage.OpGt, Value: 0},
		},
		Increment: map[string]float64{"remaining": -1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("IncrementOne guard miss returned %#v, want nil", result)
	}
	stored := findCounter(t, adapter, "gamma")
	assertCounterFields(t, stored, storage.Record{"remaining": 0, "used": 4})
}

func incrementOneSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"counters": {
			ModelName: "counters",
			Fields: map[string]storage.FieldAttribute{
				"name":      {Type: storage.FieldString},
				"remaining": {Type: storage.FieldNumber},
				"used":      {Type: storage.FieldNumber},
				"status":    {Type: storage.FieldString},
			},
		},
	}}
}

func newIncrementOneAdapter(t *testing.T) (*sqliteadapter.Adapter, *sqliteTraceLog) {
	t.Helper()
	database, statements := openTracedSQLiteDatabase(t)
	adapter, err := sqliteadapter.New(database, sqliteadapter.Options{Schema: incrementOneSchema()})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	statements.Reset()
	return adapter, statements
}

func createCounter(
	t *testing.T,
	adapter *sqliteadapter.Adapter,
	id string,
	name string,
	remaining int,
	used int,
	status string,
) {
	t.Helper()
	_, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "counters",
		Data: storage.Record{
			"id": id, "name": name, "remaining": remaining, "used": used, "status": status,
		},
		ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func findCounter(t *testing.T, adapter *sqliteadapter.Adapter, name string) storage.Record {
	t.Helper()
	record, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "counters", Where: []storage.Where{{Field: "name", Value: name}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func assertCounterFields(t *testing.T, actual storage.Record, expected storage.Record) {
	t.Helper()
	if actual == nil {
		t.Fatalf("counter = nil, want fields %#v", expected)
	}
	for field, expectedValue := range expected {
		if actual[field] != expectedValue {
			t.Fatalf("counter field %s = %#v, want %#v (record %#v)", field, actual[field], expectedValue, actual)
		}
	}
}
