package memory_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

type memoryManifestOracle struct {
	SchemaVersion   int                    `json:"schemaVersion"`
	UpstreamVersion string                 `json:"upstreamVersion"`
	OracleKind      string                 `json:"oracleKind"`
	Sources         []memoryManifestSource `json:"sources"`
	Runtime         []memoryManifestSource `json:"runtime"`
	ManifestTestIDs []string               `json:"manifestTestIDs"`
	Tests           []memoryManifestCase   `json:"tests"`
}

type memoryManifestSource struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}

type memoryManifestCase struct {
	Suite       string
	Title       string
	Observation any
}

func TestMemoryAdapterManifestBehavior(t *testing.T) {
	oracle := loadMemoryManifestOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			actual := canonicalMemoryManifestValue(t, runMemoryManifestCase(t, vector.Title))
			expected := canonicalMemoryManifestValue(t, vector.Observation)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("memory-adapter observation = %#v, want %#v", actual, expected)
			}
		})
	}
}

func runMemoryManifestCase(t *testing.T, title string) any {
	t.Helper()
	switch title {
	case "singular update with an empty where is a no-op and leaves every row untouched":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice"})
		createMemoryWidget(t, adapter, storage.Record{"id": "2", "name": "bob"})
		result, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "widget", Update: storage.Record{"name": "overwritten"},
		})
		if err != nil {
			t.Fatal(err)
		}
		rows := findMemoryWidgets(t, adapter)
		names := []string{rows[0]["name"].(string), rows[1]["name"].(string)}
		sort.Strings(names)
		return map[string]any{"result": result, "names": names}

	case "singular delete with an empty where is a no-op and removes no rows":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice"})
		createMemoryWidget(t, adapter, storage.Record{"id": "2", "name": "bob"})
		if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "widget"}); err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"resultType": "undefined",
			"ids":        memoryWidgetIDs(findMemoryWidgets(t, adapter)),
		}

	case "returns the number of affected rows, not a record":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice"})
		createMemoryWidget(t, adapter, storage.Record{"id": "2", "name": "bob"})
		createMemoryWidget(t, adapter, storage.Record{"id": "3", "name": "carol"})
		affected, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{
			Model: "widget", Where: []storage.Where{{Field: "tag", Value: "x"}},
			Update: storage.Record{"tag": "x"},
		})
		if err != nil {
			t.Fatal(err)
		}
		matched, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{
			Model: "widget",
			Where: []storage.Where{
				{Field: "id", Value: "1", Connector: storage.Or},
				{Field: "id", Value: "2", Connector: storage.Or},
			},
			Update: storage.Record{"tag": "grouped"},
		})
		if err != nil {
			t.Fatal(err)
		}
		all, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{
			Model: "widget", Update: storage.Record{"tag": "everyone"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"affected": affected,
			"matched":  matched,
			"all":      all,
			"returnTypes": []string{
				"number", "number", "number",
			},
		}

	case "applies a positive delta and returns the updated row":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice", "count": 5})
		updated := incrementMemoryWidget(t, adapter, storage.IncrementOneParams{
			Model: "widget", Where: memoryWidgetID("1"), Increment: map[string]float64{"count": 3},
		})
		stored := findMemoryWidget(t, adapter, "1")
		return map[string]any{"updatedCount": updated["count"], "storedCount": stored["count"]}

	case "applies a negative delta to decrement":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice", "remaining": 2})
		updated := incrementMemoryWidget(t, adapter, storage.IncrementOneParams{
			Model: "widget", Where: memoryWidgetID("1"), Increment: map[string]float64{"remaining": -1},
		})
		return map[string]any{"remaining": updated["remaining"]}

	case "treats a missing counter field as zero before applying the delta":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice"})
		updated := incrementMemoryWidget(t, adapter, storage.IncrementOneParams{
			Model: "widget", Where: memoryWidgetID("1"), Increment: map[string]float64{"count": 4},
		})
		return map[string]any{"count": updated["count"]}

	case "applies absolute set assignments alongside increments":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice", "count": 1})
		updated := incrementMemoryWidget(t, adapter, storage.IncrementOneParams{
			Model: "widget", Where: memoryWidgetID("1"), Increment: map[string]float64{"count": 1},
			Set: storage.Record{"tag": "touched"},
		})
		return map[string]any{"count": updated["count"], "tag": updated["tag"]}

	case "mutates only the single guarded row matching the where clause":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice", "count": 0})
		createMemoryWidget(t, adapter, storage.Record{"id": "2", "name": "bob", "count": 0})
		incrementMemoryWidget(t, adapter, storage.IncrementOneParams{
			Model: "widget", Where: memoryWidgetID("1"), Increment: map[string]float64{"count": 10},
		})
		byID := make(map[string]any)
		for _, row := range findMemoryWidgets(t, adapter) {
			byID[row["id"].(string)] = row["count"]
		}
		return map[string]any{"byId": byID}

	case "when the guard matches no row, returns null and mutates nothing":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice", "remaining": 0})
		updated, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
			Model: "widget",
			Where: []storage.Where{
				{Field: "id", Value: "1"},
				{Field: "remaining", Value: 0, Operator: storage.OpGt},
			},
			Increment: map[string]float64{"remaining": -1},
		})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"updated": updated, "remaining": findMemoryWidget(t, adapter, "1")["remaining"]}

	case "participates in copy-on-write so a failed transaction discards the increment":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "1", "name": "alice", "count": 5})
		sentinel := errors.New("Simulated failure")
		err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
			if _, err := transaction.IncrementOne(t.Context(), storage.IncrementOneParams{
				Model: "widget", Where: memoryWidgetID("1"), Increment: map[string]float64{"count": 100},
			}); err != nil {
				return err
			}
			return sentinel
		})
		return map[string]any{
			"isError":      errors.Is(err, sentinel),
			"errorMessage": err.Error(),
			"count":        findMemoryWidget(t, adapter, "1")["count"],
		}

	case "a failing transaction must not erase a write made by a concurrent in-flight operation":
		adapter := newMemoryManifestAdapter(t, nil)
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		sentinel := errors.New("Simulated failure")
		go func() {
			done <- adapter.Transaction(context.Background(), func(transaction storage.TransactionAdapter) error {
				if _, err := transaction.Create(context.Background(), storage.CreateParams{
					Model: "widget", Data: storage.Record{"id": "tx", "name": "in-transaction"}, ForceAllowID: true,
				}); err != nil {
					return err
				}
				close(started)
				<-release
				return sentinel
			})
		}()
		<-started
		createMemoryWidget(t, adapter, storage.Record{"id": "outside", "name": "outside-write"})
		close(release)
		err := <-done
		return map[string]any{
			"isError":      errors.Is(err, sentinel),
			"errorMessage": err.Error(),
			"ids":          memoryWidgetIDs(findMemoryWidgets(t, adapter)),
		}

	case "a committing transaction must not erase a write made by a concurrent in-flight operation":
		adapter := newMemoryManifestAdapter(t, nil)
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- adapter.Transaction(context.Background(), func(transaction storage.TransactionAdapter) error {
				if _, err := transaction.Create(context.Background(), storage.CreateParams{
					Model: "widget", Data: storage.Record{"id": "tx", "name": "in-transaction"}, ForceAllowID: true,
				}); err != nil {
					return err
				}
				close(started)
				<-release
				return nil
			})
		}()
		<-started
		createMemoryWidget(t, adapter, storage.Record{"id": "outside", "name": "outside-write"})
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"result": "committed",
			"ids":    memoryWidgetIDs(findMemoryWidgets(t, adapter)),
		}

	case "a committing transaction's update to one row does not clobber a concurrent update to a different row":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "a", "name": "a-original"})
		createMemoryWidget(t, adapter, storage.Record{"id": "b", "name": "b-original"})
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- adapter.Transaction(context.Background(), func(transaction storage.TransactionAdapter) error {
				if _, err := transaction.Update(context.Background(), storage.UpdateParams{
					Model: "widget", Where: memoryWidgetID("a"), Update: storage.Record{"name": "a-from-tx"},
				}); err != nil {
					return err
				}
				close(started)
				<-release
				return nil
			})
		}()
		<-started
		if _, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "widget", Where: memoryWidgetID("b"), Update: storage.Record{"name": "b-from-outside"},
		}); err != nil {
			t.Fatal(err)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		byID := make(map[string]any)
		for _, row := range findMemoryWidgets(t, adapter) {
			byID[row["id"].(string)] = row["name"]
		}
		return map[string]any{"byId": byID}

	case "a committing transaction's delete is applied while a concurrent insert survives":
		adapter := newMemoryManifestAdapter(t, nil)
		createMemoryWidget(t, adapter, storage.Record{"id": "doomed", "name": "to-be-deleted"})
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- adapter.Transaction(context.Background(), func(transaction storage.TransactionAdapter) error {
				if err := transaction.Delete(context.Background(), storage.DeleteParams{
					Model: "widget", Where: memoryWidgetID("doomed"),
				}); err != nil {
					return err
				}
				close(started)
				<-release
				return nil
			})
		}()
		<-started
		createMemoryWidget(t, adapter, storage.Record{"id": "fresh", "name": "concurrent-insert"})
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return map[string]any{"ids": memoryWidgetIDs(findMemoryWidgets(t, adapter))}

	case "uncommitted transaction writes are invisible to operations outside the transaction":
		adapter := newMemoryManifestAdapter(t, nil)
		started := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- adapter.Transaction(context.Background(), func(transaction storage.TransactionAdapter) error {
				if _, err := transaction.Create(context.Background(), storage.CreateParams{
					Model: "widget", Data: storage.Record{"id": "tx", "name": "in-transaction"}, ForceAllowID: true,
				}); err != nil {
					return err
				}
				close(started)
				<-release
				return nil
			})
		}()
		<-started
		observed := len(findMemoryWidgets(t, adapter))
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"observedDuringTransaction": observed,
			"result":                    "committed",
			"ids":                       memoryWidgetIDs(findMemoryWidgets(t, adapter)),
		}

	case "a committed transaction mutates the original db object in place":
		backing := memory.Database{"widget": {}}
		adapter := newMemoryManifestAdapter(t, backing)
		if err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
			_, err := transaction.Create(t.Context(), storage.CreateParams{
				Model: "widget", Data: storage.Record{"id": "committed", "name": "kept"}, ForceAllowID: true,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(backing["widget"]))
		for _, row := range backing["widget"] {
			ids = append(ids, row["id"].(string))
		}
		return map[string]any{"dbIds": ids}

	default:
		t.Fatalf("unknown reference implementation memory-adapter test %q", title)
		return nil
	}
}

func newMemoryManifestAdapter(t *testing.T, backing memory.Database) *memory.Adapter {
	t.Helper()
	optional := storage.Bool(false)
	schema, err := storage.CoreSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"widget": {
			Fields: map[string]storage.FieldAttribute{
				"name":      {Type: storage.FieldString, Required: optional},
				"tag":       {Type: storage.FieldString, Required: optional},
				"count":     {Type: storage.FieldNumber, Required: optional},
				"remaining": {Type: storage.FieldNumber, Required: optional},
			},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	options := []memory.Option{memory.WithSchema(schema)}
	if backing != nil {
		options = append(options, memory.WithDatabase(backing))
	}
	adapter, err := memory.New(options...)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func createMemoryWidget(t *testing.T, adapter storage.TransactionAdapter, record storage.Record) storage.Record {
	t.Helper()
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "widget", Data: record, ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func incrementMemoryWidget(t *testing.T, adapter storage.TransactionAdapter, params storage.IncrementOneParams) storage.Record {
	t.Helper()
	updated, err := adapter.IncrementOne(t.Context(), params)
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil {
		t.Fatal("incrementOne returned nil")
	}
	return updated
}

func findMemoryWidget(t *testing.T, adapter storage.TransactionAdapter, id string) storage.Record {
	t.Helper()
	row, err := adapter.FindOne(t.Context(), storage.FindOneParams{Model: "widget", Where: memoryWidgetID(id)})
	if err != nil {
		t.Fatal(err)
	}
	if row == nil {
		t.Fatalf("widget %q not found", id)
	}
	return row
}

func findMemoryWidgets(t *testing.T, adapter storage.TransactionAdapter) []storage.Record {
	t.Helper()
	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "widget", Limit: storage.Int(100)})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func memoryWidgetID(id string) []storage.Where {
	return []storage.Where{{Field: "id", Value: id}}
}

func memoryWidgetIDs(rows []storage.Record) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row["id"].(string))
	}
	sort.Strings(ids)
	return ids
}

func loadMemoryManifestOracle(t *testing.T) memoryManifestOracle {
	t.Helper()
	oracle := memoryManifestOracle{Tests: memoryManifestScenarios}
	if len(oracle.Tests) != 16 {
		t.Fatalf("memory adapter scenarios=%d, want 16", len(oracle.Tests))
	}
	for _, vector := range oracle.Tests {
		if vector.Suite == "" || vector.Title == "" || vector.Observation == nil {
			t.Fatalf("invalid memory adapter scenario: %#v", vector)
		}
	}
	return oracle
}

func canonicalMemoryManifestValue(t *testing.T, value any) any {
	t.Helper()
	if value == nil {
		return nil
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Interface, reflect.Pointer:
		if reflected.IsNil() {
			return nil
		}
		return canonicalMemoryManifestValue(t, reflected.Elem().Interface())
	case reflect.Map:
		if reflected.IsNil() {
			return nil
		}
		result := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			result[iterator.Key().String()] = canonicalMemoryManifestValue(t, iterator.Value().Interface())
		}
		return result
	case reflect.Slice, reflect.Array:
		if reflected.Kind() == reflect.Slice && reflected.IsNil() {
			return nil
		}
		result := make([]any, reflected.Len())
		for index := range reflected.Len() {
			result[index] = canonicalMemoryManifestValue(t, reflected.Index(index).Interface())
		}
		return result
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(reflected.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(reflected.Uint())
	case reflect.Float32, reflect.Float64:
		return reflected.Convert(reflect.TypeOf(float64(0))).Float()
	default:
		return value
	}
}
