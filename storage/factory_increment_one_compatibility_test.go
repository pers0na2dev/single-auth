package storage

import (
	"context"
	"reflect"
	"sync"
	"testing"
)

type adapterIncrementOneOracle struct {
	Tests []adapterIncrementOneScenario
}

type adapterIncrementOneScenario struct {
	Title    string
	Expected any
}

type incrementOneMemoryDriver struct {
	mu          sync.Mutex
	rows        []Record
	nativeCalls int
	native      bool
}

func TestAdapterIncrementOneBehavior(t *testing.T) {
	oracle := loadAdapterIncrementOneOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			actual := runAdapterIncrementOneVector(t, vector.Title)
			assertAdapterIncrementOneResult(t, vector.Expected, actual)
		})
	}
}

func runAdapterIncrementOneVector(t *testing.T, title string) map[string]any {
	t.Helper()
	newFactory := func(rows []Record, native bool) (*incrementOneMemoryDriver, Adapter) {
		driverState := &incrementOneMemoryDriver{rows: cloneIncrementRows(rows), native: native}
		adapter, err := NewAdapterFactory(AdapterFactoryConfig{
			AdapterID: "memory-test-adapter", AdapterName: "Memory Test Adapter",
			Schema: CoreSchema(),
		}, driverState.adapter())
		if err != nil {
			t.Fatal(err)
		}
		return driverState, adapter
	}
	call := func(adapter Adapter, where []Where, increment map[string]float64, set Record) (Record, error) {
		return adapter.IncrementOne(t.Context(), IncrementOneParams{
			Model: "rateLimit", Where: where, Increment: increment, Set: set,
		})
	}

	switch title {
	case "applies a positive delta and returns the updated row":
		state, adapter := newFactory([]Record{{"key": "a", "count": 0}}, false)
		result, err := call(adapter, []Where{{Field: "key", Value: "a"}}, map[string]float64{"count": 1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"resultCount": result["count"], "storedCount": state.first()["count"]}
	case "applies a negative delta to decrement":
		state, adapter := newFactory([]Record{{"key": "a", "count": 5}}, false)
		result, err := call(adapter, []Where{{Field: "key", Value: "a"}}, map[string]float64{"count": -2}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"resultCount": result["count"], "storedCount": state.first()["count"]}
	case "assigns absolute values via `set` in the same call":
		state, adapter := newFactory([]Record{{"key": "a", "count": 0, "lastRequest": 100}}, false)
		result, err := call(adapter, []Where{{Field: "key", Value: "a"}}, map[string]float64{"count": 1}, Record{"lastRequest": 999})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"resultCount": result["count"], "resultLastRequest": result["lastRequest"],
			"storedLastRequest": state.first()["lastRequest"],
		}
	case "returns null and does not mutate when the guard matches no row":
		state, adapter := newFactory([]Record{{"key": "a", "count": 0}}, false)
		result, err := call(adapter, []Where{{Field: "count", Operator: OpGt, Value: 0}}, map[string]float64{"count": -1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"resultNull": result == nil, "storedCount": state.first()["count"]}
	case "yields a single winner under contention and never goes negative":
		state, adapter := newFactory([]Record{{"key": "a", "count": 1}}, false)
		results := make(chan Record, 2)
		errors := make(chan error, 2)
		var group sync.WaitGroup
		for range 2 {
			group.Add(1)
			go func() {
				defer group.Done()
				result, err := adapter.IncrementOne(context.Background(), IncrementOneParams{
					Model:     "rateLimit",
					Where:     []Where{{Field: "count", Operator: OpGt, Value: 0}},
					Increment: map[string]float64{"count": -1},
				})
				if err != nil {
					errors <- err
					return
				}
				results <- result
			}()
		}
		group.Wait()
		close(results)
		close(errors)
		for err := range errors {
			t.Fatal(err)
		}
		winners := 0
		for result := range results {
			if result != nil {
				winners++
			}
		}
		return map[string]any{"winners": winners, "storedCount": state.first()["count"]}
	case "throws when both `increment` and `set` are empty":
		_, adapter := newFactory([]Record{{"key": "a", "count": 0}}, false)
		_, err := call(adapter, []Where{{Field: "key", Value: "a"}}, map[string]float64{}, nil)
		return map[string]any{"threw": err != nil}
	case "applies a guarded transition via `set` with an empty increment":
		state, adapter := newFactory([]Record{{"key": "a", "count": 0, "lastRequest": 100}}, false)
		where := []Where{{Field: "key", Value: "a"}, {Field: "lastRequest", Value: 100}}
		won, err := call(adapter, where, map[string]float64{}, Record{"lastRequest": 200})
		if err != nil {
			t.Fatal(err)
		}
		lost, err := call(adapter, where, map[string]float64{}, Record{"lastRequest": 300})
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"wonLastRequest": won["lastRequest"], "lostNull": lost == nil,
			"storedLastRequest": state.first()["lastRequest"],
		}
	case "delegates to a native incrementOne when implemented":
		state, adapter := newFactory([]Record{{"key": "a", "count": 10}}, true)
		result, err := call(adapter, []Where{{Field: "key", Value: "a"}}, map[string]float64{"count": 5}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{
			"nativeCalls": state.calls(), "resultCount": result["count"],
			"storedCount": state.first()["count"],
		}
	case "throws when `set` resolves to empty after input transform":
		state, adapter := newFactory([]Record{{"key": "a", "count": 0}}, true)
		_, err := call(adapter, []Where{{Field: "key", Value: "a"}}, map[string]float64{}, Record{"bogus": 1})
		return map[string]any{"threw": err != nil, "nativeCalls": state.calls()}
	default:
		t.Fatalf("unsupported adapter incrementOne test %q", title)
		return nil
	}
}

func (state *incrementOneMemoryDriver) adapter() CustomAdapter {
	base := adapterFactoryTestDriver()
	base.FindMany = func(_ context.Context, params FindManyParams) ([]Record, error) {
		state.mu.Lock()
		defer state.mu.Unlock()
		limit := len(state.rows)
		if params.Limit != nil && *params.Limit < limit {
			limit = *params.Limit
		}
		rows := make([]Record, 0, limit)
		for _, row := range state.rows {
			if matchesIncrementWhere(row, params.Where) {
				rows = append(rows, cloneFactoryRecord(row))
				if len(rows) == limit {
					break
				}
			}
		}
		return rows, nil
	}
	base.UpdateMany = func(_ context.Context, params UpdateManyParams) (int64, error) {
		state.mu.Lock()
		defer state.mu.Unlock()
		var count int64
		for _, row := range state.rows {
			if matchesIncrementWhere(row, params.Where) {
				for field, value := range params.Update {
					row[field] = cloneFactoryValue(value)
				}
				count++
			}
		}
		return count, nil
	}
	if state.native {
		base.IncrementOne = func(_ context.Context, params IncrementOneParams) (Record, error) {
			state.mu.Lock()
			defer state.mu.Unlock()
			state.nativeCalls++
			for _, row := range state.rows {
				if !matchesIncrementWhere(row, params.Where) {
					continue
				}
				for field, value := range params.Set {
					row[field] = cloneFactoryValue(value)
				}
				for field, delta := range params.Increment {
					current, _ := numericValue(row[field])
					row[field] = current + delta
				}
				return cloneFactoryRecord(row), nil
			}
			return nil, nil
		}
	}
	return base
}

func matchesIncrementWhere(row Record, where []Where) bool {
	for _, clause := range where {
		value := row[clause.Field]
		switch clause.Operator {
		case OpGt:
			left, leftOK := numericValue(value)
			right, rightOK := numericValue(clause.Value)
			if !leftOK || !rightOK || left <= right {
				return false
			}
		case OpGTE:
			left, leftOK := numericValue(value)
			right, rightOK := numericValue(clause.Value)
			if !leftOK || !rightOK || left < right {
				return false
			}
		case OpLt:
			left, leftOK := numericValue(value)
			right, rightOK := numericValue(clause.Value)
			if !leftOK || !rightOK || left >= right {
				return false
			}
		case OpLTE:
			left, leftOK := numericValue(value)
			right, rightOK := numericValue(clause.Value)
			if !leftOK || !rightOK || left > right {
				return false
			}
		case OpNe:
			if reflect.DeepEqual(value, clause.Value) {
				return false
			}
		default:
			if !reflect.DeepEqual(value, clause.Value) {
				return false
			}
		}
	}
	return true
}

func (state *incrementOneMemoryDriver) first() Record {
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.rows) == 0 {
		return nil
	}
	return cloneFactoryRecord(state.rows[0])
}

func (state *incrementOneMemoryDriver) calls() int {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.nativeCalls
}

func cloneIncrementRows(rows []Record) []Record {
	result := make([]Record, len(rows))
	for index, row := range rows {
		result[index] = cloneFactoryRecord(row)
	}
	return result
}

func assertAdapterIncrementOneResult(t *testing.T, expected, actual any) {
	t.Helper()
	want := normalizeAdapterIncrementValue(expected)
	got := normalizeAdapterIncrementValue(actual)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adapter incrementOne observation=%#v, want %#v", got, want)
	}
}

func loadAdapterIncrementOneOracle(t *testing.T) adapterIncrementOneOracle {
	t.Helper()
	oracle := adapterIncrementOneOracle{Tests: adapterIncrementOneScenarios}
	if len(oracle.Tests) != 9 {
		t.Fatalf("adapter incrementOne scenarios=%d, want 9", len(oracle.Tests))
	}
	for _, vector := range oracle.Tests {
		if vector.Title == "" || vector.Expected == nil {
			t.Fatalf("invalid adapter incrementOne scenario: %#v", vector)
		}
	}
	return oracle
}

func normalizeAdapterIncrementValue(value any) any {
	if value == nil {
		return nil
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Interface, reflect.Pointer:
		if reflected.IsNil() {
			return nil
		}
		return normalizeAdapterIncrementValue(reflected.Elem().Interface())
	case reflect.Map:
		result := make(map[string]any, reflected.Len())
		iterator := reflected.MapRange()
		for iterator.Next() {
			result[iterator.Key().String()] = normalizeAdapterIncrementValue(iterator.Value().Interface())
		}
		return result
	case reflect.Slice, reflect.Array:
		result := make([]any, reflected.Len())
		for index := range reflected.Len() {
			result[index] = normalizeAdapterIncrementValue(reflected.Index(index).Interface())
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
