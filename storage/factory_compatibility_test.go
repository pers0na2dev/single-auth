package storage

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type adapterFactoryOracleWhere struct {
	Field     string `json:"field"`
	Value     any    `json:"value"`
	Operator  string `json:"operator"`
	Connector string `json:"connector"`
	Mode      string `json:"mode"`
}

type adapterFactoryOracleResult struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
}

func TestAdapterFactoryExactBehavior(t *testing.T) {
	t.Run("uses_transaction_adapter_methods_without_double_transforming_input_or_output", func(t *testing.T) {
		var findManyCall FindManyParams
		var deleteManyCall DeleteManyParams
		driver := adapterFactoryTestDriver()
		driver.FindMany = func(_ context.Context, params FindManyParams) ([]Record, error) {
			findManyCall = params
			return []Record{{"id": "verification-id", "identifier_text": "stored-token"}}, nil
		}
		driver.DeleteMany = func(_ context.Context, params DeleteManyParams) (any, error) {
			deleteManyCall = params
			return 1, nil
		}
		adapter := newAdapterFactoryBehaviorAdapter(t, driver, nil)
		result, err := adapter.ConsumeOne(t.Context(), ConsumeOneParams{
			Model: "verification", Where: []Where{{Field: "identifier", Value: "token"}},
		})
		if err != nil {
			t.Fatal(err)
		}

		expectedResult := adapterFactoryOracleResult{ID: "verification-id", Identifier: "stored-token:output"}
		expectedFindMany := struct {
			Model string
			Limit int
			Where []adapterFactoryOracleWhere
		}{
			Model: "verificationRecords", Limit: 1,
			Where: []adapterFactoryOracleWhere{{
				Field: "identifier_text", Value: "token:findMany", Operator: "eq", Connector: "AND", Mode: "sensitive",
			}},
		}
		expectedDeleteMany := struct {
			Model string
			Where []adapterFactoryOracleWhere
		}{
			Model: "verificationRecords",
			Where: []adapterFactoryOracleWhere{
				{Field: "identifier_text", Value: "token:deleteMany", Operator: "eq", Connector: "AND", Mode: "sensitive"},
				{Field: "id", Value: "verification-id", Operator: "eq", Connector: "AND", Mode: "sensitive"},
			},
		}
		assertAdapterFactoryResult(t, result, expectedResult)
		if findManyCall.Limit == nil || *findManyCall.Limit != expectedFindMany.Limit || findManyCall.Model != expectedFindMany.Model ||
			!reflect.DeepEqual(snapshotAdapterFactoryWhere(findManyCall.Where), expectedFindMany.Where) {
			t.Fatalf("findMany call=%#v want=%#v", findManyCall, expectedFindMany)
		}
		if deleteManyCall.Model != expectedDeleteMany.Model ||
			!reflect.DeepEqual(snapshotAdapterFactoryWhere(deleteManyCall.Where), expectedDeleteMany.Where) {
			t.Fatalf("deleteMany call=%#v want=%#v", deleteManyCall, expectedDeleteMany)
		}
	})

	t.Run("returns_null_when_the_delete_loses_the_consume_race", func(t *testing.T) {
		driver := adapterFactoryTestDriver()
		driver.FindMany = func(context.Context, FindManyParams) ([]Record, error) {
			return []Record{{"id": "verification-id", "identifier_text": "stored-token"}}, nil
		}
		driver.DeleteMany = func(context.Context, DeleteManyParams) (any, error) { return 0, nil }
		adapter := newAdapterFactoryBehaviorAdapter(t, driver, nil)
		result, err := adapter.ConsumeOne(t.Context(), ConsumeOneParams{
			Model: "verification", Where: []Where{{Field: "identifier", Value: "token"}},
		})
		if err != nil || result != nil {
			t.Fatalf("ConsumeOne result=%#v err=%v, want nil", result, err)
		}
	})

	t.Run("reuses_the_active_transaction_for_the_fallback", func(t *testing.T) {
		driver := adapterFactoryTestDriver()
		driver.FindMany = func(context.Context, FindManyParams) ([]Record, error) {
			return []Record{{"id": "verification-id", "identifier_text": "stored-token"}}, nil
		}
		driver.DeleteMany = func(context.Context, DeleteManyParams) (any, error) { return 1, nil }
		var transactionCalls int
		var transactionActive bool
		var adapter Adapter
		transaction := func(_ context.Context, callback func(TransactionAdapter) error) error {
			transactionCalls++
			if transactionActive {
				return errors.New("nested transaction")
			}
			if adapter == nil {
				return errors.New("adapter has not been initialized")
			}
			transactionActive = true
			defer func() { transactionActive = false }()
			return callback(adapter)
		}
		adapter = newAdapterFactoryBehaviorAdapter(t, driver, transaction)
		var result Record
		err := RunWithTransaction(t.Context(), adapter, func(ctx context.Context, _ TransactionAdapter) error {
			var consumeErr error
			result, consumeErr = adapter.ConsumeOne(ctx, ConsumeOneParams{
				Model: "verification", Where: []Where{{Field: "identifier", Value: "token"}},
			})
			return consumeErr
		})
		if err != nil {
			t.Fatal(err)
		}
		assertAdapterFactoryResult(t, result, adapterFactoryOracleResult{
			ID: "verification-id", Identifier: "stored-token:output",
		})
		if transactionCalls != 1 {
			t.Fatalf("transaction calls=%d want=1", transactionCalls)
		}
	})

	t.Run("throws_when_deleteMany_returns_a_non_numeric_value", func(t *testing.T) {
		driver := adapterFactoryTestDriver()
		driver.FindMany = func(context.Context, FindManyParams) ([]Record, error) {
			return []Record{{"id": "verification-id", "identifier_text": "stored-token"}}, nil
		}
		driver.DeleteMany = func(context.Context, DeleteManyParams) (any, error) {
			return map[string]any{"deleted": true}, nil
		}
		adapter := newAdapterFactoryBehaviorAdapter(t, driver, nil)
		_, err := adapter.ConsumeOne(t.Context(), ConsumeOneParams{
			Model: "verification", Where: []Where{{Field: "identifier", Value: "token"}},
		})
		if err == nil {
			t.Fatal("ConsumeOne accepted a non-numeric deleteMany result")
		}
		const expectedMessage = "Adapter \"test-adapter\" returned a non-numeric value from deleteMany during the consumeOne fallback. Return the number of deleted rows, or implement a native consumeOne for atomic single-use consumption."
		if err.Error() != expectedMessage || !strings.Contains(err.Error(), "non-numeric value from deleteMany") {
			t.Fatalf("error=%q want=%q", err, expectedMessage)
		}
	})

	t.Run("coerces_string_where_values_to_match_field_types_before_querying", func(t *testing.T) {
		schema := CoreSchema()
		user := schema.Models["user"]
		user.Fields["age"] = FieldAttribute{Type: FieldNumber, Required: Bool(false)}
		schema.Models["user"] = user
		seenWhere := make([][]adapterFactoryOracleWhere, 0, 3)
		driver := adapterFactoryTestDriver()
		driver.FindMany = func(_ context.Context, params FindManyParams) ([]Record, error) {
			seenWhere = append(seenWhere, snapshotAdapterFactoryWhere(params.Where))
			return []Record{}, nil
		}
		adapter, err := NewAdapterFactory(AdapterFactoryConfig{
			AdapterID: "test-adapter", AdapterName: "Test Adapter", Schema: schema,
		}, driver)
		if err != nil {
			t.Fatal(err)
		}
		queries := [][]Where{
			{{Field: "emailVerified", Operator: OpEq, Value: "false"}},
			{{Field: "age", Operator: OpEq, Value: "25"}},
			{{Field: "age", Operator: OpIn, Value: []string{"25", "30"}}},
		}
		for _, where := range queries {
			if _, err := adapter.FindMany(t.Context(), FindManyParams{Model: "user", Where: where}); err != nil {
				t.Fatal(err)
			}
		}
		expected := [][]adapterFactoryOracleWhere{
			{{Field: "emailVerified", Value: false, Operator: "eq", Connector: "AND", Mode: "sensitive"}},
			{{Field: "age", Value: float64(25), Operator: "eq", Connector: "AND", Mode: "sensitive"}},
			{{Field: "age", Value: []any{float64(25), float64(30)}, Operator: "in", Connector: "AND", Mode: "sensitive"}},
		}
		if !reflect.DeepEqual(seenWhere, expected) {
			t.Fatalf("seen where=%#v want=%#v", seenWhere, expected)
		}
	})
}

// The fallback case forces a zero delete count. This companion test
// forces two goroutines through the same read window and proves the count gate
// permits exactly one consumer under the race detector.
func TestAdapterFactoryConsumeOneRaceGate(t *testing.T) {
	driver := adapterFactoryTestDriver()
	var mutex sync.Mutex
	finds := 0
	deleted := false
	ready := make(chan struct{})
	driver.FindMany = func(context.Context, FindManyParams) ([]Record, error) {
		mutex.Lock()
		finds++
		if finds == 2 {
			close(ready)
		}
		mutex.Unlock()
		<-ready
		return []Record{{"id": "verification-id", "identifier_text": "stored-token"}}, nil
	}
	driver.DeleteMany = func(context.Context, DeleteManyParams) (any, error) {
		mutex.Lock()
		defer mutex.Unlock()
		if deleted {
			return 0, nil
		}
		deleted = true
		return 1, nil
	}
	adapter := newAdapterFactoryBehaviorAdapter(t, driver, nil)
	results := make(chan Record, 2)
	errorsSeen := make(chan error, 2)
	for range 2 {
		go func() {
			result, err := adapter.ConsumeOne(context.Background(), ConsumeOneParams{
				Model: "verification", Where: []Where{{Field: "identifier", Value: "token"}},
			})
			results <- result
			errorsSeen <- err
		}()
	}
	winners := 0
	for range 2 {
		if err := <-errorsSeen; err != nil {
			t.Fatal(err)
		}
		if result := <-results; result != nil {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("consume winners=%d want=1", winners)
	}
}

func adapterFactoryTestDriver() CustomAdapter {
	return CustomAdapter{
		Create: func(_ context.Context, params CreateParams) (Record, error) {
			return cloneFactoryRecord(params.Data), nil
		},
		FindOne:    func(context.Context, FindOneParams) (Record, error) { return nil, nil },
		FindMany:   func(context.Context, FindManyParams) ([]Record, error) { return []Record{}, nil },
		Count:      func(context.Context, CountParams) (int64, error) { return 0, nil },
		Update:     func(context.Context, UpdateParams) (Record, error) { return nil, nil },
		UpdateMany: func(context.Context, UpdateManyParams) (int64, error) { return 0, nil },
		Delete:     func(context.Context, DeleteParams) error { return nil },
		DeleteMany: func(context.Context, DeleteManyParams) (any, error) { return 0, nil },
	}
}

func newAdapterFactoryBehaviorAdapter(
	t *testing.T,
	driver CustomAdapter,
	transaction func(context.Context, func(TransactionAdapter) error) error,
) Adapter {
	t.Helper()
	schema := CoreSchema()
	schema.UsePlural = true
	verification := schema.Models["verification"]
	verification.ModelName = "verificationRecord"
	identifier := verification.Fields["identifier"]
	identifier.FieldName = "identifier_text"
	verification.Fields["identifier"] = identifier
	schema.Models["verification"] = verification
	adapter, err := NewAdapterFactory(AdapterFactoryConfig{
		AdapterID: "test-adapter", AdapterName: "Test Adapter", Schema: schema,
		Transaction: transaction,
		TransformInput: func(input AdapterTransformContext) (any, error) {
			if input.Field == "identifier_text" {
				if value, ok := input.Data.(string); ok {
					return value + ":" + string(input.Action), nil
				}
			}
			return input.Data, nil
		},
		TransformOutput: func(output AdapterOutputTransformContext) (any, error) {
			if output.Field == "identifier" {
				if value, ok := output.Data.(string); ok {
					return value + ":output", nil
				}
			}
			return output.Data, nil
		},
	}, driver)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func snapshotAdapterFactoryWhere(where []Where) []adapterFactoryOracleWhere {
	result := make([]adapterFactoryOracleWhere, len(where))
	for index, clause := range where {
		result[index] = adapterFactoryOracleWhere{
			Field: clause.Field, Value: clause.Value, Operator: string(clause.Operator),
			Connector: string(clause.Connector), Mode: string(clause.Mode),
		}
	}
	return result
}

func assertAdapterFactoryResult(t *testing.T, actual Record, expected adapterFactoryOracleResult) {
	t.Helper()
	if actual == nil || actual["id"] != expected.ID || actual["identifier"] != expected.Identifier {
		t.Fatalf("result=%#v want id=%q identifier=%q", actual, expected.ID, expected.Identifier)
	}
}
