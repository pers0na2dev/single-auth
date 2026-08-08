package mssql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/pers0na2dev/single-auth/storage"
)

const thingProjection = "[id], [count], [__single_present__count], [created], [__single_present__created], [data], [__single_present__data], [flag], [__single_present__flag], [name], [__single_present__name]"

const insertedThingProjection = "[inserted].[id], [inserted].[count], [inserted].[__single_present__count], [inserted].[created], [inserted].[__single_present__created], [inserted].[data], [inserted].[__single_present__data], [inserted].[flag], [inserted].[__single_present__flag], [inserted].[name], [inserted].[__single_present__name]"

const deletedThingProjection = "[deleted].[id], [deleted].[count], [deleted].[__single_present__count], [deleted].[created], [deleted].[__single_present__created], [deleted].[data], [deleted].[__single_present__data], [deleted].[flag], [deleted].[__single_present__flag], [deleted].[name], [deleted].[__single_present__name]"

const createThingSQL = "INSERT INTO [thing] ([count], [__single_present__count], [created], [__single_present__created], [data], [__single_present__data], [flag], [__single_present__flag], [id], [name], [__single_present__name]) OUTPUT " + insertedThingProjection + " VALUES (@p1, 1, @p2, 1, @p3, 1, @p4, 1, @p5, @p6, 1)"

func TestCreateRoundTripAndUniqueNormalization(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 123_000_000, time.FixedZone("plus-two", 2*60*60))
	utcCreatedAt := createdAt.UTC()
	data := storage.Record{
		"id": "t1", "count": 2, "created": createdAt,
		"data": map[string]any{"enabled": true}, "flag": true, "name": "Thing",
	}
	mock.ExpectQuery(createThingSQL).
		WithArgs(int64(2), utcCreatedAt.Format(time.RFC3339Nano), `{"enabled":true}`, int64(1), "t1", "Thing").
		WillReturnRows(thingRows().AddRow(
			[]byte("t1"), []byte("2"), int64(1), []byte("2026-08-08 10:00:00.123"), int64(1),
			[]byte(`{"enabled":true}`), int64(1), int64(1), int64(1), []byte("Thing"), int64(1),
		))
	created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "thing", Data: data, ForceAllowID: true})
	if err != nil {
		t.Fatal(err)
	}
	if created["id"] != "t1" || created["count"] != 2 || created["flag"] != true || created["name"] != "Thing" {
		t.Fatalf("created = %#v", created)
	}
	if !reflect.DeepEqual(created["data"], map[string]any{"enabled": true}) {
		t.Fatalf("JSON = %#v", created["data"])
	}
	if got, ok := created["created"].(time.Time); !ok || !got.Equal(utcCreatedAt) {
		t.Fatalf("created date = %#v", created["created"])
	}

	mock.ExpectQuery(createThingSQL).
		WithArgs(int64(2), utcCreatedAt.Format(time.RFC3339Nano), `{"enabled":true}`, int64(1), "t1", "Thing").
		WillReturnError(fakeMSSQLError{Number: 2627, message: "Violation of PRIMARY KEY constraint"})
	_, err = adapter.Create(t.Context(), storage.CreateParams{Model: "thing", Data: data, ForceAllowID: true})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate error = %v", err)
	}
	if got := normalizeError(context.Background(), "update thing", fakeMSSQLError{Number: 2601, message: "duplicate index"}); !errors.Is(got, storage.ErrUniqueConstraint) {
		t.Fatalf("2601 error = %v", got)
	}
	assertExpectations(t, mock)
}

func TestSerialAndUUIDIDModes(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{"empty": {Fields: map[string]storage.FieldAttribute{}}}}

	t.Run("serial-default", func(t *testing.T) {
		db, mock := newMockDB(t)
		adapter, err := New(db, Options{Schema: schema, IDType: SerialID})
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery("INSERT INTO [empty] OUTPUT [inserted].[id] DEFAULT VALUES").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
		created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty"})
		if err != nil || created["id"] != "42" || !adapter.Capabilities().NumericIDs {
			t.Fatalf("serial create = %#v, %v; caps=%#v", created, err, adapter.Capabilities())
		}
		assertExpectations(t, mock)
	})

	t.Run("serial-explicit-identity-insert", func(t *testing.T) {
		db, mock := newMockDB(t)
		adapter, err := New(db, Options{Schema: schema, IDType: SerialID})
		if err != nil {
			t.Fatal(err)
		}
		insert := "INSERT INTO [empty] ([id]) OUTPUT [inserted].[id] VALUES (@p1)"
		mock.ExpectQuery(identityInsertBatch("empty", insert)).WithArgs(int64(7)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(7)))
		created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty", Data: storage.Record{"id": "7"}, ForceAllowID: true})
		if err != nil || created["id"] != "7" {
			t.Fatalf("explicit serial create = %#v, %v", created, err)
		}
		assertExpectations(t, mock)
	})

	t.Run("uuid", func(t *testing.T) {
		db, mock := newMockDB(t)
		const identifier = "018fca23-7b2f-4cc0-98c5-001122334455"
		adapter, err := New(db, Options{Schema: schema, IDType: UUIDID, IDGenerator: func(string) (any, error) { return identifier, nil }})
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectQuery("INSERT INTO [empty] ([id]) OUTPUT [inserted].[id] VALUES (@p1)").WithArgs(identifier).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(identifier))
		created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty"})
		if err != nil || created["id"] != identifier {
			t.Fatalf("UUID create = %#v, %v", created, err)
		}
		assertExpectations(t, mock)
	})
}

func TestFindManyPaginationMissingNullAndJoins(t *testing.T) {
	t.Run("zero-limit-does-not-query", func(t *testing.T) {
		adapter, mock := newMockAdapter(t, thingSchema())
		rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "thing", Limit: storage.Int(0), Offset: storage.Int(5)})
		if err != nil || len(rows) != 0 {
			t.Fatalf("zero-limit rows = %#v, %v", rows, err)
		}
		assertExpectations(t, mock)
	})

	t.Run("top", func(t *testing.T) {
		adapter, mock := newMockAdapter(t, thingSchema())
		query := "SELECT TOP (@p3) [id], [name], [__single_present__name], [count], [__single_present__count] FROM [thing] WHERE (CHARINDEX(@p1 COLLATE Latin1_General_100_BIN2, [name] COLLATE Latin1_General_100_BIN2) = 1 AND [count] >= @p2) ORDER BY [count] DESC"
		mock.ExpectQuery(query).WithArgs("T", int64(2), 2).WillReturnRows(
			sqlmock.NewRows([]string{"id", "name", "name_present", "count", "count_present"}).
				AddRow("t2", "Two", 1, int64(2), 1).
				AddRow("t3", "Three", 1, int64(3), 1),
		)
		rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "thing", Where: []storage.Where{
				{Field: "name", Operator: storage.OpStartsWith, Value: "T"},
				{Field: "count", Operator: storage.OpGTE, Value: 2},
			},
			Select: []string{"id", "name", "count"}, SortBy: &storage.Sort{Field: "count", Direction: storage.Descending}, Limit: storage.Int(2),
		})
		if err != nil || len(rows) != 2 || rows[1]["count"] != 3 {
			t.Fatalf("rows = %#v, %v", rows, err)
		}
		assertExpectations(t, mock)
	})

	t.Run("offset-fetch-and-missing-null", func(t *testing.T) {
		schema := storage.Schema{Models: map[string]storage.ModelSchema{
			"optional": {Fields: map[string]storage.FieldAttribute{
				"note": {Type: storage.FieldString, Required: storage.Bool(false)}, "rank": {Type: storage.FieldNumber},
			}},
		}}
		adapter, mock := newMockAdapter(t, schema)
		query := "SELECT [id], [note], [__single_present__note], [rank], [__single_present__rank] FROM [optional] ORDER BY [id] ASC OFFSET @p1 ROWS FETCH NEXT @p2 ROWS ONLY"
		mock.ExpectQuery(query).WithArgs(1, 2).WillReturnRows(
			sqlmock.NewRows([]string{"id", "note", "note_present", "rank", "rank_present"}).
				AddRow("missing", nil, 0, int64(2), 1).
				AddRow("null", nil, 1, int64(1), 1),
		)
		rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "optional", Limit: storage.Int(2), Offset: storage.Int(1)})
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := rows[0]["note"]; exists {
			t.Fatalf("missing note materialized: %#v", rows[0])
		}
		if value, exists := rows[1]["note"]; !exists || value != nil {
			t.Fatalf("explicit null lost: %#v", rows[1])
		}
		assertExpectations(t, mock)
	})

	t.Run("one-to-many", func(t *testing.T) {
		adapter, mock := newMockAdapter(t, relationSchema())
		mock.ExpectQuery("SELECT TOP (@p2) [id], [name], [__single_present__name] FROM [parent] WHERE [id] COLLATE Latin1_General_100_BIN2 = @p1 COLLATE Latin1_General_100_BIN2").WithArgs("p1", 1).
			WillReturnRows(sqlmock.NewRows([]string{"id", "name", "name_present"}).AddRow("p1", "Parent", 1))
		mock.ExpectQuery("SELECT TOP (@p2) [id], [parentId], [__single_present__parentId], [value], [__single_present__value] FROM [child] WHERE [parentId] COLLATE Latin1_General_100_BIN2 = @p1 COLLATE Latin1_General_100_BIN2").WithArgs("p1", 100).
			WillReturnRows(sqlmock.NewRows([]string{"id", "parent_id", "parent_present", "value", "value_present"}).
				AddRow("c1", "p1", 1, "one", 1).AddRow("c2", "p1", 1, "two", 1))
		row, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "parent", Where: []storage.Where{{Field: "id", Value: "p1"}}, Join: map[string]storage.JoinOption{"child": {}},
		})
		if err != nil {
			t.Fatal(err)
		}
		children, ok := row["child"].([]storage.Record)
		if !ok || len(children) != 2 || children[1]["value"] != "two" {
			t.Fatalf("join = %#v", row["child"])
		}
		assertExpectations(t, mock)
	})
}

func TestCRUDAndAtomicMutationSQL(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

	updateSQL := "UPDATE [thing] SET [name] = @p1, [__single_present__name] = 1 OUTPUT " + insertedThingProjection + " WHERE [id] COLLATE Latin1_General_100_BIN2 = @p2 COLLATE Latin1_General_100_BIN2"
	mock.ExpectQuery(updateSQL).WithArgs("Renamed", "t1").WillReturnRows(thingRows().AddRow(
		"t1", int64(2), 1, createdAt, 1, nil, 0, int64(1), 1, "Renamed", 1,
	))
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}}, Update: storage.Record{"name": "Renamed"}})
	if err != nil || updated["name"] != "Renamed" {
		t.Fatalf("update = %#v, %v", updated, err)
	}

	mock.ExpectExec("UPDATE [thing] SET [flag] = @p1, [__single_present__flag] = 1 WHERE [count] >= @p2").
		WithArgs(int64(0), int64(1)).WillReturnResult(sqlmock.NewResult(0, 2))
	count, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{Model: "thing", Where: []storage.Where{{Field: "count", Operator: storage.OpGTE, Value: 1}}, Update: storage.Record{"flag": false}})
	if err != nil || count != 2 {
		t.Fatalf("update many = %d, %v", count, err)
	}

	mock.ExpectExec("DELETE FROM [thing] WHERE [id] COLLATE Latin1_General_100_BIN2 = @p1 COLLATE Latin1_General_100_BIN2").WithArgs("t1").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}}}); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("DELETE FROM [thing]").WillReturnResult(sqlmock.NewResult(0, 3))
	count, err = adapter.DeleteMany(t.Context(), storage.DeleteManyParams{Model: "thing"})
	if err != nil || count != 3 {
		t.Fatalf("delete many = %d, %v", count, err)
	}
	mock.ExpectQuery("SELECT COUNT(*) FROM [thing] WHERE [count] > @p1").WithArgs(int64(0)).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(4)))
	count, err = adapter.Count(t.Context(), storage.CountParams{Model: "thing", Where: []storage.Where{{Field: "count", Operator: storage.OpGt, Value: 0}}})
	if err != nil || count != 4 {
		t.Fatalf("count = %d, %v", count, err)
	}

	consumeSQL := "DELETE FROM [thing] WITH (UPDLOCK, ROWLOCK) OUTPUT " + deletedThingProjection + " WHERE [id] IN (SELECT TOP (1) [id] FROM [thing] WITH (UPDLOCK, ROWLOCK) WHERE [name] COLLATE Latin1_General_100_BIN2 = @p1 COLLATE Latin1_General_100_BIN2)"
	mock.ExpectQuery(consumeSQL).WithArgs("one-time").WillReturnRows(thingRows().AddRow(
		"t1", int64(2), 1, createdAt, 1, nil, 0, int64(0), 1, "one-time", 1,
	))
	consumed, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{Model: "thing", Where: []storage.Where{{Field: "name", Value: "one-time"}}})
	if err != nil || consumed["id"] != "t1" {
		t.Fatalf("consume = %#v, %v", consumed, err)
	}

	incrementSQL := "UPDATE TOP (1) [thing] WITH (UPDLOCK, ROWLOCK) SET [count] = COALESCE([count], 0) + @p1, [__single_present__count] = 1 OUTPUT " + insertedThingProjection + " WHERE ([id] COLLATE Latin1_General_100_BIN2 = @p2 COLLATE Latin1_General_100_BIN2 AND [count] > @p3)"
	mock.ExpectQuery(incrementSQL).WithArgs(int64(-1), "t1", int64(0)).WillReturnRows(thingRows().AddRow(
		"t1", int64(1), 1, createdAt, 1, nil, 0, int64(0), 1, "counter", 1,
	))
	incremented, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}, {Field: "count", Operator: storage.OpGt, Value: 0}}, Increment: map[string]float64{"count": -1},
	})
	if err != nil || incremented["count"] != 1 {
		t.Fatalf("increment = %#v, %v", incremented, err)
	}

	mock.ExpectQuery(consumeSQL).WithArgs("missing").WillReturnRows(thingRows())
	missing, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{Model: "thing", Where: []storage.Where{{Field: "name", Value: "missing"}}})
	if err != nil || missing != nil {
		t.Fatalf("missing consume = %#v, %v", missing, err)
	}
	assertExpectations(t, mock)
}

func TestTransactionCommitAndRollback(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	sentinel := errors.New("rollback")
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery(createThingSQL).
		WithArgs(int64(1), createdAt.Format(time.RFC3339Nano), `{"tx":true}`, int64(0), "tx", "Transaction").
		WillReturnRows(thingRows().AddRow("tx", int64(1), 1, createdAt, 1, []byte(`{"tx":true}`), 1, int64(0), 1, "Transaction", 1))
	mock.ExpectRollback()
	err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
		_, createErr := transaction.Create(t.Context(), storage.CreateParams{
			Model: "thing", Data: storage.Record{"id": "tx", "count": 1, "created": createdAt, "data": map[string]any{"tx": true}, "flag": false, "name": "Transaction"}, ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("rollback error = %v", err)
	}
	mock.ExpectBegin()
	mock.ExpectCommit()
	if err := adapter.Transaction(t.Context(), func(storage.TransactionAdapter) error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

func TestCapabilitiesCancellationAndConcurrentReads(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	capabilities := adapter.Capabilities()
	if capabilities.NumericIDs || capabilities.UUIDs || capabilities.JSON || capabilities.Dates || capabilities.Booleans || capabilities.Arrays || !capabilities.Transactions || !capabilities.Joins || !capabilities.SchemaCreation || !capabilities.AtomicConsumeOne || !capabilities.AtomicIncrement {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := adapter.FindMany(ctx, storage.FindManyParams{Model: "thing"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}

	mock.MatchExpectationsInOrder(false)
	const racers = 24
	for range racers {
		mock.ExpectQuery("SELECT COUNT(*) FROM [thing]").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	}
	start := make(chan struct{})
	errorsChannel := make(chan error, racers)
	var wait sync.WaitGroup
	for range racers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			count, err := adapter.Count(context.Background(), storage.CountParams{Model: "thing"})
			if err != nil {
				errorsChannel <- err
			} else if count != 1 {
				errorsChannel <- fmt.Errorf("count = %d", count)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
	assertExpectations(t, mock)
}

func TestInFlightContextCancellationIsPreserved(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	mock.ExpectQuery("SELECT COUNT(*) FROM [thing]").WillDelayFor(50 * time.Millisecond).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := adapter.Count(ctx, storage.CountParams{Model: "thing"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v", err)
	}
	assertExpectations(t, mock)
}

func thingSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {ModelName: "thing", Fields: map[string]storage.FieldAttribute{
			"count": {Type: storage.FieldNumber, Required: storage.Bool(false)}, "created": {Type: storage.FieldDate},
			"data": {Type: storage.FieldJSON, Required: storage.Bool(false)}, "flag": {Type: storage.FieldBoolean, Required: storage.Bool(false)},
			"name": {Type: storage.FieldString, Unique: true},
		}},
	}}
}

func relationSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"parent": {Fields: map[string]storage.FieldAttribute{"name": {Type: storage.FieldString}}},
		"child": {Fields: map[string]storage.FieldAttribute{
			"parentId": {Type: storage.FieldString, References: &storage.Reference{Model: "parent", Field: "id"}}, "value": {Type: storage.FieldString},
		}},
	}}
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func newMockAdapter(t *testing.T, schema storage.Schema) (*Adapter, sqlmock.Sqlmock) {
	t.Helper()
	db, mock := newMockDB(t)
	adapter, err := New(db, Options{Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	return adapter, mock
}

func thingRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "count", "count_present", "created", "created_present", "data", "data_present",
		"flag", "flag_present", "name", "name_present",
	})
}

func assertExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

type fakeMSSQLError struct {
	Number  int32
	message string
}

func (e fakeMSSQLError) Error() string { return e.message }
