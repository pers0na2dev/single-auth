package mysql

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

const thingProjection = "`id`, `count`, `__single_present__count`, `created`, `__single_present__created`, `data`, `__single_present__data`, `flag`, `__single_present__flag`, `name`, `__single_present__name`"

const createThingSQL = "INSERT INTO `thing` (`count`, `__single_present__count`, `created`, `__single_present__created`, `data`, `__single_present__data`, `flag`, `__single_present__flag`, `id`, `name`, `__single_present__name`) VALUES (?, TRUE, ?, TRUE, ?, TRUE, ?, TRUE, ?, ?, TRUE)"

func TestCreateRoundTripAndUniqueNormalization(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 123_000_000, time.UTC)
	data := storage.Record{
		"id": "t1", "count": 2, "created": createdAt,
		"data": map[string]any{"enabled": true}, "flag": true, "name": "Thing",
	}
	mock.ExpectBegin()
	mock.ExpectExec(createThingSQL).
		WithArgs(int64(2), createdAt, `{"enabled":true}`, int64(1), "t1", "Thing").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT " + thingProjection + " FROM `thing` WHERE BINARY `id` = BINARY ? LIMIT 1").
		WithArgs("t1").
		WillReturnRows(thingRows().AddRow(
			[]byte("t1"), []byte("2"), []byte("1"), []byte("2026-08-08 12:00:00.123"), true,
			[]byte(`{"enabled":true}`), 1, []byte("1"), true, []byte("Thing"), true,
		))
	mock.ExpectCommit()
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
	if got, ok := created["created"].(time.Time); !ok || !got.Equal(createdAt) {
		t.Fatalf("created date = %#v", created["created"])
	}

	mock.ExpectBegin()
	mock.ExpectExec(createThingSQL).
		WithArgs(int64(2), createdAt, `{"enabled":true}`, int64(1), "t1", "Thing").
		WillReturnError(fakeMySQLError{Number: 1062, message: "Duplicate entry 't1' for key 'PRIMARY'"})
	mock.ExpectRollback()
	_, err = adapter.Create(t.Context(), storage.CreateParams{Model: "thing", Data: data, ForceAllowID: true})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate error = %v", err)
	}
	assertExpectations(t, mock)
}

func TestSerialAndUUIDIDModes(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{"empty": {Fields: map[string]storage.FieldAttribute{}}}}

	t.Run("serial", func(t *testing.T) {
		db, mock := newMockDB(t)
		adapter, err := New(db, Options{Schema: schema, IDType: SerialID})
		if err != nil {
			t.Fatal(err)
		}
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO `empty` () VALUES ()").WillReturnResult(sqlmock.NewResult(42, 1))
		mock.ExpectQuery("SELECT `id` FROM `empty` WHERE `id` = ? LIMIT 1").WithArgs(int64(42)).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
		mock.ExpectCommit()
		created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty"})
		if err != nil || created["id"] != "42" || !adapter.Capabilities().NumericIDs {
			t.Fatalf("serial create = %#v, %v; caps=%#v", created, err, adapter.Capabilities())
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
		mock.ExpectBegin()
		mock.ExpectExec("INSERT INTO `empty` (`id`) VALUES (?)").WithArgs(identifier).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("SELECT `id` FROM `empty` WHERE BINARY `id` = BINARY ? LIMIT 1").WithArgs(identifier).
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(identifier))
		mock.ExpectCommit()
		created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty"})
		if err != nil || created["id"] != identifier {
			t.Fatalf("UUID create = %#v, %v", created, err)
		}
		assertExpectations(t, mock)
	})
}

func TestUpdateLocksThenReturnsMutatedRow(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT `id` FROM `thing` WHERE BINARY `id` = BINARY ? LIMIT 1 FOR UPDATE").WithArgs("t1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow([]byte("t1")))
	mock.ExpectExec("UPDATE `thing` SET `name` = ?, `__single_present__name` = TRUE WHERE BINARY `id` = BINARY ?").
		WithArgs("Renamed", "t1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT " + thingProjection + " FROM `thing` WHERE BINARY `id` = BINARY ? LIMIT 1").WithArgs("t1").
		WillReturnRows(thingRows().AddRow("t1", int64(2), true, createdAt, true, nil, false, int64(1), true, "Renamed", true))
	mock.ExpectCommit()
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}}, Update: storage.Record{"name": "Renamed"},
	})
	if err != nil || updated["name"] != "Renamed" {
		t.Fatalf("update = %#v, %v", updated, err)
	}
	assertExpectations(t, mock)
}

func TestConsumeAndIncrementAreTransactional(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT " + thingProjection + " FROM `thing` WHERE BINARY `name` = BINARY ? LIMIT 1 FOR UPDATE").WithArgs("one-time").
		WillReturnRows(thingRows().AddRow("t1", int64(2), true, createdAt, true, nil, false, int64(0), true, "one-time", true))
	mock.ExpectExec("DELETE FROM `thing` WHERE BINARY `id` = BINARY ?").WithArgs("t1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	consumed, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{Model: "thing", Where: []storage.Where{{Field: "name", Value: "one-time"}}})
	if err != nil || consumed["id"] != "t1" {
		t.Fatalf("consume = %#v, %v", consumed, err)
	}

	mock.ExpectBegin()
	mock.ExpectQuery("SELECT `id` FROM `thing` WHERE (BINARY `id` = BINARY ? AND `count` > ?) LIMIT 1 FOR UPDATE").
		WithArgs("t1", int64(0)).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow([]byte("t1")))
	mock.ExpectExec("UPDATE `thing` SET `count` = COALESCE(`count`, 0) + ?, `__single_present__count` = TRUE WHERE BINARY `id` = BINARY ?").
		WithArgs(int64(-1), "t1").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT " + thingProjection + " FROM `thing` WHERE BINARY `id` = BINARY ? LIMIT 1").WithArgs("t1").
		WillReturnRows(thingRows().AddRow("t1", int64(1), true, createdAt, true, nil, false, int64(0), true, "counter", true))
	mock.ExpectCommit()
	incremented, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}, {Field: "count", Operator: storage.OpGt, Value: 0}}, Increment: map[string]float64{"count": -1},
	})
	if err != nil || incremented["count"] != 1 {
		t.Fatalf("increment = %#v, %v", incremented, err)
	}
	assertExpectations(t, mock)
}

func TestTransactionAdapterDoesNotNestPrivateTransactions(t *testing.T) {
	adapter, mock := newMockAdapter(t, storage.Schema{Models: map[string]storage.ModelSchema{"empty": {Fields: map[string]storage.FieldAttribute{}}}})
	sentinel := errors.New("rollback")
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO `empty` (`id`) VALUES (?)").WithArgs("inside").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT `id` FROM `empty` WHERE BINARY `id` = BINARY ? LIMIT 1").WithArgs("inside").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("inside"))
	mock.ExpectRollback()
	err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
		_, createErr := transaction.Create(t.Context(), storage.CreateParams{Model: "empty", Data: storage.Record{"id": "inside"}, ForceAllowID: true})
		if createErr != nil {
			return createErr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("transaction error = %v", err)
	}
	assertExpectations(t, mock)
}

func TestFindManyPaginationMissingNullAndJoins(t *testing.T) {
	t.Run("pagination-and-missing-null", func(t *testing.T) {
		schema := storage.Schema{Models: map[string]storage.ModelSchema{
			"optional": {Fields: map[string]storage.FieldAttribute{
				"note": {Type: storage.FieldString, Required: storage.Bool(false)}, "rank": {Type: storage.FieldNumber},
			}},
		}}
		adapter, mock := newMockAdapter(t, schema)
		query := "SELECT `id`, `note`, `__single_present__note`, `rank`, `__single_present__rank` FROM `optional` ORDER BY `rank` DESC LIMIT ? OFFSET ?"
		mock.ExpectQuery(query).WithArgs(2, 1).WillReturnRows(
			sqlmock.NewRows([]string{"id", "note", "note_present", "rank", "rank_present"}).
				AddRow("missing", nil, false, int64(2), true).
				AddRow("null", nil, true, int64(1), true),
		)
		rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "optional", SortBy: &storage.Sort{Field: "rank", Direction: storage.Descending}, Limit: storage.Int(2), Offset: storage.Int(1),
		})
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
		mock.ExpectQuery("SELECT `id`, `name`, `__single_present__name` FROM `parent` WHERE BINARY `id` = BINARY ? LIMIT ?").WithArgs("p1", 1).
			WillReturnRows(sqlmock.NewRows([]string{"id", "name", "name_present"}).AddRow("p1", "Parent", true))
		mock.ExpectQuery("SELECT `id`, `parentId`, `__single_present__parentId`, `value`, `__single_present__value` FROM `child` WHERE BINARY `parentId` = BINARY ? LIMIT ?").WithArgs("p1", 100).
			WillReturnRows(sqlmock.NewRows([]string{"id", "parent_id", "parent_present", "value", "value_present"}).
				AddRow("c1", "p1", true, "one", true).AddRow("c2", "p1", true, "two", true))
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

func TestManyMutationsAndCount(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	mock.ExpectExec("UPDATE `thing` SET `flag` = ?, `__single_present__flag` = TRUE WHERE `count` >= ?").
		WithArgs(int64(0), int64(1)).WillReturnResult(sqlmock.NewResult(0, 2))
	count, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{
		Model: "thing", Where: []storage.Where{{Field: "count", Operator: storage.OpGTE, Value: 1}}, Update: storage.Record{"flag": false},
	})
	if err != nil || count != 2 {
		t.Fatalf("update many = %d, %v", count, err)
	}
	mock.ExpectExec("DELETE FROM `thing` WHERE BINARY `id` = BINARY ?").WithArgs("t1").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}}}); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec("DELETE FROM `thing`").WillReturnResult(sqlmock.NewResult(0, 3))
	count, err = adapter.DeleteMany(t.Context(), storage.DeleteManyParams{Model: "thing"})
	if err != nil || count != 3 {
		t.Fatalf("delete many = %d, %v", count, err)
	}
	mock.ExpectQuery("SELECT COUNT(*) FROM `thing` WHERE `count` > ?").WithArgs(int64(0)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(4)))
	count, err = adapter.Count(t.Context(), storage.CountParams{Model: "thing", Where: []storage.Where{{Field: "count", Operator: storage.OpGt, Value: 0}}})
	if err != nil || count != 4 {
		t.Fatalf("count = %d, %v", count, err)
	}
	assertExpectations(t, mock)
}

func TestCapabilitiesAndConcurrentReads(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	capabilities := adapter.Capabilities()
	if capabilities.NumericIDs || capabilities.UUIDs || capabilities.JSON || !capabilities.Dates || capabilities.Booleans || capabilities.Arrays || !capabilities.Transactions || !capabilities.AtomicConsumeOne || !capabilities.AtomicIncrement {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	mock.MatchExpectationsInOrder(false)
	const racers = 24
	for range racers {
		mock.ExpectQuery("SELECT COUNT(*) FROM `thing`").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
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

func TestCancelledContextDoesNotReachDatabase(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := adapter.FindMany(ctx, storage.FindManyParams{Model: "thing"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
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
			"parentId": {Type: storage.FieldString, References: &storage.Reference{Model: "parent", Field: "id"}},
			"value":    {Type: storage.FieldString},
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

type fakeMySQLError struct {
	Number  uint16
	message string
}

func (e fakeMySQLError) Error() string { return e.message }
