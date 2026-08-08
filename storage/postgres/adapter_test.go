package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/pers0na2dev/single-auth/storage"
)

const thingProjection = `"id", "count", "__single_present__count", "created", "__single_present__created", "data", "__single_present__data", "flag", "__single_present__flag", "name", "__single_present__name"`

const createThingSQL = `INSERT INTO "public"."thing" ("count", "__single_present__count", "created", "__single_present__created", "data", "__single_present__data", "flag", "__single_present__flag", "id", "name", "__single_present__name") VALUES ($1, TRUE, $2, TRUE, $3::jsonb, TRUE, $4, TRUE, $5, $6, TRUE) RETURNING ` + thingProjection

func TestCreateRoundTripAndUniqueNormalization(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 123, time.UTC)
	data := storage.Record{
		"id": "t1", "count": 2, "created": createdAt,
		"data": map[string]any{"enabled": true}, "flag": true, "name": "Thing",
	}
	mock.ExpectQuery(createThingSQL).
		WithArgs(int64(2), createdAt, `{"enabled":true}`, true, "t1", "Thing").
		WillReturnRows(thingRows().AddRow(
			"t1", float64(2), true, createdAt, true, []byte(`{"enabled":true}`), true, true, true, "Thing", true,
		))
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "thing", Data: data, ForceAllowID: true,
	})
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

	mock.ExpectQuery(createThingSQL).
		WithArgs(int64(2), createdAt, `{"enabled":true}`, true, "t1", "Thing").
		WillReturnError(fakePostgresError{state: "23505", message: "duplicate"})
	_, err = adapter.Create(t.Context(), storage.CreateParams{
		Model: "thing", Data: data, ForceAllowID: true,
	})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate error = %v", err)
	}
	assertExpectations(t, mock)
}

func TestFindManyUsesPostgresPlaceholdersAndPagination(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	query := `SELECT "id", "name", "__single_present__name", "count", "__single_present__count" FROM "public"."thing" WHERE ("name" LIKE $1 AND "count" >= $2) ORDER BY "count" DESC LIMIT $3 OFFSET $4`
	mock.ExpectQuery(query).
		WithArgs("T%", int64(2), 2, 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "name_present", "count", "count_present"}).
			AddRow("t2", "Two", true, float64(2), true).
			AddRow("t3", "Three", true, float64(3), true))
	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "thing",
		Where: []storage.Where{
			{Field: "name", Operator: storage.OpStartsWith, Value: "T"},
			{Field: "count", Operator: storage.OpGTE, Value: 2},
		},
		Select: []string{"id", "name", "count"},
		SortBy: &storage.Sort{Field: "count", Direction: storage.Descending},
		Limit:  storage.Int(2), Offset: storage.Int(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["id"] != "t2" || rows[1]["count"] != 3 {
		t.Fatalf("rows = %#v", rows)
	}
	assertExpectations(t, mock)
}

func TestMissingAndExplicitNullRemainDistinct(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"optional": {Fields: map[string]storage.FieldAttribute{
			"note": {Type: storage.FieldString, Required: storage.Bool(false)},
		}},
	}}
	adapter, mock := newMockAdapter(t, schema)
	query := `SELECT "id", "note", "__single_present__note" FROM "public"."optional" LIMIT $1`
	mock.ExpectQuery(query).WithArgs(100).WillReturnRows(
		sqlmock.NewRows([]string{"id", "note", "note_present"}).
			AddRow("missing", nil, false).
			AddRow("null", nil, true),
	)
	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "optional"})
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
}

func TestCRUDMutationSQL(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

	updateSQL := `UPDATE "public"."thing" SET "name" = $1, "__single_present__name" = TRUE WHERE "id" = $2 RETURNING ` + thingProjection
	mock.ExpectQuery(updateSQL).WithArgs("Renamed", "t1").WillReturnRows(thingRows().AddRow(
		"t1", float64(2), true, createdAt, true, nil, false, true, true, "Renamed", true,
	))
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}}, Update: storage.Record{"name": "Renamed"},
	})
	if err != nil || updated["name"] != "Renamed" {
		t.Fatalf("update = %#v, %v", updated, err)
	}

	updateManySQL := `UPDATE "public"."thing" SET "flag" = $1, "__single_present__flag" = TRUE WHERE "count" >= $2`
	mock.ExpectExec(updateManySQL).WithArgs(false, int64(1)).WillReturnResult(sqlmock.NewResult(0, 2))
	count, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{
		Model: "thing", Where: []storage.Where{{Field: "count", Operator: storage.OpGTE, Value: 1}}, Update: storage.Record{"flag": false},
	})
	if err != nil || count != 2 {
		t.Fatalf("update many = %d, %v", count, err)
	}

	mock.ExpectExec(`DELETE FROM "public"."thing" WHERE "id" = $1`).WithArgs("t1").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "thing", Where: []storage.Where{{Field: "id", Value: "t1"}}}); err != nil {
		t.Fatal(err)
	}
	mock.ExpectExec(`DELETE FROM "public"."thing" WHERE "flag" = $1`).WithArgs(false).WillReturnResult(sqlmock.NewResult(0, 3))
	count, err = adapter.DeleteMany(t.Context(), storage.DeleteManyParams{Model: "thing", Where: []storage.Where{{Field: "flag", Value: false}}})
	if err != nil || count != 3 {
		t.Fatalf("delete many = %d, %v", count, err)
	}
	mock.ExpectQuery(`SELECT COUNT(*) FROM "public"."thing" WHERE "count" > $1`).WithArgs(int64(0)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(4)))
	count, err = adapter.Count(t.Context(), storage.CountParams{Model: "thing", Where: []storage.Where{{Field: "count", Operator: storage.OpGt, Value: 0}}})
	if err != nil || count != 4 {
		t.Fatalf("count = %d, %v", count, err)
	}
	assertExpectations(t, mock)
}

func TestAtomicConsumeAndIncrementSQL(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	createdAt := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	qualified := `"target_row"."id", "target_row"."count", "target_row"."__single_present__count", "target_row"."created", "target_row"."__single_present__created", "target_row"."data", "target_row"."__single_present__data", "target_row"."flag", "target_row"."__single_present__flag", "target_row"."name", "target_row"."__single_present__name"`
	consumeSQL := `WITH "single_target" AS (SELECT "id" FROM "public"."thing" WHERE "name" = $1 LIMIT 1 FOR UPDATE) DELETE FROM "public"."thing" AS "target_row" USING "single_target" WHERE "target_row"."id" = "single_target"."id" RETURNING ` + qualified
	mock.ExpectQuery(consumeSQL).WithArgs("one-time").WillReturnRows(thingRows().AddRow(
		"t1", float64(2), true, createdAt, true, nil, false, false, true, "one-time", true,
	))
	consumed, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{
		Model: "thing", Where: []storage.Where{{Field: "name", Value: "one-time"}},
	})
	if err != nil || consumed["id"] != "t1" {
		t.Fatalf("consume = %#v, %v", consumed, err)
	}

	incrementSQL := `WITH "single_target" AS (SELECT "id" FROM "public"."thing" WHERE ("id" = $2 AND "count" > $3) LIMIT 1 FOR UPDATE) UPDATE "public"."thing" AS "target_row" SET "count" = COALESCE("target_row"."count", 0) + $1, "__single_present__count" = TRUE FROM "single_target" WHERE "target_row"."id" = "single_target"."id" RETURNING ` + qualified
	mock.ExpectQuery(incrementSQL).WithArgs(int64(-1), "t1", int64(0)).WillReturnRows(thingRows().AddRow(
		"t1", float64(1), true, createdAt, true, nil, false, false, true, "counter", true,
	))
	incremented, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model:     "thing",
		Where:     []storage.Where{{Field: "id", Value: "t1"}, {Field: "count", Operator: storage.OpGt, Value: 0}},
		Increment: map[string]float64{"count": -1},
	})
	if err != nil || incremented["count"] != 1 {
		t.Fatalf("increment = %#v, %v", incremented, err)
	}

	mock.ExpectQuery(consumeSQL).WithArgs("missing").WillReturnRows(thingRows())
	missing, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{
		Model: "thing", Where: []storage.Where{{Field: "name", Value: "missing"}},
	})
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
		WithArgs(int64(1), createdAt, `{"tx":true}`, false, "tx", "Transaction").
		WillReturnRows(thingRows().AddRow(
			"tx", float64(1), true, createdAt, true, []byte(`{"tx":true}`), true, false, true, "Transaction", true,
		))
	mock.ExpectRollback()
	if err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
		_, err := transaction.Create(t.Context(), storage.CreateParams{
			Model: "thing",
			Data: storage.Record{
				"id": "tx", "count": 1, "created": createdAt, "data": map[string]any{"tx": true}, "flag": false, "name": "Transaction",
			},
			ForceAllowID: true,
		})
		if err != nil {
			return err
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("rollback error = %v", err)
	}
	mock.ExpectBegin()
	mock.ExpectCommit()
	if err := adapter.Transaction(t.Context(), func(storage.TransactionAdapter) error { return nil }); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

func TestJoinsUsePostgresPlaceholders(t *testing.T) {
	schema := relationSchema()
	adapter, mock := newMockAdapter(t, schema)
	baseQuery := `SELECT "id", "name", "__single_present__name" FROM "public"."parent" WHERE "id" = $1 LIMIT $2`
	mock.ExpectQuery(baseQuery).WithArgs("p1", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "name_present"}).AddRow("p1", "Parent", true))
	joinQuery := `SELECT "id", "parentId", "__single_present__parentId", "value", "__single_present__value" FROM "public"."child" WHERE "parentId" = $1 LIMIT $2`
	mock.ExpectQuery(joinQuery).WithArgs("p1", 100).
		WillReturnRows(sqlmock.NewRows([]string{"id", "parent_id", "parent_present", "value", "value_present"}).
			AddRow("c1", "p1", true, "one", true).
			AddRow("c2", "p1", true, "two", true))
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
}

func TestMultipleJoinsUseIndependentQueries(t *testing.T) {
	schema := relationSchema()
	schema.Models["account"] = storage.ModelSchema{Fields: map[string]storage.FieldAttribute{
		"parentId": {Type: storage.FieldString, References: &storage.Reference{Model: "parent", Field: "id"}},
		"provider": {Type: storage.FieldString},
	}}
	adapter, mock := newMockAdapter(t, schema)
	mock.ExpectQuery(`SELECT "id", "name", "__single_present__name" FROM "public"."parent" WHERE "id" = $1 LIMIT $2`).
		WithArgs("p1", 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "name", "name_present"}).AddRow("p1", "Parent", true))
	mock.ExpectQuery(`SELECT "id", "parentId", "__single_present__parentId", "provider", "__single_present__provider" FROM "public"."account" WHERE "parentId" = $1 LIMIT $2`).
		WithArgs("p1", 100).
		WillReturnRows(sqlmock.NewRows([]string{"id", "parent_id", "parent_present", "provider", "provider_present"}).
			AddRow("a1", "p1", true, "github", true))
	mock.ExpectQuery(`SELECT "id", "parentId", "__single_present__parentId", "value", "__single_present__value" FROM "public"."child" WHERE "parentId" = $1 LIMIT $2`).
		WithArgs("p1", 100).
		WillReturnRows(sqlmock.NewRows([]string{"id", "parent_id", "parent_present", "value", "value_present"}).
			AddRow("c1", "p1", true, "one", true))

	row, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "parent", Where: []storage.Where{{Field: "id", Value: "p1"}},
		Join: map[string]storage.JoinOption{"child": {}, "account": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	accounts, accountOK := row["account"].([]storage.Record)
	children, childOK := row["child"].([]storage.Record)
	if !accountOK || len(accounts) != 1 || accounts[0]["provider"] != "github" ||
		!childOK || len(children) != 1 || children[0]["value"] != "one" {
		t.Fatalf("multiple joins = %#v", row)
	}
	assertExpectations(t, mock)
}

func TestSerialIDReferencesDecodeAsStrings(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	adapter, err := New(db, Options{Schema: relationSchema(), IDType: SerialID})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`SELECT "id", "parentId", "__single_present__parentId", "value", "__single_present__value" FROM "public"."child" WHERE "id" = $1 LIMIT $2`).
		WithArgs(int64(9), 1).
		WillReturnRows(sqlmock.NewRows([]string{"id", "parent_id", "parent_present", "value", "value_present"}).
			AddRow(int64(9), int64(42), true, "child", true))

	row, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "child", Where: []storage.Where{{Field: "id", Value: "9"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row["id"] != "9" || row["parentId"] != "42" {
		t.Fatalf("serial row = %#v", row)
	}
	assertExpectations(t, mock)
}

func TestBigIntIncrementRejectsFractionalDelta(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {Fields: map[string]storage.FieldAttribute{
			"count": {Type: storage.FieldNumber, BigInt: true, Required: storage.Bool(false)},
		}},
	}}
	adapter, mock := newMockAdapter(t, schema)
	_, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
		Model: "thing", Where: []storage.Where{{Field: "id", Value: "one"}}, Increment: map[string]float64{"count": 0.5},
	})
	if !errors.Is(err, storage.ErrInvalidIncrement) {
		t.Fatalf("fractional BIGINT error = %v", err)
	}
	assertExpectations(t, mock)
}

func TestEnsureSchemaExecutesPlanTransactionally(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	plan, err := PlanSchema(thingSchema())
	if err != nil {
		t.Fatal(err)
	}
	expectEmptyPostgresCatalog(mock, "auth", "public")
	mock.ExpectBegin()
	for _, statement := range plan.Statements {
		mock.ExpectExec(statement).WillReturnResult(sqlmock.NewResult(0, 0))
	}
	mock.ExpectCommit()
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	artifact, err := adapter.CreateSchema(t.Context(), thingSchema(), "schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Code != plan.SQL() || artifact.Path != "schema.sql" || !artifact.Append || artifact.Overwrite {
		t.Fatalf("artifact = %#v", artifact)
	}
	assertExpectations(t, mock)
}

func TestEnsureSchemaRollsBackOnDDLFailure(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	plan, err := PlanSchema(thingSchema())
	if err != nil {
		t.Fatal(err)
	}
	expectEmptyPostgresCatalog(mock, "auth", "public")
	mock.ExpectBegin()
	mock.ExpectExec(plan.Statements[0]).WillReturnError(errors.New("ddl failed"))
	mock.ExpectRollback()
	if err := adapter.EnsureSchema(t.Context()); err == nil {
		t.Fatal("schema creation unexpectedly succeeded")
	}
	assertExpectations(t, mock)
}

func TestEnsureSchemaReconcilesAdditiveFieldThenNoops(t *testing.T) {
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
	adapter, mock := newMockAdapter(t, schema)

	expectPostgresCatalog(mock, "auth", "public", []postgresCatalogColumn{
		{table: "child", column: "id", dataType: "text"},
		{table: "parent", column: "id", dataType: "text"},
	})
	expectPostgresMigrationMetadata(mock, "auth", "public", false)
	child, err := resolveModel(adapter.config, "child")
	if err != nil {
		t.Fatal(err)
	}
	parentID, err := resolveField(adapter.config, child, "parentId")
	if err != nil {
		t.Fatal(err)
	}
	foreignKey, err := postgresMigrationForeignKeyStatement(adapter.config, child, parentID)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectBegin()
	mock.ExpectExec(`ALTER TABLE "public"."child" ADD COLUMN "parentId" TEXT`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`ALTER TABLE "public"."child" ADD COLUMN "__single_present__parentId" BOOLEAN NOT NULL DEFAULT FALSE`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS "single_child_parentId_idx" ON "public"."child" ("parentId")`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(foreignKey).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	expectPostgresCatalog(mock, "auth", "public", []postgresCatalogColumn{
		{table: "child", column: "id", dataType: "text"},
		{table: "child", column: "parentId", dataType: "text"},
		{table: "child", column: "__single_present__parentId", dataType: "boolean"},
		{table: "parent", column: "id", dataType: "text"},
	})
	expectPostgresMigrationMetadata(mock, "auth", "public", true)
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

type postgresCatalogColumn struct {
	table    string
	column   string
	dataType string
}

func expectPostgresCatalog(mock sqlmock.Sqlmock, database, schema string, columns []postgresCatalogColumn) {
	mock.ExpectQuery(`SELECT current_database()`).
		WillReturnRows(sqlmock.NewRows([]string{"current_database"}).AddRow(database))
	rows := sqlmock.NewRows([]string{"table_catalog", "table_schema", "table_name", "column_name", "data_type"})
	for _, column := range columns {
		rows.AddRow(database, schema, column.table, column.column, column.dataType)
	}
	mock.ExpectQuery(`SELECT table_catalog, table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE table_catalog = $1 AND table_schema = $2
ORDER BY table_name, ordinal_position`).
		WithArgs(database, schema).
		WillReturnRows(rows)
}

func expectPostgresMigrationMetadata(mock sqlmock.Sqlmock, database, schema string, present bool) {
	indexes := sqlmock.NewRows([]string{"schemaname", "tablename", "indexname"})
	foreignKeys := sqlmock.NewRows([]string{
		"table_schema", "table_name", "column_name", "target_schema", "target_table", "target_column",
	})
	if present {
		indexes.AddRow(schema, "child", "single_child_parentId_idx")
		foreignKeys.AddRow(schema, "child", "parentId", schema, "parent", "id")
	}
	mock.ExpectQuery(postgresMigrationIndexesQuery).
		WithArgs(schema).
		WillReturnRows(indexes)
	mock.ExpectQuery(postgresMigrationForeignKeysQuery).
		WithArgs(database, schema).
		WillReturnRows(foreignKeys)
}

func expectEmptyPostgresCatalog(mock sqlmock.Sqlmock, database, schema string) {
	expectPostgresCatalog(mock, database, schema, nil)
}

func TestAdapterIsRaceSafeForConcurrentReads(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	mock.MatchExpectationsInOrder(false)
	const racers = 32
	for range racers {
		mock.ExpectQuery(`SELECT COUNT(*) FROM "public"."thing"`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
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

func TestInFlightContextCancellationIsPreserved(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	mock.ExpectQuery(`SELECT COUNT(*) FROM "public"."thing"`).
		WillDelayFor(50 * time.Millisecond).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := adapter.Count(ctx, storage.CountParams{Model: "thing"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline error = %v", err)
	}
	assertExpectations(t, mock)
}

func TestCapabilitiesMatchNativePostgresScalars(t *testing.T) {
	adapter, mock := newMockAdapter(t, thingSchema())
	capabilities := adapter.Capabilities()
	if capabilities.NumericIDs || !capabilities.UUIDs || !capabilities.JSON || !capabilities.Dates || !capabilities.Booleans || capabilities.Arrays {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	assertExpectations(t, mock)
}

func TestSerialIDUsesDefaultValuesAndDecodesAsString(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"empty": {Fields: map[string]storage.FieldAttribute{}},
	}}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	adapter, err := New(db, Options{Schema: schema, IDType: SerialID})
	if err != nil {
		t.Fatal(err)
	}
	if !adapter.Capabilities().NumericIDs {
		t.Fatal("serial adapter does not advertise numeric IDs")
	}
	mock.ExpectQuery(`INSERT INTO "public"."empty" DEFAULT VALUES RETURNING "id"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(int64(42)))
	created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if created["id"] != "42" {
		t.Fatalf("serial ID = %#v", created["id"])
	}
	assertExpectations(t, mock)
}

func TestUUIDIDUsesInjectedGenerator(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"empty": {Fields: map[string]storage.FieldAttribute{}},
	}}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	const identifier = "018fca23-7b2f-4cc0-98c5-001122334455"
	adapter, err := New(db, Options{
		Schema: schema, IDType: UUIDID,
		IDGenerator: func(string) (any, error) { return identifier, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery(`INSERT INTO "public"."empty" ("id") VALUES ($1::text::uuid) RETURNING "id"`).WithArgs(identifier).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(identifier))
	created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if created["id"] != identifier {
		t.Fatalf("UUID = %#v", created["id"])
	}
	assertExpectations(t, mock)
}

func TestUUIDIDUsesDatabaseDefaultWithoutGenerator(t *testing.T) {
	schema := storage.Schema{Models: map[string]storage.ModelSchema{
		"empty": {Fields: map[string]storage.FieldAttribute{}},
	}}
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	adapter, err := New(db, Options{Schema: schema, IDType: UUIDID})
	if err != nil {
		t.Fatal(err)
	}
	const identifier = "018fca23-7b2f-4cc0-98c5-001122334455"
	mock.ExpectQuery(`INSERT INTO "public"."empty" DEFAULT VALUES RETURNING "id"`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(identifier))
	created, err := adapter.Create(t.Context(), storage.CreateParams{Model: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if created["id"] != identifier {
		t.Fatalf("database UUID = %#v", created["id"])
	}
	assertExpectations(t, mock)
}

func thingSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"thing": {
			ModelName: "thing",
			Fields: map[string]storage.FieldAttribute{
				"count":   {Type: storage.FieldNumber, Required: storage.Bool(false)},
				"created": {Type: storage.FieldDate},
				"data":    {Type: storage.FieldJSON, Required: storage.Bool(false)},
				"flag":    {Type: storage.FieldBoolean, Required: storage.Bool(false)},
				"name":    {Type: storage.FieldString, Unique: true},
			},
		},
	}}
}

func relationSchema() storage.Schema {
	return storage.Schema{Models: map[string]storage.ModelSchema{
		"parent": {Fields: map[string]storage.FieldAttribute{
			"name": {Type: storage.FieldString},
		}},
		"child": {Fields: map[string]storage.FieldAttribute{
			"parentId": {Type: storage.FieldString, References: &storage.Reference{Model: "parent", Field: "id"}},
			"value":    {Type: storage.FieldString},
		}},
	}}
}

func newMockAdapter(t *testing.T, schema storage.Schema) (*Adapter, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
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

type fakePostgresError struct {
	state   string
	message string
}

func (e fakePostgresError) Error() string    { return e.message }
func (e fakePostgresError) SQLState() string { return e.state }

type fakePQCode string

type fakePQError struct{ Code fakePQCode }

func (e fakePQError) Error() string { return "pq error" }

func TestLibPQStyleCodeFieldNormalizes(t *testing.T) {
	err := normalizeError(context.Background(), "create thing", fakePQError{Code: "23505"})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("lib/pq-style error = %v", err)
	}
}
