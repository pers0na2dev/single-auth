package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	sqliteadapter "github.com/pers0na2dev/single-auth/storage/sqlite"

	_ "modernc.org/sqlite"
)

var databaseSequence atomic.Uint64

func TestAdapterContract(t *testing.T) {
	fixed := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	adaptertest.Run(t, func(t *testing.T, schema storage.Schema) (storage.Adapter, error) {
		t.Helper()
		return newAdapter(t, schema, fixed), nil
	})
}

func TestMissingAndExplicitNullRemainDistinct(t *testing.T) {
	adapter := newAdapter(t, adaptertest.ContractSchema(), time.Now())
	createUser(t, adapter, "missing", storage.Record{})
	createUser(t, adapter, "null", storage.Record{"image": nil})

	missing, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "missing"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := missing["image"]; exists {
		t.Fatalf("missing image was materialized: %#v", missing)
	}
	explicitNull, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: "null"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value, exists := explicitNull["image"]; !exists || value != nil {
		t.Fatalf("explicit null was lost: %#v", explicitNull)
	}
}

func TestCustomPhysicalNamesPluralTablesAndScalarRoundTrip(t *testing.T) {
	schema, err := adaptertest.ContractSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"labels": {Type: storage.FieldStringArray, Required: storage.Bool(false)},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	schema.UsePlural = true
	userSchema := schema.Models["user"]
	userSchema.ModelName = "member"
	email := userSchema.Fields["email"]
	email.FieldName = "email_address"
	userSchema.Fields["email"] = email
	schema.Models["user"] = userSchema

	adapter := newAdapter(t, schema, time.Now())
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "members",
		Data: storage.Record{
			"id":            "u1",
			"name":          "User",
			"email_address": "user@example.com",
			"emailVerified": true,
			"rank":          1,
			"metadata":      map[string]any{"enabled": true},
			"labels":        []string{"one", "two"},
		},
		ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created["email"] != "user@example.com" {
		t.Fatalf("canonical email missing: %#v", created)
	}
	if _, leaked := created["email_address"]; leaked {
		t.Fatalf("physical alias leaked: %#v", created)
	}
	if created["emailVerified"] != true {
		t.Fatalf("boolean = %#v", created["emailVerified"])
	}
	if !reflect.DeepEqual(created["metadata"], map[string]any{"enabled": true}) {
		t.Fatalf("JSON = %#v", created["metadata"])
	}
	if !reflect.DeepEqual(created["labels"], []string{"one", "two"}) {
		t.Fatalf("array = %#v", created["labels"])
	}
	if _, ok := created["createdAt"].(time.Time); !ok {
		t.Fatalf("date type = %T", created["createdAt"])
	}
}

func TestPhysicalAliasMayEqualAnotherCanonicalField(t *testing.T) {
	schema, err := adaptertest.ContractSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"first":  {Type: storage.FieldString, Required: storage.Bool(false), FieldName: "second"},
			"second": {Type: storage.FieldString, Required: storage.Bool(false), FieldName: "stored_second"},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	adapter := newAdapter(t, schema, time.Now())
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user",
		Data: userRecord("collision", storage.Record{
			"first": "first-value", "second": "second-value",
		}),
		ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created["first"] != "first-value" || created["second"] != "second-value" {
		t.Fatalf("physical/canonical collision corrupted create: %#v", created)
	}
	updated, err := adapter.Update(t.Context(), storage.UpdateParams{
		Model:  "user",
		Where:  []storage.Where{{Field: "first", Value: "first-value"}},
		Update: storage.Record{"first": "updated-first"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated["first"] != "updated-first" || updated["second"] != "second-value" {
		t.Fatalf("physical/canonical collision corrupted update: %#v", updated)
	}
}

func TestArrayContainsUsesElementEncoding(t *testing.T) {
	schema, err := adaptertest.ContractSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"labels": {Type: storage.FieldStringArray, Required: storage.Bool(false)},
			"scores": {Type: storage.FieldNumberArray, Required: storage.Bool(false)},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	adapter := newAdapter(t, schema, time.Now())
	createUser(t, adapter, "arrays", storage.Record{
		"labels": []string{"one", "Two"},
		"scores": []float64{1, 2.5},
	})

	checks := []storage.Where{
		{Field: "labels", Operator: storage.OpContains, Value: "one"},
		{Field: "labels", Operator: storage.OpContains, Value: "two", Mode: storage.Insensitive},
		{Field: "scores", Operator: storage.OpContains, Value: 2.5},
	}
	for _, where := range checks {
		rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "user", Where: []storage.Where{where},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0]["id"] != "arrays" {
			t.Fatalf("contains %#v returned %#v", where, rows)
		}
	}
}

func TestMixedConnectorGroupsAndMembershipNullSemantics(t *testing.T) {
	adapter := newAdapter(t, adaptertest.ContractSchema(), time.Now())
	createUser(t, adapter, "u1", storage.Record{"rank": 1, "tag": "no"})
	createUser(t, adapter, "u2", storage.Record{"rank": 2, "tag": "yes", "image": nil})
	createUser(t, adapter, "u3", storage.Record{"rank": 2, "tag": "no", "image": "avatar"})

	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "user",
		Where: []storage.Where{
			{Field: "rank", Value: 1},
			{Field: "rank", Value: 2, Connector: storage.Or},
			{Field: "tag", Value: "yes", Connector: storage.And},
		},
		Limit: storage.Int(100),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(rows); !reflect.DeepEqual(got, []string{}) {
		t.Fatalf("AND/OR connector groups returned %v", got)
	}

	membership := []struct {
		name     string
		operator storage.Operator
		value    []any
		want     []string
	}{
		{name: "empty-in", operator: storage.OpIn, value: []any{}, want: []string{}},
		{name: "empty-not-in", operator: storage.OpNotIn, value: []any{}, want: []string{"u1", "u2", "u3"}},
		{name: "null-or-avatar-in", operator: storage.OpIn, value: []any{nil, "avatar"}, want: []string{"u1", "u2", "u3"}},
		{name: "null-or-avatar-not-in", operator: storage.OpNotIn, value: []any{nil, "avatar"}, want: []string{}},
		{name: "other-not-in-includes-null", operator: storage.OpNotIn, value: []any{"other"}, want: []string{"u1", "u2", "u3"}},
	}
	for _, check := range membership {
		t.Run(check.name, func(t *testing.T) {
			rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
				Model:  "user",
				Where:  []storage.Where{{Field: "image", Operator: check.operator, Value: check.value}},
				SortBy: &storage.Sort{Field: "id", Direction: storage.Ascending},
				Limit:  storage.Int(100),
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := ids(rows); !reflect.DeepEqual(got, check.want) {
				t.Fatalf("got %v, want %v", got, check.want)
			}
		})
	}
}

func TestDatesCompareAndSortByInstant(t *testing.T) {
	adapter := newAdapter(t, adaptertest.ContractSchema(), time.Now())
	createUser(t, adapter, "owner", nil)
	zero := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	nanosecond := zero.Add(time.Nanosecond)
	for _, session := range []struct {
		id      string
		expires time.Time
	}{{"s0", zero}, {"s1", nanosecond}} {
		_, err := adapter.Create(t.Context(), storage.CreateParams{
			Model: "session",
			Data: storage.Record{
				"id": session.id, "token": session.id + "-token", "userId": "owner", "expiresAt": session.expires,
			},
			ForceAllowID: true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	equivalent := zero.In(time.FixedZone("plus-two", 2*60*60))
	match, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "expiresAt", Value: equivalent}},
	})
	if err != nil || match == nil || match["id"] != "s0" {
		t.Fatalf("equivalent instant match = %#v, %v", match, err)
	}
	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "session", SortBy: &storage.Sort{Field: "expiresAt", Direction: storage.Ascending},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(rows); !reflect.DeepEqual(got, []string{"s0", "s1"}) {
		t.Fatalf("date order = %v", got)
	}
}

func TestUniqueErrorsNormalizeOnCreateAndUpdate(t *testing.T) {
	adapter := newAdapter(t, adaptertest.ContractSchema(), time.Now())
	createUser(t, adapter, "first", storage.Record{"email": "same@example.com"})
	_, err := adapter.Create(t.Context(), storage.CreateParams{
		Model:        "user",
		Data:         userRecord("second", storage.Record{"email": "same@example.com"}),
		ForceAllowID: true,
	})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate create error = %v", err)
	}
	createUser(t, adapter, "second", storage.Record{"email": "second@example.com"})
	_, err = adapter.Update(t.Context(), storage.UpdateParams{
		Model:  "user",
		Where:  []storage.Where{{Field: "id", Value: "second"}},
		Update: storage.Record{"email": "same@example.com"},
	})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate update error = %v", err)
	}
}

func TestAtomicOperationsAcrossAdapterInstances(t *testing.T) {
	db := openDatabase(t)
	schema := adaptertest.ContractSchema()
	adapters := make([]*sqliteadapter.Adapter, 8)
	for index := range adapters {
		adapter, err := sqliteadapter.New(db, sqliteadapter.Options{Schema: schema})
		if err != nil {
			t.Fatal(err)
		}
		adapters[index] = adapter
	}
	if err := adapters[0].EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, err := adapters[0].Create(t.Context(), storage.CreateParams{
		Model: "verification",
		Data: storage.Record{
			"id": "v1", "identifier": "consume-race", "value": "secret",
			"expiresAt": time.Now().Add(time.Hour),
		},
		ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	const racers = 64
	var consumed atomic.Int64
	runRacers(t, racers, func(index int) error {
		row, err := adapters[index%len(adapters)].ConsumeOne(context.Background(), storage.ConsumeOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "consume-race"}},
		})
		if row != nil {
			consumed.Add(1)
		}
		return err
	})
	if consumed.Load() != 1 {
		t.Fatalf("consume winners = %d", consumed.Load())
	}

	createUser(t, adapters[0], "counter", storage.Record{"remaining": 10})
	var incremented atomic.Int64
	runRacers(t, racers, func(index int) error {
		row, err := adapters[index%len(adapters)].IncrementOne(context.Background(), storage.IncrementOneParams{
			Model:     "user",
			Where:     []storage.Where{{Field: "id", Value: "counter"}, {Field: "remaining", Operator: storage.OpGt, Value: 0}},
			Increment: map[string]float64{"remaining": -1},
		})
		if row != nil {
			incremented.Add(1)
		}
		return err
	})
	if incremented.Load() != 10 {
		t.Fatalf("increment winners = %d", incremented.Load())
	}
}

func TestConsumeOneWithNonUniquePredicateDeletesExactlyOneRow(t *testing.T) {
	adapter := newAdapter(t, adaptertest.ContractSchema(), time.Now())
	for _, id := range []string{"verification-1", "verification-2"} {
		_, err := adapter.Create(t.Context(), storage.CreateParams{
			Model: "verification",
			Data: storage.Record{
				"id":         id,
				"identifier": "shared-identifier",
				"value":      id,
				"expiresAt":  time.Now().Add(time.Hour),
			},
			ForceAllowID: true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	consumed, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{
		Model: "verification",
		Where: []storage.Where{{Field: "identifier", Value: "shared-identifier"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if consumed == nil {
		t.Fatal("ConsumeOne returned nil for matching rows")
	}

	remaining, err := adapter.FindMany(t.Context(), storage.FindManyParams{
		Model: "verification",
		Where: []storage.Where{{Field: "identifier", Value: "shared-identifier"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Fatalf("remaining rows = %#v, want exactly one", remaining)
	}
	if remaining[0]["id"] == consumed["id"] {
		t.Fatalf("consumed row still exists: consumed=%#v remaining=%#v", consumed, remaining)
	}
}

func TestConcurrentUniqueCreateAcrossAdapterInstances(t *testing.T) {
	db := openDatabase(t)
	schema := adaptertest.ContractSchema()
	adapters := make([]*sqliteadapter.Adapter, 8)
	for index := range adapters {
		var err error
		adapters[index], err = sqliteadapter.New(db, sqliteadapter.Options{Schema: schema})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := adapters[0].EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}

	var successes atomic.Int64
	var conflicts atomic.Int64
	runRacers(t, 64, func(index int) error {
		_, err := adapters[index%len(adapters)].Create(context.Background(), storage.CreateParams{
			Model:        "user",
			Data:         userRecord(fmt.Sprintf("u%d", index), storage.Record{"email": "race@example.com"}),
			ForceAllowID: true,
		})
		switch {
		case err == nil:
			successes.Add(1)
			return nil
		case errors.Is(err, storage.ErrUniqueConstraint):
			conflicts.Add(1)
			return nil
		default:
			return err
		}
	})
	if successes.Load() != 1 || conflicts.Load() != 63 {
		t.Fatalf("successes=%d conflicts=%d", successes.Load(), conflicts.Load())
	}
}

func TestCancelledContextWhileWaitingForWriter(t *testing.T) {
	adapter := newAdapter(t, adaptertest.ContractSchema(), time.Now())
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- adapter.Transaction(context.Background(), func(storage.TransactionAdapter) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := adapter.Create(ctx, storage.CreateParams{Model: "user", Data: userRecord("cancelled", nil), ForceAllowID: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting writer error = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOuterContextCancellationRollsBackTransaction(t *testing.T) {
	adapter := newAdapter(t, adaptertest.ContractSchema(), time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	err := adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		_, err := transaction.Create(t.Context(), storage.CreateParams{
			Model: "user", Data: userRecord("cancelled-transaction", nil), ForceAllowID: true,
		})
		if err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("transaction cancellation error = %v", err)
	}
	count, err := adapter.Count(t.Context(), storage.CountParams{Model: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cancelled transaction committed %d rows", count)
	}
}

func newAdapter(t *testing.T, schema storage.Schema, clock time.Time) *sqliteadapter.Adapter {
	t.Helper()
	db := openDatabase(t)
	adapter, err := sqliteadapter.New(db, sqliteadapter.Options{
		Schema: schema,
		Clock:  func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.EnsureSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	return adapter
}

func openDatabase(t *testing.T) *sql.DB {
	t.Helper()
	name := databaseSequence.Add(1)
	dsn := fmt.Sprintf(
		"file:single_auth_%d?mode=memory&cache=shared&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)",
		name,
	)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(16)
	if err := db.PingContext(t.Context()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func createUser(t *testing.T, adapter storage.TransactionAdapter, id string, extension storage.Record) {
	t.Helper()
	_, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user", Data: userRecord(id, extension), ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func userRecord(id string, extension storage.Record) storage.Record {
	record := storage.Record{
		"id": id, "name": id, "email": id + "@example.com", "emailVerified": false, "rank": 1,
	}
	for key, value := range extension {
		record[key] = value
	}
	return record
}

func ids(records []storage.Record) []string {
	result := make([]string, 0, len(records))
	for _, record := range records {
		result = append(result, record["id"].(string))
	}
	return result
}

func runRacers(t *testing.T, count int, callback func(int) error) {
	t.Helper()
	start := make(chan struct{})
	errorsChannel := make(chan error, count)
	var wait sync.WaitGroup
	for index := range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if err := callback(index); err != nil {
				errorsChannel <- err
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Error(err)
	}
}
