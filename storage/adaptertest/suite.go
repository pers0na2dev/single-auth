// Package adaptertest contains the reusable behavioral contract for every
// single-auth storage adapter.
package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

// Factory must return a fresh adapter configured for the supplied schema.
type Factory func(*testing.T, storage.Schema) (storage.Adapter, error)

// Run registers the database-neutral storage contract on t.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	t.Run("create-find-select-and-copy-isolation", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		input := user("u1", "Alice", "Alice@Example.com", 1)
		input["metadata"] = map[string]any{"roles": []any{"admin"}}
		created, err := adapter.Create(t.Context(), storage.CreateParams{
			Model:        "user",
			Data:         input,
			ForceAllowID: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		input["name"] = "mutated input"
		input["metadata"].(map[string]any)["roles"].([]any)[0] = "mutated"
		created["name"] = "mutated output"

		found, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user",
			Where: []storage.Where{{Field: "id", Value: "u1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if found["name"] != "Alice" {
			t.Fatalf("retained map mutated stored row: %#v", found)
		}
		metadata := found["metadata"].(map[string]any)
		if got := metadata["roles"].([]any)[0]; got != "admin" {
			t.Fatalf("retained nested slice mutated stored row: %v", got)
		}

		selected, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model:  "user",
			Where:  []storage.Where{{Field: "id", Value: "u1"}},
			Select: []string{"email", "name"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(selected, storage.Record{"email": "Alice@Example.com", "name": "Alice"}) {
			t.Fatalf("unexpected select result: %#v", selected)
		}
	})

	t.Run("where-operators-and-connectors", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		for _, row := range []storage.Record{
			user("u1", "Alice Alpha", "alice@example.com", 1),
			user("u2", "bob beta", "bob@example.com", 2),
			user("u3", "Carol", "carol@sample.test", 3),
		} {
			mustCreate(t, adapter, "user", row)
		}

		checks := []struct {
			name  string
			where []storage.Where
			ids   []string
		}{
			{"eq", []storage.Where{{Field: "rank", Value: 2}}, []string{"u2"}},
			{"ne", []storage.Where{{Field: "rank", Operator: storage.OpNe, Value: 2}}, []string{"u1", "u3"}},
			{"lt", []storage.Where{{Field: "rank", Operator: storage.OpLt, Value: 2}}, []string{"u1"}},
			{"lte", []storage.Where{{Field: "rank", Operator: storage.OpLTE, Value: 2}}, []string{"u1", "u2"}},
			{"gt", []storage.Where{{Field: "rank", Operator: storage.OpGt, Value: 2}}, []string{"u3"}},
			{"gte", []storage.Where{{Field: "rank", Operator: storage.OpGTE, Value: 2}}, []string{"u2", "u3"}},
			{"in", []storage.Where{{Field: "rank", Operator: storage.OpIn, Value: []int{1, 3}}}, []string{"u1", "u3"}},
			{"not-in", []storage.Where{{Field: "rank", Operator: storage.OpNotIn, Value: []int{1, 3}}}, []string{"u2"}},
			{"contains", []storage.Where{{Field: "name", Operator: storage.OpContains, Value: "bet"}}, []string{"u2"}},
			{"starts-with-insensitive", []storage.Where{{Field: "name", Operator: storage.OpStartsWith, Value: "ALICE", Mode: storage.Insensitive}}, []string{"u1"}},
			{"ends-with", []storage.Where{{Field: "email", Operator: storage.OpEndsWith, Value: "sample.test"}}, []string{"u3"}},
			{"or", []storage.Where{{Field: "id", Value: "u1", Connector: storage.Or}, {Field: "id", Value: "u3", Connector: storage.Or}}, []string{"u1", "u3"}},
			{"and", []storage.Where{{Field: "rank", Operator: storage.OpGTE, Value: 2}, {Field: "rank", Operator: storage.OpLTE, Value: 2}}, []string{"u2"}},
		}
		for _, check := range checks {
			t.Run(check.name, func(t *testing.T) {
				rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user", Where: check.where, Limit: storage.Int(100)})
				if err != nil {
					t.Fatal(err)
				}
				ids := recordIDs(rows)
				if !reflect.DeepEqual(ids, check.ids) {
					t.Fatalf("got IDs %v, want %v", ids, check.ids)
				}
			})
		}
	})

	t.Run("null-and-missing", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		withNull := user("null", "Null", "null@example.com", 1)
		withNull["image"] = nil
		mustCreate(t, adapter, "user", withNull)
		mustCreate(t, adapter, "user", user("missing", "Missing", "missing@example.com", 2))
		mustCreate(t, adapter, "user", withImage("image", "Image", "image@example.com", 3, "avatar"))

		equalNull, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "user",
			Where: []storage.Where{{Field: "image", Value: nil}},
			Limit: storage.Int(100),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := recordIDs(equalNull); !reflect.DeepEqual(got, []string{"missing", "null"}) {
			t.Fatalf("eq null must match null and missing: %v", got)
		}
		notNull, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "user",
			Where: []storage.Where{{Field: "image", Operator: storage.OpNe, Value: nil}},
			Limit: storage.Int(100),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := recordIDs(notNull); !reflect.DeepEqual(got, []string{"image"}) {
			t.Fatalf("ne null must match only non-null: %v", got)
		}
	})

	t.Run("sort-limit-offset-count", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		for index := 1; index <= 5; index++ {
			mustCreate(t, adapter, "user", user(fmt.Sprintf("u%d", index), fmt.Sprintf("User %d", index), fmt.Sprintf("u%d@example.com", index), index))
		}
		rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model:  "user",
			SortBy: &storage.Sort{Field: "rank", Direction: storage.Descending},
			Offset: storage.Int(1),
			Limit:  storage.Int(2),
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := recordIDsInOrder(rows); !reflect.DeepEqual(got, []string{"u4", "u3"}) {
			t.Fatalf("unexpected page: %v", got)
		}
		count, err := adapter.Count(t.Context(), storage.CountParams{Model: "user", Where: []storage.Where{{Field: "rank", Operator: storage.OpGTE, Value: 3}}})
		if err != nil || count != 3 {
			t.Fatalf("count = %d, %v", count, err)
		}
	})

	t.Run("update-and-update-many", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		mustCreate(t, adapter, "user", user("u1", "One", "one@example.com", 1))
		mustCreate(t, adapter, "user", user("u2", "Two", "two@example.com", 2))

		updated, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model:  "user",
			Where:  []storage.Where{{Field: "id", Value: "u1"}, {Field: "rank", Value: 1}},
			Update: storage.Record{"name": "Updated"},
		})
		if err != nil || updated["name"] != "Updated" {
			t.Fatalf("update = %#v, %v", updated, err)
		}
		miss, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model:  "user",
			Where:  []storage.Where{{Field: "id", Value: "u1"}, {Field: "rank", Value: 99}},
			Update: storage.Record{"name": "Wrong"},
		})
		if err != nil || miss != nil {
			t.Fatalf("guard miss = %#v, %v", miss, err)
		}
		empty, err := adapter.Update(t.Context(), storage.UpdateParams{Model: "user", Update: storage.Record{"name": "Wrong"}})
		if err != nil || empty != nil {
			t.Fatalf("empty singular update = %#v, %v", empty, err)
		}
		count, err := adapter.UpdateMany(t.Context(), storage.UpdateManyParams{Model: "user", Update: storage.Record{"tag": "all"}})
		if err != nil || count != 2 {
			t.Fatalf("update all = %d, %v", count, err)
		}
	})

	t.Run("update-by-insensitive-non-unique-predicate-applies-on-update", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		created := mustCreate(t, adapter, "user", user("u1", "Shared Name", "one@example.com", 1))
		mustCreate(t, adapter, "user", user("u2", "Other Name", "two@example.com", 2))
		if created["stamp"] != "created" {
			t.Fatalf("create stamp = %#v, want created", created["stamp"])
		}

		updated, err := adapter.Update(t.Context(), storage.UpdateParams{
			Model: "user",
			Where: []storage.Where{{
				Field: "name", Value: "shared name", Mode: storage.Insensitive,
			}},
			Update: storage.Record{"tag": "matched"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if updated == nil || updated["id"] != "u1" || updated["tag"] != "matched" || updated["stamp"] != "updated" {
			t.Fatalf("insensitive non-unique update = %#v", updated)
		}
		persisted, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user", Where: []storage.Where{{Field: "id", Value: "u1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if persisted["tag"] != "matched" || persisted["stamp"] != "updated" {
			t.Fatalf("persisted update = %#v", persisted)
		}
	})

	t.Run("delete-and-delete-many", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		mustCreate(t, adapter, "user", user("u1", "One", "one@example.com", 1))
		mustCreate(t, adapter, "user", user("u2", "Two", "two@example.com", 2))
		if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "user"}); err != nil {
			t.Fatal(err)
		}
		count, _ := adapter.Count(t.Context(), storage.CountParams{Model: "user"})
		if count != 2 {
			t.Fatalf("empty singular delete removed rows: %d", count)
		}
		if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "user", Where: []storage.Where{{Field: "id", Value: "u1"}}}); err != nil {
			t.Fatal(err)
		}
		if err := adapter.Delete(t.Context(), storage.DeleteParams{Model: "user", Where: []storage.Where{{Field: "id", Value: "u1"}}}); err != nil {
			t.Fatalf("repeated delete of missing row: %v", err)
		}
		deleted, err := adapter.DeleteMany(t.Context(), storage.DeleteManyParams{Model: "user"})
		if err != nil || deleted != 1 {
			t.Fatalf("deleteMany = %d, %v", deleted, err)
		}
	})

	t.Run("joins", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		mustCreate(t, adapter, "user", user("u1", "One", "one@example.com", 1))
		mustCreate(t, adapter, "session", session("s1", "u1", "token-1"))
		mustCreate(t, adapter, "session", session("s2", "u1", "token-2"))

		joined, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "user",
			Where: []storage.Where{{Field: "id", Value: "u1"}},
			Join:  map[string]storage.JoinOption{"session": {}},
		})
		if err != nil {
			t.Fatal(err)
		}
		sessions, ok := joined["session"].([]storage.Record)
		if !ok || len(sessions) != 2 {
			t.Fatalf("forward join = %#v", joined["session"])
		}
		backward, err := adapter.FindOne(t.Context(), storage.FindOneParams{
			Model: "session",
			Where: []storage.Where{{Field: "id", Value: "s1"}},
			Join:  map[string]storage.JoinOption{"user": {}},
		})
		if err != nil {
			t.Fatal(err)
		}
		joinedUser, ok := backward["user"].(storage.Record)
		if !ok || joinedUser["id"] != "u1" {
			t.Fatalf("backward join = %#v", backward["user"])
		}
	})

	t.Run("consume-one-is-atomic", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		mustCreate(t, adapter, "verification", verification("v1", "once"))
		const racers = 64
		var winners atomic.Int64
		errorsChannel := make(chan error, racers)
		var wait sync.WaitGroup
		wait.Add(racers)
		for range racers {
			go func() {
				defer wait.Done()
				row, err := adapter.ConsumeOne(context.Background(), storage.ConsumeOneParams{
					Model: "verification",
					Where: []storage.Where{{Field: "identifier", Value: "once"}},
				})
				if err != nil {
					errorsChannel <- err
					return
				}
				if row != nil {
					winners.Add(1)
				}
			}()
		}
		wait.Wait()
		close(errorsChannel)
		for err := range errorsChannel {
			t.Error(err)
		}
		if got := winners.Load(); got != 1 {
			t.Fatalf("consume winners = %d, want 1", got)
		}
	})

	t.Run("consume-one-removes-exactly-one-non-unique-match", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		mustCreate(t, adapter, "verification", verification("v1", "shared"))
		mustCreate(t, adapter, "verification", verification("v2", "shared"))

		consumed, err := adapter.ConsumeOne(t.Context(), storage.ConsumeOneParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "shared"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if consumed == nil || (consumed["id"] != "v1" && consumed["id"] != "v2") {
			t.Fatalf("consumed row = %#v", consumed)
		}
		remaining, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "shared"}},
			Limit: storage.Int(10),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(remaining) != 1 || remaining[0]["id"] == consumed["id"] {
			t.Fatalf("consumed = %#v, remaining = %#v", consumed, remaining)
		}
	})

	t.Run("increment-one-is-atomic-and-guarded", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		row := user("u1", "Counter", "counter@example.com", 1)
		row["remaining"] = 10
		mustCreate(t, adapter, "user", row)
		const racers = 64
		var winners atomic.Int64
		errorsChannel := make(chan error, racers)
		var wait sync.WaitGroup
		wait.Add(racers)
		for range racers {
			go func() {
				defer wait.Done()
				updated, err := adapter.IncrementOne(context.Background(), storage.IncrementOneParams{
					Model:     "user",
					Where:     []storage.Where{{Field: "id", Value: "u1"}, {Field: "remaining", Operator: storage.OpGt, Value: 0}},
					Increment: map[string]float64{"remaining": -1},
				})
				if err != nil {
					errorsChannel <- err
					return
				}
				if updated != nil {
					winners.Add(1)
				}
			}()
		}
		wait.Wait()
		close(errorsChannel)
		for err := range errorsChannel {
			t.Error(err)
		}
		if got := winners.Load(); got != 10 {
			t.Fatalf("increment winners = %d, want 10", got)
		}
		final, err := adapter.FindOne(t.Context(), storage.FindOneParams{Model: "user", Where: []storage.Where{{Field: "id", Value: "u1"}}})
		if err != nil || final["remaining"] != 0 {
			t.Fatalf("remaining = %#v, %v", final["remaining"], err)
		}
	})

	t.Run("increment-one-mutates-one-non-unique-match-with-delta-and-set", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		first := user("u1", "Shared Counter", "one@example.com", 1)
		first["remaining"] = 5
		second := user("u2", "Shared Counter", "two@example.com", 2)
		second["remaining"] = 5
		mustCreate(t, adapter, "user", first)
		mustCreate(t, adapter, "user", second)

		updated, err := adapter.IncrementOne(t.Context(), storage.IncrementOneParams{
			Model: "user",
			Where: []storage.Where{
				{Field: "name", Value: "Shared Counter"},
				{Field: "remaining", Operator: storage.OpGt, Value: 0},
			},
			Increment: map[string]float64{"remaining": -1},
			Set:       storage.Record{"status": "closed"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if updated == nil || fmt.Sprint(updated["remaining"]) != "4" || updated["status"] != "closed" {
			t.Fatalf("increment result = %#v", updated)
		}

		rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{
			Model: "user", Where: []storage.Where{{Field: "name", Value: "Shared Counter"}},
			Limit: storage.Int(10),
		})
		if err != nil {
			t.Fatal(err)
		}
		mutated, untouched := 0, 0
		for _, row := range rows {
			switch fmt.Sprint(row["remaining"]) {
			case "4":
				if row["id"] != updated["id"] || row["status"] != "closed" {
					t.Fatalf("mutated row = %#v, returned = %#v", row, updated)
				}
				mutated++
			case "5":
				if status, exists := row["status"]; exists && status != nil {
					t.Fatalf("untouched row received set value: %#v", row)
				}
				untouched++
			default:
				t.Fatalf("unexpected counter row: %#v", row)
			}
		}
		if mutated != 1 || untouched != 1 {
			t.Fatalf("mutated = %d, untouched = %d, rows = %#v", mutated, untouched, rows)
		}
	})

	t.Run("transactions-commit-and-rollback", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		sentinel := errors.New("rollback")
		err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
			mustCreateContext(t, transaction, "user", user("rolled-back", "Rollback", "rollback@example.com", 1))
			return sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("rollback error = %v", err)
		}
		count, _ := adapter.Count(t.Context(), storage.CountParams{Model: "user"})
		if count != 0 {
			t.Fatalf("failed transaction committed %d rows", count)
		}

		if err := adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
			_, err := transaction.Create(t.Context(), storage.CreateParams{Model: "user", Data: user("committed", "Commit", "commit@example.com", 1), ForceAllowID: true})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		count, _ = adapter.Count(t.Context(), storage.CountParams{Model: "user"})
		if count != 1 {
			t.Fatalf("committed transaction count = %d", count)
		}
	})

	t.Run("cancelled-context", func(t *testing.T) {
		adapter := newAdapter(t, factory, ContractSchema())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := adapter.FindMany(ctx, storage.FindManyParams{Model: "user"})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled query error = %v", err)
		}
	})
}

// ContractSchema extends the core tables with fields used by the common suite.
func ContractSchema() storage.Schema {
	schema, err := storage.CoreSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"rank":      {Type: storage.FieldNumber, Required: storage.Bool(false), Sortable: true},
			"remaining": {Type: storage.FieldNumber, Required: storage.Bool(false)},
			"tag":       {Type: storage.FieldString, Required: storage.Bool(false)},
			"status":    {Type: storage.FieldString, Required: storage.Bool(false)},
			"stamp": {
				Type: storage.FieldString, DefaultValue: storage.StaticValue("created"),
				OnUpdate: storage.StaticValue("updated"),
			},
			"metadata": {Type: storage.FieldJSON, Required: storage.Bool(false)},
		}},
	}})
	if err != nil {
		panic(err)
	}
	return schema
}

func newAdapter(t *testing.T, factory Factory, schema storage.Schema) storage.Adapter {
	t.Helper()
	adapter, err := factory(t, schema)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func mustCreate(t *testing.T, adapter storage.TransactionAdapter, model string, row storage.Record) storage.Record {
	t.Helper()
	return mustCreateContext(t, adapter, model, row)
}

func mustCreateContext(t *testing.T, adapter storage.TransactionAdapter, model string, row storage.Record) storage.Record {
	t.Helper()
	created, err := adapter.Create(t.Context(), storage.CreateParams{Model: model, Data: row, ForceAllowID: true})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func user(id, name, email string, rank int) storage.Record {
	return storage.Record{
		"id":            id,
		"name":          name,
		"email":         email,
		"emailVerified": false,
		"rank":          rank,
	}
}

func withImage(id, name, email string, rank int, image string) storage.Record {
	record := user(id, name, email, rank)
	record["image"] = image
	return record
}

func session(id, userID, token string) storage.Record {
	return storage.Record{
		"id":        id,
		"userId":    userID,
		"token":     token,
		"expiresAt": time.Now().Add(time.Hour),
	}
}

func verification(id, identifier string) storage.Record {
	return storage.Record{
		"id":         id,
		"identifier": identifier,
		"value":      "secret",
		"expiresAt":  time.Now().Add(time.Hour),
	}
}

func recordIDs(rows []storage.Record) []string {
	ids := recordIDsInOrder(rows)
	sort.Strings(ids)
	return ids
}

func recordIDsInOrder(rows []storage.Record) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row["id"].(string))
	}
	return ids
}
