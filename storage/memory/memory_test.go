package memory_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
	"github.com/pers0na2dev/single-auth/storage/adaptertest"
	"github.com/pers0na2dev/single-auth/storage/memory"
)

func TestTransactionPreservesConcurrentOutsideWrite(t *testing.T) {
	adapter := memory.MustNew(memory.WithSchema(adaptertest.ContractSchema()))
	written := make(chan struct{})
	release := make(chan struct{})
	transactionDone := make(chan error, 1)

	go func() {
		transactionDone <- adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
			_, err := transaction.Create(t.Context(), storage.CreateParams{
				Model:        "user",
				Data:         testUser("inside"),
				ForceAllowID: true,
			})
			if err != nil {
				return err
			}
			close(written)
			<-release
			return nil
		})
	}()

	<-written
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model:        "user",
		Data:         testUser("outside"),
		ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	visible, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user", Limit: storage.Int(100)})
	if err != nil {
		t.Fatal(err)
	}
	if ids := sortedIDs(visible); !reflect.DeepEqual(ids, []string{"outside"}) {
		t.Fatalf("uncommitted transaction write became visible: %v", ids)
	}
	close(release)
	if err := <-transactionDone; err != nil {
		t.Fatal(err)
	}
	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user", Limit: storage.Int(100)})
	if err != nil {
		t.Fatal(err)
	}
	if ids := sortedIDs(rows); !reflect.DeepEqual(ids, []string{"inside", "outside"}) {
		t.Fatalf("commit clobbered concurrent write: %v", ids)
	}
}

func TestRollbackPreservesConcurrentOutsideWrite(t *testing.T) {
	adapter := memory.MustNew(memory.WithSchema(adaptertest.ContractSchema()))
	sentinel := errors.New("rollback")
	written := make(chan struct{})
	release := make(chan struct{})
	transactionDone := make(chan error, 1)

	go func() {
		transactionDone <- adapter.Transaction(t.Context(), func(transaction storage.TransactionAdapter) error {
			_, err := transaction.Create(t.Context(), storage.CreateParams{
				Model:        "user",
				Data:         testUser("inside"),
				ForceAllowID: true,
			})
			if err != nil {
				return err
			}
			close(written)
			<-release
			return sentinel
		})
	}()

	<-written
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model:        "user",
		Data:         testUser("outside"),
		ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-transactionDone; !errors.Is(err, sentinel) {
		t.Fatalf("transaction error = %v", err)
	}
	rows, err := adapter.FindMany(t.Context(), storage.FindManyParams{Model: "user", Limit: storage.Int(100)})
	if err != nil {
		t.Fatal(err)
	}
	if ids := sortedIDs(rows); !reflect.DeepEqual(ids, []string{"outside"}) {
		t.Fatalf("rollback clobbered concurrent write: %v", ids)
	}
}

func TestCustomPhysicalNamesAndPluralTables(t *testing.T) {
	schema := adaptertest.ContractSchema()
	schema.UsePlural = true
	user := schema.Models["user"]
	user.ModelName = "member"
	email := user.Fields["email"]
	email.FieldName = "email_address"
	user.Fields["email"] = email
	schema.Models["user"] = user

	adapter := memory.MustNew(memory.WithSchema(schema))
	if _, err := adapter.Create(t.Context(), storage.CreateParams{
		Model:        "user",
		Data:         testUser("u1"),
		ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	row, err := adapter.FindOne(t.Context(), storage.FindOneParams{
		Model: "members",
		Where: []storage.Where{{Field: "email_address", Value: "u1@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row["id"] != "u1" || row["email"] != "u1@example.com" {
		t.Fatalf("alias round trip = %#v", row)
	}
	if _, leaked := row["email_address"]; leaked {
		t.Fatalf("physical field leaked into canonical output: %#v", row)
	}
}

func TestScalarCapabilityTransformsRoundTrip(t *testing.T) {
	schema, err := adaptertest.ContractSchema().Merge(storage.Schema{Models: map[string]storage.ModelSchema{
		"user": {Fields: map[string]storage.FieldAttribute{
			"labels": {Type: storage.FieldStringArray, Required: storage.Bool(false)},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	capabilities := storage.NativeCapabilities()
	capabilities.JSON = false
	capabilities.Arrays = false
	capabilities.Dates = false
	capabilities.Booleans = false
	adapter := memory.MustNew(memory.WithSchema(schema), memory.WithScalarCapabilities(capabilities))
	created, err := adapter.Create(t.Context(), storage.CreateParams{
		Model: "user",
		Data: storage.Record{
			"id":            "u1",
			"name":          "User",
			"email":         "user@example.com",
			"emailVerified": true,
			"metadata":      map[string]any{"enabled": true},
			"labels":        []string{"one", "two"},
		},
		ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created["emailVerified"] != true {
		t.Fatalf("boolean conversion = %#v", created["emailVerified"])
	}
	if !reflect.DeepEqual(created["metadata"], map[string]any{"enabled": true}) {
		t.Fatalf("JSON conversion = %#v", created["metadata"])
	}
	if !reflect.DeepEqual(created["labels"], []string{"one", "two"}) {
		t.Fatalf("array conversion = %#v", created["labels"])
	}
	if _, ok := created["createdAt"].(time.Time); !ok {
		t.Fatalf("date conversion = %T", created["createdAt"])
	}
}

func testUser(id string) storage.Record {
	return storage.Record{
		"id":            id,
		"name":          id,
		"email":         id + "@example.com",
		"emailVerified": false,
		"rank":          1,
	}
}

func sortedIDs(rows []storage.Record) []string {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row["id"].(string))
	}
	if len(ids) == 2 && ids[0] > ids[1] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	return ids
}
