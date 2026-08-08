package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestUniqueFieldsRejectCreateAndUpdate(t *testing.T) {
	adapter := MustNew()
	first := createUniqueUser(t, adapter, "first@example.com")
	createUniqueUser(t, adapter, "second@example.com")

	_, err := adapter.Create(context.Background(), storage.CreateParams{
		Model: "user",
		Data:  uniqueUser("third", "first@example.com"),
	})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate create error = %v", err)
	}

	second, err := adapter.FindOne(context.Background(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "second@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Update(context.Background(), storage.UpdateParams{
		Model:  "user",
		Where:  []storage.Where{{Field: "id", Value: second["id"]}},
		Update: storage.Record{"email": first["email"]},
	})
	if !errors.Is(err, storage.ErrUniqueConstraint) {
		t.Fatalf("duplicate update error = %v", err)
	}
}

func TestConcurrentTransactionsCannotCommitDuplicateUniqueValue(t *testing.T) {
	adapter := MustNew()
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	errorsChannel := make(chan error, 2)
	var workers sync.WaitGroup
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			errorsChannel <- adapter.Transaction(context.Background(), func(tx storage.TransactionAdapter) error {
				ready <- struct{}{}
				<-release
				_, err := tx.Create(context.Background(), storage.CreateParams{
					Model: "user",
					Data:  uniqueUser(string(rune('a'+index)), "race@example.com"),
				})
				return err
			})
		}(index)
	}
	<-ready
	<-ready
	close(release)
	workers.Wait()
	close(errorsChannel)

	var successes, conflicts int
	for err := range errorsChannel {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, storage.ErrUniqueConstraint):
			conflicts++
		default:
			t.Fatalf("unexpected transaction error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
	count, err := adapter.Count(context.Background(), storage.CountParams{
		Model: "user", Where: []storage.Where{{Field: "email", Value: "race@example.com"}},
	})
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func createUniqueUser(t *testing.T, adapter *Adapter, email string) storage.Record {
	t.Helper()
	created, err := adapter.Create(context.Background(), storage.CreateParams{
		Model: "user", Data: uniqueUser(email, email),
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func uniqueUser(name, email string) storage.Record {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	return storage.Record{
		"name": name, "email": email, "emailVerified": false,
		"createdAt": now, "updatedAt": now,
	}
}
