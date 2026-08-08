package postgres

import (
	"context"
	"fmt"

	"github.com/pers0na2dev/single-auth/storage"
)

type transactionAdapter struct{ *executor }

// Transaction executes callback in a database/sql transaction. Callback
// failure or outer-context cancellation rolls back; success commits before
// Transaction returns.
func (a *Adapter) Transaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error {
	if callback == nil {
		return fmt.Errorf("postgres: transaction callback is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return normalizeError(ctx, "begin transaction", err)
	}
	completed := false
	defer func() {
		if !completed {
			_ = tx.Rollback()
		}
	}()

	transaction := &transactionAdapter{executor: &executor{runner: tx, config: a.config}}
	if err := callback(transaction); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return normalizeError(ctx, "commit transaction", err)
	}
	completed = true
	return nil
}

var _ storage.TransactionAdapter = (*transactionAdapter)(nil)
