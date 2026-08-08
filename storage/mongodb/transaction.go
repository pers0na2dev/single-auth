package mongodb

import (
	"context"
	"fmt"

	"github.com/pers0na2dev/single-auth/storage"
)

// Transaction executes callback in a MongoDB session transaction. The
// transaction adapter binds the session to every operation context so callers
// do not need to manually propagate a driver-specific context.
func (adapter *Adapter) Transaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error {
	if callback == nil {
		return fmt.Errorf("mongodb: transaction callback is nil")
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if adapter.transactions == nil || !adapter.config.capabilities.Transactions {
		return fmt.Errorf("%w: mongodb transactions are disabled", storage.ErrTransactionsUnsupported)
	}
	return adapter.transactions.Run(ctx, func(bind contextBinder) error {
		transaction := &transactionAdapter{executor: &executor{
			database: adapter.database,
			config:   adapter.config,
			bind:     bind,
		}}
		return callback(transaction)
	})
}
