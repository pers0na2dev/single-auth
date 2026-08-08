package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/internal/txscope"
	"github.com/pers0na2dev/single-auth/storage"
)

func contextWithTransactionAdapter(
	ctx context.Context,
	adapter storage.TransactionAdapter,
) context.Context {
	return txscope.BindAdapter(ctx, adapter)
}

func currentTransactionAdapter(
	ctx context.Context,
	fallback storage.TransactionAdapter,
) storage.TransactionAdapter {
	return txscope.CurrentAdapter(ctx, fallback)
}

// AdapterForContext returns the adapter bound to ctx, or the root adapter when
// no transaction/adapter scope is active.
func (a *Auth) AdapterForContext(ctx context.Context) storage.TransactionAdapter {
	if a == nil {
		return nil
	}
	return currentTransactionAdapter(ctx, a.adapter)
}

// RunWithAdapter binds the root adapter without marking the scope as an active
// transaction. A nested RunInTransaction therefore still opens one, matching
// upstream implementation's runWithAdapter semantics.
func (a *Auth) RunWithAdapter(ctx context.Context, callback func(context.Context) error) error {
	if a == nil || a.adapter == nil {
		return errors.New("single-auth: auth is not initialized")
	}
	if callback == nil {
		return errors.New("single-auth: adapter callback is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	scope := txscope.New(a.adapter, false)
	err := callback(txscope.Bind(ctx, scope))
	if hookErr := scope.CloseAndRunHooks(); hookErr != nil {
		return hookErr
	}
	return err
}

// QueueAfterTransactionHook queues hook on the current adapter scope. Outside
// a scope it executes immediately.
func QueueAfterTransactionHook(ctx context.Context, hook func() error) error {
	return txscope.QueueAfterTransaction(ctx, hook)
}

// RunInTransaction runs callback with a context carrying the active Better
// Auth transaction adapter. Passing that context to Invoke/Dispatch requests
// gives plugins the same nested getCurrentAdapter semantics as upstream's
// AsyncLocalStorage transaction scope.
func (a *Auth) RunInTransaction(
	ctx context.Context,
	callback func(context.Context) error,
) error {
	if a == nil || a.adapter == nil {
		return errors.New("single-auth: auth is not initialized")
	}
	if callback == nil {
		return errors.New("single-auth: transaction callback is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if scope := txscope.Current(ctx); scope != nil && scope.Active() {
		return callback(ctx)
	}
	if txscope.Current(ctx) == nil {
		if current := currentTransactionAdapter(ctx, nil); current != nil {
			return callback(ctx)
		}
	}
	var scope *txscope.Scope
	err := a.adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		scope = txscope.New(transaction, true)
		return callback(txscope.Bind(ctx, scope))
	})
	if errors.Is(err, storage.ErrTransactionsUnsupported) {
		return callback(ctx)
	}
	if scope != nil {
		if hookErr := scope.CloseAndRunHooks(); hookErr != nil {
			return hookErr
		}
	}
	return err
}

func (a *Auth) runWithTransactionAdapter(
	ctx context.Context,
	callback func(context.Context, storage.TransactionAdapter) error,
) error {
	if callback == nil {
		return fmt.Errorf("single-auth: transaction callback is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if scope := txscope.Current(ctx); scope != nil && scope.Active() {
		return callback(ctx, scope.Adapter())
	}
	if txscope.Current(ctx) == nil {
		if current := currentTransactionAdapter(ctx, nil); current != nil {
			return callback(ctx, current)
		}
	}
	var scope *txscope.Scope
	err := a.adapter.Transaction(ctx, func(transaction storage.TransactionAdapter) error {
		scope = txscope.New(transaction, true)
		bound := txscope.Bind(ctx, scope)
		endpoint := engine.ContextFrom(ctx)
		if endpoint == nil {
			return callback(bound, transaction)
		}
		original := endpoint.Request()
		endpoint.ReplaceRequest(original.WithContext(bound))
		defer endpoint.ReplaceRequest(original)
		return callback(bound, transaction)
	})
	if errors.Is(err, storage.ErrTransactionsUnsupported) {
		return callback(ctx, a.adapter)
	}
	if scope != nil {
		if hookErr := scope.CloseAndRunHooks(); hookErr != nil {
			return hookErr
		}
	}
	return err
}
