// Package txscope owns context-bound adapter and after-transaction state.
//
// It is internal because transaction scoping is a runtime implementation
// detail. The stable public entry points remain methods and functions in the
// root singleauth package.
package txscope

import (
	"context"
	"errors"
	"sync"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type adapterContextKey struct{}
type scopeContextKey struct{}

// Scope is the adapter state associated with one logical operation.
type Scope struct {
	adapter storage.TransactionAdapter
	active  bool

	mutex  sync.Mutex
	hooks  []func() error
	closed bool
}

// New creates an adapter scope. active reports whether the adapter is backed
// by an actual storage transaction rather than a plain adapter binding.
func New(adapter storage.TransactionAdapter, active bool) *Scope {
	return &Scope{adapter: adapter, active: active}
}

// Adapter returns the adapter bound to the scope.
func (scope *Scope) Adapter() storage.TransactionAdapter {
	if scope == nil {
		return nil
	}
	return scope.adapter
}

// Active reports whether the scope represents an active transaction.
func (scope *Scope) Active() bool {
	return scope != nil && scope.active
}

// Queue appends a hook while the scope is open and executes it immediately
// after the scope has closed.
func (scope *Scope) Queue(hook func() error) error {
	if hook == nil {
		return errors.New("single-auth: after-transaction hook is nil")
	}
	if scope == nil {
		return hook()
	}
	scope.mutex.Lock()
	if !scope.closed {
		scope.hooks = append(scope.hooks, hook)
		scope.mutex.Unlock()
		return nil
	}
	scope.mutex.Unlock()
	return hook()
}

// CloseAndRunHooks closes the scope and runs queued hooks in registration
// order. It returns the first hook error.
func (scope *Scope) CloseAndRunHooks() error {
	if scope == nil {
		return nil
	}
	scope.mutex.Lock()
	scope.closed = true
	hooks := append([]func() error(nil), scope.hooks...)
	scope.hooks = nil
	scope.mutex.Unlock()
	for _, hook := range hooks {
		if err := hook(); err != nil {
			return err
		}
	}
	return nil
}

// BindAdapter stores an adapter in ctx without marking it as transactional.
func BindAdapter(ctx context.Context, adapter storage.TransactionAdapter) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, adapterContextKey{}, adapter)
}

// Bind stores scope in ctx.
func Bind(ctx context.Context, scope *Scope) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, scopeContextKey{}, scope)
}

// Current returns the nearest scope from a Go context or its engine context.
func Current(ctx context.Context) *Scope {
	if ctx != nil {
		if scope, ok := ctx.Value(scopeContextKey{}).(*Scope); ok && scope != nil {
			return scope
		}
		if endpoint := engine.ContextFrom(ctx); endpoint != nil {
			if scope, ok := endpoint.GoContext().Value(scopeContextKey{}).(*Scope); ok && scope != nil {
				return scope
			}
		}
	}
	return nil
}

// CurrentAdapter returns the nearest scoped adapter or fallback.
func CurrentAdapter(ctx context.Context, fallback storage.TransactionAdapter) storage.TransactionAdapter {
	if scope := Current(ctx); scope != nil && scope.Adapter() != nil {
		return scope.Adapter()
	}
	if ctx != nil {
		if adapter, ok := ctx.Value(adapterContextKey{}).(storage.TransactionAdapter); ok && adapter != nil {
			return adapter
		}
		if endpoint := engine.ContextFrom(ctx); endpoint != nil {
			if adapter, ok := endpoint.GoContext().Value(adapterContextKey{}).(storage.TransactionAdapter); ok && adapter != nil {
				return adapter
			}
		}
	}
	return fallback
}

// QueueAfterTransaction queues hook on the current scope. Outside a scope it
// executes hook immediately.
func QueueAfterTransaction(ctx context.Context, hook func() error) error {
	if hook == nil {
		return errors.New("single-auth: after-transaction hook is nil")
	}
	if scope := Current(ctx); scope != nil {
		return scope.Queue(hook)
	}
	return hook()
}
