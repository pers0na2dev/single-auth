// Package requeststate provides request-scoped typed state using context.Context.
package requeststate

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrNoRequestState matches the reference implementation's failure outside a request scope.
	ErrNoRequestState = errors.New("No request state found. Please make sure you are calling this function within a `runWithRequestState` callback.")
	ErrNilStore       = errors.New("requeststate: store is nil")
)

type contextKey struct{}
type stateKey struct{}

// Store holds values for one request. It is safe for concurrent access.
type Store struct {
	mutex  sync.RWMutex
	values map[*stateKey]any
}

// NewStore creates an empty request state store.
func NewStore() *Store {
	return &Store{values: make(map[*stateKey]any)}
}

// Run executes fn with store bound to the returned callback context.
func Run[T any](ctx context.Context, store *Store, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if store == nil {
		return zero, ErrNilStore
	}
	if fn == nil {
		return zero, errors.New("requeststate: callback is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return fn(context.WithValue(ctx, contextKey{}, store))
}

// RunWithRequestState is the error-only convenience form of Run.
func RunWithRequestState(ctx context.Context, store *Store, fn func(context.Context) error) error {
	_, err := Run(ctx, store, func(bound context.Context) (struct{}, error) {
		return struct{}{}, fn(bound)
	})
	return err
}

// Has reports whether ctx carries a request state store.
func Has(ctx context.Context) bool {
	_, err := Current(ctx)
	return err == nil
}

// Current returns the store bound to ctx.
func Current(ctx context.Context) (*Store, error) {
	if ctx != nil {
		if store, ok := ctx.Value(contextKey{}).(*Store); ok && store != nil {
			return store, nil
		}
	}
	return nil, ErrNoRequestState
}

// State is one typed value shared through a Store.
type State[T any] struct {
	key  *stateKey
	init func(context.Context) (T, error)
}

// Define creates a lazily initialized typed state.
func Define[T any](init func(context.Context) (T, error)) *State[T] {
	return &State[T]{key: &stateKey{}, init: init}
}

// DefineValue adapts a synchronous initializer.
func DefineValue[T any](init func() T) *State[T] {
	return Define(func(context.Context) (T, error) { return init(), nil })
}

// Ref returns the stable opaque identity used to key this state in a Store.
func (state *State[T]) Ref() any {
	if state == nil {
		return nil
	}
	return state.key
}

// Get returns the current value, invoking the initializer on first access in
// each request store.
func (state *State[T]) Get(ctx context.Context) (T, error) {
	var zero T
	if state == nil || state.key == nil {
		return zero, errors.New("requeststate: state is nil")
	}
	store, err := Current(ctx)
	if err != nil {
		return zero, err
	}
	store.mutex.RLock()
	value, exists := store.values[state.key]
	store.mutex.RUnlock()
	if exists {
		decoded, ok := value.(T)
		if !ok {
			return zero, errors.New("requeststate: stored value has unexpected type")
		}
		return decoded, nil
	}
	if state.init == nil {
		return zero, errors.New("requeststate: initializer is nil")
	}
	initialized, err := state.init(ctx)
	if err != nil {
		return zero, err
	}
	store.mutex.Lock()
	if current, alreadySet := store.values[state.key]; alreadySet {
		store.mutex.Unlock()
		decoded, ok := current.(T)
		if !ok {
			return zero, errors.New("requeststate: stored value has unexpected type")
		}
		return decoded, nil
	}
	store.values[state.key] = initialized
	store.mutex.Unlock()
	return initialized, nil
}

// Set replaces the state value in the current request store.
func (state *State[T]) Set(ctx context.Context, value T) error {
	if state == nil || state.key == nil {
		return errors.New("requeststate: state is nil")
	}
	store, err := Current(ctx)
	if err != nil {
		return err
	}
	store.mutex.Lock()
	store.values[state.key] = value
	store.mutex.Unlock()
	return nil
}
