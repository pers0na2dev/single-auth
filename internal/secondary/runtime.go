// Package secondary owns the process-local runtime around optional secondary
// storage. Public storage contracts remain in the root package; these local
// structural interfaces keep the internal package independent from it.
package secondary

import (
	"context"
	"sync"

	"github.com/pers0na2dev/single-auth/observability/logger"
	secondarycontract "github.com/pers0na2dev/single-auth/storage/secondary"
)

// Runtime coordinates secondary storage access and process-local fallback
// locks. It is safe for concurrent use.
type Runtime struct {
	stringStore secondarycontract.Storage
	valueStore  secondarycontract.ValueStorage
	log         *logger.Logger
	locks       [64]sync.Mutex

	warnNonAtomicVerification sync.Once
}

// New creates a runtime or returns nil when no secondary store is configured.
func New(
	stringStore secondarycontract.Storage,
	valueStore secondarycontract.ValueStorage,
	log *logger.Logger,
) *Runtime {
	if stringStore == nil && valueStore == nil {
		return nil
	}
	return &Runtime{stringStore: stringStore, valueStore: valueStore, log: log}
}

// Get returns the raw value for key.
func (runtime *Runtime) Get(ctx context.Context, key string) (any, error) {
	if runtime == nil {
		return nil, nil
	}
	if runtime.valueStore != nil {
		return runtime.valueStore.GetValue(ctx, key)
	}
	return runtime.stringStore.Get(ctx, key)
}

// Set stores canonical JSON text for key.
func (runtime *Runtime) Set(ctx context.Context, key, value string, ttl int64) error {
	if runtime.valueStore != nil {
		return runtime.valueStore.Set(ctx, key, value, ttl)
	}
	return runtime.stringStore.Set(ctx, key, value, ttl)
}

// Delete removes key.
func (runtime *Runtime) Delete(ctx context.Context, key string) error {
	if runtime.valueStore != nil {
		return runtime.valueStore.Delete(ctx, key)
	}
	return runtime.stringStore.Delete(ctx, key)
}

// AtomicGetAndDelete consumes key when the configured backend supports it.
// The boolean reports whether an atomic implementation was available.
func (runtime *Runtime) AtomicGetAndDelete(ctx context.Context, key string) (any, bool, error) {
	if runtime.valueStore != nil {
		atomic, ok := runtime.valueStore.(secondarycontract.ValueGetAndDeleter)
		if !ok {
			return nil, false, nil
		}
		value, err := atomic.GetAndDeleteValue(ctx, key)
		return value, true, err
	}
	atomic, ok := runtime.stringStore.(secondarycontract.GetAndDeleter)
	if !ok {
		return nil, false, nil
	}
	value, err := atomic.GetAndDelete(ctx, key)
	return value, true, err
}

// LockFor returns a stable sharded process-local mutex for key.
func (runtime *Runtime) LockFor(key string) *sync.Mutex {
	var hash uint32 = 2166136261
	for index := 0; index < len(key); index++ {
		hash ^= uint32(key[index])
		hash *= 16777619
	}
	return &runtime.locks[int(hash%uint32(len(runtime.locks)))]
}

// Source returns the configured backend for optional capability detection.
func (runtime *Runtime) Source() any {
	if runtime == nil {
		return nil
	}
	if runtime.valueStore != nil {
		return runtime.valueStore
	}
	return runtime.stringStore
}

// WarnNonAtomicVerification logs the cross-process atomicity warning once.
func (runtime *Runtime) WarnNonAtomicVerification() {
	if runtime == nil {
		return
	}
	runtime.warnNonAtomicVerification.Do(func() {
		if runtime.log != nil {
			runtime.log.Warn("Secondary storage does not implement `getAndDelete`, so single-use verification values cannot be consumed atomically across processes. Implement `getAndDelete` or use database-backed verification storage to guarantee single use.")
		}
	})
}
