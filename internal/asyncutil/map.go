package asyncutil

import (
	"context"
	"errors"
	"math"
	"sync"
)

// ErrNilMapper is returned when MapConcurrent receives a nil mapper for a
// non-empty input.
var ErrNilMapper = errors.New("asyncutil: nil mapper")

// Options configures MapConcurrent.
type Options struct {
	// Concurrency is the maximum number of mapper calls in flight. Fractional
	// values are floored and the result is clamped to [1, len(items)]. NaN and
	// values below one select a single worker.
	Concurrency float64
}

// Mapper transforms one item. Index is the item's position in the input.
//
// The context is the same context passed to MapConcurrent. A mapper may honor
// it to stop its own in-flight work; MapConcurrent itself checks cancellation
// before scheduling each next item.
type Mapper[T, R any] func(ctx context.Context, item T, index int) (R, error)

// MapConcurrent maps items with bounded concurrency and preserves input order
// in the returned slice.
//
// The first mapper error stops new work from being scheduled and is returned
// immediately. Mapper calls already in flight are allowed to finish, matching
// the reference implementation's Promise-based behavior. Cancellation is observed through
// context.Cause at the next scheduling boundary; an already-cancelled context
// prevents every mapper call.
//
// An empty input returns a non-nil empty slice without consulting ctx or
// invoking mapper.
func MapConcurrent[T, R any](
	ctx context.Context,
	items []T,
	mapper Mapper[T, R],
	options Options,
) ([]R, error) {
	itemCount := len(items)
	if itemCount == 0 {
		return []R{}, nil
	}
	if mapper == nil {
		return nil, ErrNilMapper
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cancellationCause(ctx); err != nil {
		return nil, err
	}

	workerCount := normalizedWorkerCount(options.Concurrency, itemCount)
	results := make([]R, itemCount)

	var state struct {
		sync.Mutex
		next     int
		stopped  bool
		firstErr error
	}

	errorReady := make(chan error, 1)
	workerDone := make(chan struct{}, workerCount)

	stopLocked := func(err error) {
		if state.stopped {
			return
		}
		state.stopped = true
		state.firstErr = err
		// The channel has room for the only error published while holding the
		// state lock, so this send cannot delay the worker that observed it.
		errorReady <- err
	}

	worker := func() {
		defer func() { workerDone <- struct{}{} }()

		for {
			state.Lock()
			if state.stopped || state.next >= itemCount {
				state.Unlock()
				return
			}
			if err := cancellationCause(ctx); err != nil {
				stopLocked(err)
				state.Unlock()
				return
			}
			index := state.next
			state.next++
			state.Unlock()

			result, err := mapper(ctx, items[index], index)
			if err != nil {
				state.Lock()
				stopLocked(err)
				state.Unlock()
				return
			}
			results[index] = result
		}
	}

	for range workerCount {
		go worker()
	}

	remaining := workerCount
	for remaining > 0 {
		select {
		case err := <-errorReady:
			return nil, err
		case <-workerDone:
			remaining--
		}
	}

	// If the final worker's completion won the select race with errorReady,
	// inspect the protected state before reporting success.
	state.Lock()
	firstErr := state.firstErr
	state.Unlock()
	if firstErr != nil {
		return nil, firstErr
	}
	return results, nil
}

func cancellationCause(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return ctx.Err()
}

func normalizedWorkerCount(concurrency float64, itemCount int) int {
	if math.IsNaN(concurrency) || concurrency < 1 {
		return 1
	}
	if math.IsInf(concurrency, 1) || concurrency >= float64(itemCount) {
		return itemCount
	}

	workers := int(math.Floor(concurrency))
	if workers < 1 {
		return 1
	}
	return workers
}
