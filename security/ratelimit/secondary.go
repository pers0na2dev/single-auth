package ratelimit

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
)

// SecondaryStorage is reference implementation's string-valued cache contract. An empty
// value represents a missing key.
type SecondaryStorage interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string, int64) error
}

// SecondaryIncrementer is the optional fixed-window atomic counter primitive.
// Increment must create a missing counter with ttlSeconds and must not extend
// that TTL on subsequent calls.
type SecondaryIncrementer interface {
	Increment(context.Context, string, int64) (int64, error)
}

// SecondaryOptions configures JSON parse diagnostics.
type SecondaryOptions struct {
	Error func(string, error)
}

type secondaryStore struct {
	storage SecondaryStorage
	log     func(string, error)
}

type atomicSecondaryStore struct {
	*secondaryStore
	increment SecondaryIncrementer
}

// NewSecondaryStore wraps a reference implementation secondary storage implementation. If
// storage also implements SecondaryIncrementer, the returned Storage also
// implements AtomicStorage.
func NewSecondaryStore(storage SecondaryStorage, options SecondaryOptions) Storage {
	base := &secondaryStore{storage: storage, log: options.Error}
	if increment, ok := storage.(SecondaryIncrementer); ok {
		return &atomicSecondaryStore{secondaryStore: base, increment: increment}
	}
	return base
}

func (store *secondaryStore) Get(ctx context.Context, key string) (*Record, error) {
	value, err := store.storage.Get(ctx, key)
	if err != nil || value == "" {
		return nil, err
	}
	trimmed := bytes.TrimSpace([]byte(value))
	if !json.Valid(trimmed) {
		var discarded any
		parseError := json.Unmarshal(trimmed, &discarded)
		if store.log != nil {
			store.log("Failed to parse JSON", parseError)
		}
		return nil, nil
	}
	if bytes.Equal(trimmed, []byte("null")) || bytes.Equal(trimmed, []byte("false")) || bytes.Equal(trimmed, []byte("0")) || bytes.Equal(trimmed, []byte(`""`)) {
		return nil, nil
	}
	var record Record
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, nil
	}
	if err := json.Unmarshal(trimmed, &record); err != nil {
		if store.log != nil {
			store.log("Failed to parse JSON", err)
		}
		return nil, nil
	}
	return &record, nil
}

func (store *secondaryStore) Set(ctx context.Context, key string, value Record, _ bool, ttlSeconds int64) error {
	value.Key = key
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	encoded := strings.TrimSuffix(buffer.String(), "\n")
	return store.storage.Set(ctx, key, encoded, ttlSeconds)
}

func (store *atomicSecondaryStore) Consume(ctx context.Context, key string, rule Rule) (ConsumeResult, error) {
	count, err := store.increment.Increment(ctx, key, rule.Window)
	if err != nil {
		return ConsumeResult{}, err
	}
	if count <= rule.Max {
		return ConsumeResult{Allowed: true}, nil
	}
	retry := rule.Window
	return ConsumeResult{Allowed: false, RetryAfter: &retry}, nil
}
