package ratelimit

import (
	"context"
	"sync"
	"testing"
)

type secondaryMock struct {
	mu         sync.Mutex
	values     map[string]string
	counts     map[string]int64
	ttls       map[string]int64
	increments int
}

func newSecondaryMock() *secondaryMock {
	return &secondaryMock{values: map[string]string{}, counts: map[string]int64{}, ttls: map[string]int64{}}
}
func (mock *secondaryMock) Get(_ context.Context, key string) (string, error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	return mock.values[key], nil
}
func (mock *secondaryMock) Set(_ context.Context, key, value string, ttl int64) error {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	mock.values[key] = value
	mock.ttls[key] = ttl
	return nil
}
func (mock *secondaryMock) Increment(_ context.Context, key string, ttl int64) (int64, error) {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	mock.increments++
	mock.counts[key]++
	if mock.counts[key] == 1 {
		mock.ttls[key] = ttl
	}
	return mock.counts[key], nil
}

type secondaryWithoutIncrement struct{ inner *secondaryMock }

func (store secondaryWithoutIncrement) Get(ctx context.Context, key string) (string, error) {
	return store.inner.Get(ctx, key)
}
func (store secondaryWithoutIncrement) Set(ctx context.Context, key, value string, ttl int64) error {
	return store.inner.Set(ctx, key, value, ttl)
}

func TestSecondaryAtomicCounterUsesFixedWindow(t *testing.T) {
	mock := newSecondaryMock()
	store := NewSecondaryStore(mock, SecondaryOptions{})
	atomic, ok := store.(AtomicStorage)
	if !ok {
		t.Fatal("increment-capable storage is not atomic")
	}
	for index := 1; index <= 4; index++ {
		result, err := atomic.Consume(t.Context(), "key", Rule{Window: 60, Max: 3})
		if err != nil {
			t.Fatal(err)
		}
		if result.Allowed != (index <= 3) {
			t.Fatalf("consume %d allowed=%v", index, result.Allowed)
		}
		if index == 4 && (result.RetryAfter == nil || *result.RetryAfter != 60) {
			t.Fatalf("retry = %#v", result.RetryAfter)
		}
	}
	if mock.ttls["key"] != 60 || mock.increments != 4 {
		t.Fatalf("ttl=%d increments=%d", mock.ttls["key"], mock.increments)
	}
}

func TestSecondaryLegacyJSONAndWarning(t *testing.T) {
	clock := newFakeClock()
	mock := newSecondaryMock()
	legacy := secondaryWithoutIncrement{inner: mock}
	var warnings []string
	limiter := New(Config{
		Enabled:     boolPointer(true),
		Production:  false,
		DefaultRule: Rule{Window: 10, Max: 1},
		IP:          IPOptions{Development: true},
		Now:         clock.Now,
		Warn:        func(message string) { warnings = append(warnings, message) },
	}, NewSecondaryStore(legacy, SecondaryOptions{}))
	request := requestFor(t, "https://example.com/get-session")
	first, err := limiter.Check(t.Context(), request)
	if err != nil || !first.Allowed {
		t.Fatalf("first = %#v, %v", first, err)
	}
	second, err := limiter.Check(t.Context(), request)
	if err != nil || second.Allowed {
		t.Fatalf("second = %#v, %v", second, err)
	}
	if len(warnings) != 1 || warnings[0] != legacyStorageWarning {
		t.Fatalf("warnings = %#v", warnings)
	}
	if mock.ttls[first.Key] != 10 {
		t.Fatalf("ttl = %d", mock.ttls[first.Key])
	}
}

func TestSecondaryMalformedJSONIsMissing(t *testing.T) {
	mock := newSecondaryMock()
	mock.values["key"] = "not-json"
	logged := 0
	store := NewSecondaryStore(secondaryWithoutIncrement{inner: mock}, SecondaryOptions{Error: func(string, error) { logged++ }})
	record, err := store.Get(t.Context(), "key")
	if err != nil || record != nil || logged != 1 {
		t.Fatalf("record=%#v err=%v logged=%d", record, err, logged)
	}
}
