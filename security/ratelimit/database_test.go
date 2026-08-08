package ratelimit

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
	storagememory "github.com/pers0na2dev/single-auth/storage/memory"
)

func TestDatabaseStoreAtomicConcurrencyAndReset(t *testing.T) {
	clock := newFakeClock()
	adapter := storagememory.MustNew()
	store := NewDatabaseStore(adapter, DatabaseOptions{Now: clock.Now, GlobalWindow: 10})
	const requests = 50
	start := make(chan struct{})
	allowed := make(chan bool, requests)
	var group sync.WaitGroup
	for index := 0; index < requests; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := store.Consume(context.Background(), "client|/sign-in", Rule{Window: 10, Max: 1})
			if err != nil {
				t.Errorf("consume: %v", err)
				return
			}
			allowed <- result.Allowed
		}()
	}
	close(start)
	group.Wait()
	close(allowed)
	count := 0
	for value := range allowed {
		if value {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("allowed %d concurrent requests, want 1", count)
	}
	clock.Advance(11 * time.Second)
	reset, err := store.Consume(t.Context(), "client|/sign-in", Rule{Window: 10, Max: 1})
	if err != nil || !reset.Allowed {
		t.Fatalf("reset = %#v, %v", reset, err)
	}
}

func TestDatabaseStorePrunesAfterElapsedReset(t *testing.T) {
	clock := newFakeClock()
	now := clock.Now().UnixMilli()
	adapter := storagememory.MustNew(storagememory.WithInitialData(map[string][]storage.Record{
		"rateLimit": {
			{"key": "old|/path", "count": int64(1), "lastRequest": now - 61_000},
			{"key": "target|/path", "count": int64(1), "lastRequest": now - 11_000},
		},
	}))
	store := NewDatabaseStore(adapter, DatabaseOptions{Now: clock.Now, GlobalWindow: 10})
	result, err := store.Consume(t.Context(), "target|/path", Rule{Window: 10, Max: 1})
	if err != nil || !result.Allowed {
		t.Fatalf("reset = %#v, %v", result, err)
	}
	old, err := store.Get(t.Context(), "old|/path")
	if err != nil || old != nil {
		t.Fatalf("old row = %#v, %v", old, err)
	}
	target, err := store.Get(t.Context(), "target|/path")
	if err != nil || target == nil || target.Count != 1 || target.LastRequest != now {
		t.Fatalf("target = %#v, %v", target, err)
	}
}

func TestDatabaseStoreStrictElapsedBoundary(t *testing.T) {
	clock := newFakeClock()
	store := NewDatabaseStore(storagememory.MustNew(), DatabaseOptions{Now: clock.Now})
	first, err := store.Consume(t.Context(), "key", Rule{Window: 10, Max: 1})
	if err != nil || !first.Allowed {
		t.Fatalf("first = %#v, %v", first, err)
	}
	clock.Advance(10 * time.Second)
	boundary, err := store.Consume(t.Context(), "key", Rule{Window: 10, Max: 1})
	if err != nil || boundary.Allowed || boundary.RetryAfter == nil || *boundary.RetryAfter != 0 {
		t.Fatalf("exact boundary = %#v, %v", boundary, err)
	}
	clock.Advance(time.Millisecond)
	reset, err := store.Consume(t.Context(), "key", Rule{Window: 10, Max: 1})
	if err != nil || !reset.Allowed {
		t.Fatalf("after boundary = %#v, %v", reset, err)
	}
}
