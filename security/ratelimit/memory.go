package ratelimit

import (
	"container/list"
	"context"
	"sync"
	"time"
)

const defaultMemoryMaxEntries = 100_000

// MemoryOptions configures an isolated in-process storage instance.
type MemoryOptions struct {
	MaxEntries int
	Now        func() time.Time
}

type memoryEntry struct {
	record    Record
	expiresAt int64
	order     *list.Element
}

// MemoryStore is a race-safe atomic storage backend. Each instance is
// isolated, making tests and multiple auth engines independent.
type MemoryStore struct {
	mu         sync.Mutex
	entries    map[string]*memoryEntry
	order      *list.List
	maxEntries int
	now        func() time.Time
}

// NewMemoryStore creates an empty atomic in-process backend.
func NewMemoryStore(options MemoryOptions) *MemoryStore {
	maximum := options.MaxEntries
	if maximum <= 0 {
		maximum = defaultMemoryMaxEntries
	}
	return &MemoryStore{
		entries:    make(map[string]*memoryEntry),
		order:      list.New(),
		maxEntries: maximum,
		now:        options.Now,
	}
}

// Get returns a copy of a live record.
func (store *MemoryStore) Get(ctx context.Context, key string) (*Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := unixMillis(store.now)
	store.mu.Lock()
	defer store.mu.Unlock()
	entry := store.entries[key]
	if entry == nil {
		return nil, nil
	}
	if now >= entry.expiresAt {
		store.remove(entry)
		return nil, nil
	}
	record := entry.record
	return &record, nil
}

// Set creates or updates a record and slides its expiry by ttlSeconds.
func (store *MemoryStore) Set(ctx context.Context, key string, value Record, _ bool, ttlSeconds int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := unixMillis(store.now)
	value.Key = key
	store.mu.Lock()
	defer store.mu.Unlock()
	store.set(key, value, now+secondsToMillis(ttlSeconds))
	return nil
}

// Consume atomically decides and records one request.
func (store *MemoryStore) Consume(ctx context.Context, key string, rule Rule) (ConsumeResult, error) {
	if err := ctx.Err(); err != nil {
		return ConsumeResult{}, err
	}
	now := unixMillis(store.now)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.prune(now)
	var current *Record
	if entry := store.entries[key]; entry != nil && now < entry.expiresAt {
		record := entry.record
		current = &record
	}
	decision := decideConsume(current, rule, now)
	if decision.allowed {
		decision.next.Key = key
		store.set(key, decision.next, now+secondsToMillis(rule.Window))
	}
	return ConsumeResult{Allowed: decision.allowed, RetryAfter: decision.retryAfter}, nil
}

// Len returns the number of entries, including entries that have not yet been
// encountered by an expiry sweep.
func (store *MemoryStore) Len() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.entries)
}

func (store *MemoryStore) set(key string, record Record, expiresAt int64) {
	if existing := store.entries[key]; existing != nil {
		existing.record = record
		existing.expiresAt = expiresAt
		return
	}
	element := store.order.PushBack(key)
	store.entries[key] = &memoryEntry{record: record, expiresAt: expiresAt, order: element}
}

func (store *MemoryStore) remove(entry *memoryEntry) {
	delete(store.entries, entry.record.Key)
	store.order.Remove(entry.order)
}

func (store *MemoryStore) prune(now int64) {
	for element := store.order.Front(); element != nil; {
		next := element.Next()
		key := element.Value.(string)
		entry := store.entries[key]
		if entry != nil && now >= entry.expiresAt {
			store.remove(entry)
		}
		element = next
	}
	overflow := len(store.entries) - store.maxEntries
	for removed := 0; removed < overflow; removed++ {
		front := store.order.Front()
		if front == nil {
			break
		}
		entry := store.entries[front.Value.(string)]
		if entry == nil {
			store.order.Remove(front)
			removed--
			continue
		}
		store.remove(entry)
	}
}
