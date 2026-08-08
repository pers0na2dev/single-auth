---
title: "github.com/pers0na2dev/single-auth/storage/secondary/redis"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/secondary/redis.

- Import path: `github.com/pers0na2dev/single-auth/storage/secondary/redis`
- Package name: `redis`

Package redis implements reference implementation-compatible secondary storage on top of
a small, driver-neutral Redis command interface.

Store implements the single-auth SecondaryStorage contract plus the optional
atomic GetAndDelete and rate-limit Increment methods. The caller owns the
Redis connection and adapts its chosen client to Commander. Redis 6.2 and
newer use GETDEL; older servers transparently fall back to an atomic Lua
script after one capability probe.

## Variables

```go
var (
	ErrInvalidClient = errors.New("redis secondary storage: invalid client")

	ErrInvalidTTL = errors.New("redis secondary storage: increment TTL must be positive")

	ErrInvalidReply = errors.New("redis secondary storage: invalid Redis reply")
)
```

## Functions

### `Prefix`

Prefix returns a pointer suitable for Options.KeyPrefix, including an empty
prefix when explicit unprefixed storage is desired.

```go
func Prefix(value string) *string
```

## Types

### `CommandFunc`

CommandFunc adapts a function to Commander.

```go
type CommandFunc func(context.Context, ...any) (any, error)
```

## Methods on `CommandFunc`

### `Do`

```go
func (function CommandFunc) Do(ctx context.Context, args ...any) (any, error)
```

### `Commander`

Commander is the minimal Redis client surface used by Store. Implementations
execute one command and return its decoded RESP value. A missing bulk value
should preferably be returned as (nil, nil); Options.IsNotFound can normalize
clients that instead return a sentinel error such as redis.Nil.

A go-redis adapter, for example, can forward to client.Do(ctx, args...).Result().

```go
type Commander interface {
	Do(context.Context, ...any) (any, error)
}
```

### `Options`

Options configures Store.

```go
type Options struct {
	// KeyPrefix is prepended verbatim to every key. Nil selects
	// "single-auth:"; a pointer to an empty string explicitly disables prefixing.
	KeyPrefix *string
	// ScanCount is Redis SCAN's per-page hint for ListKeys and Clear. Zero
	// selects 100.
	ScanCount int64
	// IsNotFound recognizes a client-specific missing-key sentinel error.
	IsNotFound func(error) bool
}
```

### `Store`

Store is a concurrency-safe reference implementation Redis secondary store. It does not
own or close the configured Commander.

```go
type Store struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Store`

### `New`

New validates options and returns a Redis-backed secondary store.

```go
func New(client Commander, options Options) (*Store, error)
```

## Methods on `Store`

### `Clear`

Clear deletes this store's keys page by page using SCAN and batched DEL.
It never uses blocking KEYS. Clear is idempotent but not atomic: an error
after an earlier page was deleted leaves a partially cleared store.

```go
func (store *Store) Clear(ctx context.Context) error
```

### `Delete`

Delete removes key. Removing a missing key succeeds.

```go
func (store *Store) Delete(ctx context.Context, key string) error
```

### `Get`

Get returns an empty string for a missing key.

```go
func (store *Store) Get(ctx context.Context, key string) (string, error)
```

### `GetAndDelete`

GetAndDelete atomically returns and removes key. Redis 6.2+ uses GETDEL;
older servers use a Lua fallback. The capability state is synchronized so a
concurrent first use does not issue a thundering herd of failed probes.

```go
func (store *Store) GetAndDelete(ctx context.Context, key string) (string, error)
```

### `Increment`

Increment atomically increments a fixed-window counter and applies expiry
only when the counter is created (the INCR result is 1). Later increments do
not extend the window TTL.

```go
func (store *Store) Increment(ctx context.Context, key string, ttlSeconds int64) (int64, error)
```

### `KeyPrefix`

KeyPrefix returns the configured raw key prefix.

```go
func (store *Store) KeyPrefix() string
```

### `ListKeys`

ListKeys enumerates this store's keys through non-blocking SCAN pages,
strips the configured prefix, and de-duplicates keys that SCAN repeats.
Redis only guarantees best-effort visibility while the keyspace changes.

```go
func (store *Store) ListKeys(ctx context.Context) ([]string, error)
```

### `Set`

Set stores value persistently when ttlSeconds is non-positive and uses
Redis SETEX when it is positive, matching reference implementation's Redis adapter.

```go
func (store *Store) Set(ctx context.Context, key, value string, ttlSeconds int64) error
```

