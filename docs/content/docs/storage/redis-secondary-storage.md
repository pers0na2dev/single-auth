---
title: "Redis secondary storage"
---

Use Redis for sessions, verification values, and atomic rate-limit counters.

The Redis package implements secondary storage. It is not a primary `storage.Adapter` and cannot replace PostgreSQL, MySQL, SQLite, SQL Server, MongoDB, or the memory adapter in `Options.Database`.

Use it through `Options.SecondaryStorage` alongside a primary adapter.

## Complete go-redis adapter

`secondary/redis` depends on a small driver-neutral `Commander` interface:

```go
type Commander interface {
    Do(context.Context, ...any) (any, error)
}
```

Adapt go-redis as follows:

```go
package authsetup

import (
    "context"
    "errors"
    "fmt"

    goredis "github.com/redis/go-redis/v9"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/storage"
    redisstore "github.com/pers0na2dev/single-auth/storage/secondary/redis"
)

type commander struct {
    client *goredis.Client
}

func (c commander) Do(
    ctx context.Context,
    args ...any,
) (any, error) {
    return c.client.Do(ctx, args...).Result()
}

func OpenWithRedis(
    ctx context.Context,
    address string,
    secret string,
    primary storage.Adapter,
) (*singleauth.Auth, *goredis.Client, error) {
    if len(secret) < 32 {
        return nil, nil, fmt.Errorf("authentication secret must contain at least 32 characters")
    }

    client := goredis.NewClient(&goredis.Options{Addr: address})
    if err := client.Ping(ctx).Err(); err != nil {
        client.Close()
        return nil, nil, err
    }

    secondary, err := redisstore.New(
        commander{client: client},
        redisstore.Options{
            KeyPrefix: redisstore.Prefix("myapp:auth:"),
            IsNotFound: func(err error) bool {
                return errors.Is(err, goredis.Nil)
            },
        },
    )
    if err != nil {
        client.Close()
        return nil, nil, err
    }

    auth, err := singleauth.New(singleauth.Options{
        BaseURL:         "https://example.com",
        Secret:          secret,
        Database:        primary,
        SecondaryStorage: secondary,
        Session: singleauth.SessionOptions{
            StoreSessionInDatabase:    false,
            PreserveSessionInDatabase: false,
        },
        Verification: singleauth.VerificationOptions{
            StoreInDatabase: false,
        },
        RateLimit: singleauth.RateLimitOptions{
            Storage: "secondary-storage",
        },
    })
    if err != nil {
        client.Close()
        return nil, nil, err
    }

    return auth, client, nil
}

var _ singleauth.SecondaryStorage = (*redisstore.Store)(nil)
var _ singleauth.SecondaryGetAndDeleter = (*redisstore.Store)(nil)
```

The caller must eventually call `client.Close()`.

## Constructor options

```go
store, err := redisstore.New(client, redisstore.Options{
    KeyPrefix:  redisstore.Prefix("myapp:auth:"),
    ScanCount:  250,
    IsNotFound: isNotFound,
})
```

### `KeyPrefix`

`nil` selects the current default prefix `better-auth:`. Supply an application-specific prefix to isolate environments and applications:

```go
KeyPrefix: redisstore.Prefix("production:identity:"),
```

An explicit empty prefix disables prefixing:

```go
KeyPrefix: redisstore.Prefix(""),
```

Disabling the prefix is not recommended when a Redis database contains unrelated keys.

### `ScanCount`

Controls the per-page hint used by `SCAN` in `ListKeys` and `Clear`. Zero selects 100. Negative values are rejected.

### `IsNotFound`

Normalizes a client-specific missing-key sentinel such as `redis.Nil`. A missing bulk value returned as `(nil, nil)` already works without this callback.

## Operations

### Get

```go
value, err := store.Get(ctx, "session-token")
```

A missing key returns an empty string. Consequently, an intentionally stored empty string is indistinguishable from a missing key through this interface.

### Set

```go
err := store.Set(ctx, "session-token", encodedSession, 3600)
```

- Positive TTL seconds use `SETEX`.
- Zero or negative TTL uses persistent `SET`.

### Delete

```go
err := store.Delete(ctx, "session-token")
```

Deleting a missing key succeeds.

### Atomic get and delete

```go
value, err := store.GetAndDelete(ctx, "verification:token")
```

Redis 6.2 and newer use `GETDEL`. Older servers are detected once and use an atomic Lua get-and-delete script. Concurrent first use is synchronized so every caller does not issue a failed capability probe.

### Atomic increment

```go
count, err := store.Increment(ctx, "rate-limit:client", 60)
```

`Increment` uses one Lua script. It sets expiration only when `INCR` returns 1, so later requests do not extend the fixed window. TTL must be positive.

The store's increment method is detected automatically by the rate limiter and provides cross-process atomic counters.

### List keys

```go
keys, err := store.ListKeys(ctx)
```

The store uses non-blocking `SCAN`, strips the configured prefix, removes duplicates, and sorts the result. Redis only guarantees best-effort visibility while the keyspace is changing.

### Clear

```go
err := store.Clear(ctx)
```

`Clear` scans only the configured prefix and deletes matched pages with batched `DEL`. It never uses blocking `KEYS`. It is idempotent but not atomic; an error can leave an earlier page deleted and later pages intact.

## Session storage behavior

With any secondary store configured, sessions are authoritative in secondary storage by default.

```go
Session: singleauth.SessionOptions{
    StoreSessionInDatabase: true,
},
```

This writes a primary-database copy as well. When a secondary session is missing, the database copy can be used to repopulate it unless preservation rules make the missing secondary record authoritative.

```go
Session: singleauth.SessionOptions{
    StoreSessionInDatabase:    true,
    PreserveSessionInDatabase: true,
},
```

`PreserveSessionInDatabase` retains the database copy after revocation for audit purposes while the secondary entry remains authoritative.

## Verification storage behavior

Verification records are secondary-only by default:

```go
Verification: singleauth.VerificationOptions{
    StoreInDatabase: false,
},
```

Set `StoreInDatabase: true` for a primary copy.

Single-use verification values require cross-process atomic get-and-delete. `redisstore.Store` implements that optional interface. A custom secondary store without it falls back to an in-process keyed lock, which cannot prevent two separate application instances from consuming the same value. single-auth logs a warning when this fallback is used.

## Rate-limit storage behavior

When secondary storage is configured and `RateLimit.Storage` is empty, single-auth selects secondary storage automatically. Set it explicitly for clarity:

```go
RateLimit: singleauth.RateLimitOptions{
    Storage: "secondary-storage",
    Window:  60,
    Max:     100,
},
```

Other accepted primary modes are `memory` and `database`.

## Object-valued secondary stores

Some wrappers parse JSON before returning a value. Such implementations cannot satisfy the string-returning `SecondaryStorage` interface. Implement `SecondaryValueStorage` instead:

```go
type SecondaryValueStorage interface {
    GetValue(context.Context, string) (any, error)
    Set(context.Context, string, string, int64) error
    Delete(context.Context, string) error
}
```

For atomic verification consumption, also implement:

```go
type SecondaryValueGetAndDeleter interface {
    GetAndDeleteValue(context.Context, string) (any, error)
}
```

Configure it through `Options.SecondaryValueStorage`. Do not set both secondary interfaces at the same time.
