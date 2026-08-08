---
title: "Run multiple replicas"
description: "Choose shared session and verification authority, Redis behavior, cache policy, and rollout invariants for multiple server replicas."
---

Multiple Go processes must agree on secrets, public URL policy, durable data,
single-use values, and rate-limit counters. Process-local locks and the memory
adapter protect only one runtime; they are not a distributed coordination
mechanism.

## Shared-state inventory

| State | Multi-replica requirement |
| --- | --- |
| Users and accounts | One shared primary database. |
| Stateful sessions | Shared primary database or shared secondary storage. |
| OAuth state and verification values | Shared store with atomic single-use consumption. |
| Rate limits | Shared atomic storage when limits must apply across replicas. |
| Signing/encryption | Identical active secret and retained versioned keys. |
| Public URLs and cookies | Identical `BaseURL`/dynamic policy, base path, prefix, attributes, and trusted origins. |
| Clock | Synchronized hosts; expiry and token validation use wall time. |

The built-in memory adapter and memory rate limiter are per process. A
file-backed SQLite database is normally local to one replica. Use PostgreSQL,
MySQL, SQL Server, or MongoDB for a conventional shared primary store, or
provide another adapter that passes the same transaction and atomic-operation
contracts.

## Primary-database sessions

With no secondary store, the primary adapter is authoritative for sessions and
verification records:

```go
auth, err := singleauth.New(singleauth.Options{
    Environment: "production",
    BaseURL:      "https://accounts.example.com",
    Secret:       os.Getenv("SINGLE_AUTH_SECRET"),
    Database:     primary,
    Session: singleauth.SessionOptions{
        ExpiresIn: 30 * 24 * time.Hour,
    },
})
```

Use a backend connection pool sized for the total replica count. Run additive
migrations once as a controlled deployment stage; `New` itself does not modify
the database.

The primary adapter must enforce unique constraints and transaction behavior
across processes. Same-process scoped locks are an optimization and a local
race shield, not a substitute for database guarantees.

## Redis as secondary authority

`Options.SecondaryStorage` moves session, verification, and default
rate-limiting hot state to a string-valued secondary store. The native
`secondary/redis` package provides atomic get-delete and fixed-window increment
extensions.

```go
secondary, err := redisstore.New(redisCommander, redisstore.Options{
    KeyPrefix: redisstore.Prefix("production:identity:"),
})
if err != nil {
    return nil, err
}

auth, err := singleauth.New(singleauth.Options{
    Environment:      "production",
    BaseURL:           "https://accounts.example.com",
    Secret:            os.Getenv("SINGLE_AUTH_SECRET"),
    Database:          primary,
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
```

Adapt your Redis client to `redis.Commander`; the store does not own or close
that client. Use a different prefix for every application and environment.

Session choices with secondary storage:

| Option | Behavior |
| --- | --- |
| `StoreSessionInDatabase=false` | Secondary storage is the only server-side session copy. |
| `StoreSessionInDatabase=true` | Write a primary-database copy as well; secondary remains authoritative. |
| `PreserveSessionInDatabase=false` | Revocation removes the retained database copy. |
| `PreserveSessionInDatabase=true` | Retain the database copy for audit while removing secondary authority. |

Do not treat a preserved database row as an active session. Authentication
continues to follow the authoritative secondary entry.

## Atomic single-use values

OAuth state, reset tokens, email tokens, OTPs, and similar records must be
consumed once. Cross-replica replay safety requires one of:

- primary `Adapter.ConsumeOne` with a backend-atomic implementation;
- secondary `GetAndDelete` through `SecondaryGetAndDeleter`;
- another transaction/isolation mechanism with equivalent observable behavior.

The Redis store uses `GETDEL` on Redis 6.2+ and a Lua fallback on older servers.
If a custom secondary store exposes only `Get` and `Delete`, two replicas can
observe the same value before either deletion completes.

For OAuth, database state also uses a signed browser binding cookie. Every
replica needs the same active secret and cookie configuration or the callback
will fail even when the shared state row exists.

## Cookie cache trade-offs

The optional session-data cookie cache avoids a store read for ordinary session
lookups:

```go
Session: singleauth.SessionOptions{
    CookieCache: singleauth.CookieCacheOptions{
        Enabled:  true,
        MaxAge:   2 * time.Minute,
        Strategy: "jwe",
        Version:  "authz-v3",
    },
},
```

The cache introduces bounded staleness. Sensitive stateful endpoints request
authoritative session lookup so revoked storage state is not accepted solely
from a stale cookie. Application authorization embedded in additional
user/session fields may remain stale on ordinary reads until cache expiry.

Increment `Version` when cached authorization semantics change. All replicas
must deploy the same version. A mixed rollout is safe only if you accept cache
misses and reissuance; do not alternate incompatible meanings under one
version.

`Session.Stateless=true` makes the signed session-data cookie authoritative.
That changes the revocation model: there is no server-side session authority to
consult for normal reads. Choose it deliberately, use a short cache lifetime,
and document how emergency revocation works for your application.

## Rate limiting

The production default enables HTTP rate limiting, but the default storage
choice follows configured state. For a replica-wide limit, select secondary
storage and ensure it implements an atomic increment operation.

Legacy get/set-only stores can lose increments under contention. The runtime
warns once and enforcement becomes best effort. Direct API calls bypass the
HTTP limiter entirely; protect any application endpoint that exposes them.

## Rollout invariants

Before increasing replica count, verify:

1. every replica uses the same `SINGLE_AUTH_SECRET` or ordered
   `SINGLE_AUTH_SECRETS` value;
2. all replicas use the same schema, cookie names, cache version, base URL,
   base path, and trusted origins;
3. migrations completed before new code receives traffic;
4. the selected store implements atomic consume/increment where required;
5. provider callback URLs route back to any healthy replica;
6. clocks are synchronized and shutdown drains in-flight callbacks;
7. Redis and database clients have timeouts, health monitoring, and pool sizes
   appropriate for aggregate traffic;
8. a rolling deploy has a documented compatibility window for schema and
   encrypted payloads.

## Failure drills

Test more than happy-path sign-in:

- create a session on replica A and read/revoke it through replica B;
- start OAuth on A and complete the callback on B;
- race the same verification token through two replicas and require one success;
- exhaust a rate limit across alternating replicas;
- remove a secondary session while a cookie cache exists and verify an
  authoritative endpoint rejects it;
- restart every replica while keeping database/Redis state and confirm sessions
  survive;
- rotate the active secret and confirm the expected cookie and in-flight OAuth
  invalidation described in [Rotate secrets](./rotate-secrets.md).

Read [Sessions](../core/sessions.md),
[Redis secondary storage](../storage/redis-secondary-storage.md), and
[Transactions](../storage/transactions.md) for the lower-level contracts.
