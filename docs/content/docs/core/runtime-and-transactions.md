---
title: "Runtime and transactions"
---

Construction, migration contexts, adapter scoping, nested transactions, and post-transaction work.

`singleauth.New` constructs one immutable runtime. Do it once at application startup and share the returned pointer between goroutines and transports.

## Constructors

| Constructor | Behavior |
| --- | --- |
| `New(Options)` | Full runtime. Uses the supplied adapter or creates an isolated memory adapter. |
| `MustNew(Options)` | Calls `New` and panics on configuration errors. |
| `NewWithSQLiteDatabase(Options, *sql.DB)` | Builds the native SQLite adapter from a raw handle and enables native schema migration. |
| `NewMinimal(Options)` | Adapter-only minimal entry point. Runtime behavior is otherwise shared with `Auth`. |
| `NewMinimalWithDatabase(Options, any)` | Accepts a `storage.Adapter`; rejects raw database values. |

The full constructor performs these steps before returning:

1. clone and normalize options;
2. resolve the legacy secret or versioned secret ring;
3. merge the core schema, optional database rate-limit schema, explicit schema, static plugin schemas, and plugin-factory schemas;
4. initialize the explicit adapter, raw SQLite adapter, or memory adapter;
5. wrap storage with database hooks;
6. build plugin factories against the bound host runtime;
7. freeze password-hash wrappers and database hooks;
8. build the rate limiter, endpoint registry, dispatcher, and `net/http` handler.

Duplicate or incompatible schemas, endpoints, plugin IDs, routes, and middleware patterns fail construction. A factory's `PluginID` must be non-empty and must match the plugin returned by `Build`.

## Runtime accessors

```go
handler := auth.Handler()                 // net/http.Handler
dispatcher := auth.Dispatcher()           // fasthttp and Fiber input
registry := auth.Registry()               // immutable endpoint registry
adapter := auth.Adapter()                 // hook-aware storage.Adapter
internal := auth.InternalAdapter()        // Better Auth lifecycle facade
logger := auth.Logger()
limiter := auth.RateLimiter()
snapshot := auth.Options()                // independent copy
codes := auth.ErrorCodes()                // independent merged map
```

`Dispatch` accepts a transport-neutral `contract.Request`. `Invoke` accepts an endpoint's direct API name and `engine.DirectInput`. `API` is the typed convenience façade over `Invoke`. `ResolveBaseURL` applies the same host allowlist and proxy policy used by core OAuth and email routes.

`EncodeOAuthToken` and `DecodeOAuthToken` apply the configured OAuth-token encryption and secret rotation policy. Treat their result as storage data, not as a browser session token.

## Migrations

`RunMigrations` uses a background context. `RunMigrationsContext` accepts cancellation. The same methods are available through `Auth.Context()`:

```go
runtimeContext, err := auth.Context()
if err != nil {
    return err
}

log.Printf("database type: %s", runtimeContext.DatabaseType)
if err := runtimeContext.RunMigrationsContext(ctx); err != nil {
    return err
}
```

An adapter implementing `storage.SchemaEnsurer` supplies migration support. `NewWithSQLiteDatabase` also installs SQLite's `EnsureSchema`. Otherwise full mode returns `ErrFullMigrationsRequireDatabase` with the upstream-compatible diagnostic.

Minimal mode never performs migrations: both `MinimalAuth.RunMigrations` and `MinimalContext.RunMigrations` return `ErrMinimalMigrationsUnsupported`. `NewMinimalWithDatabase` rejects a raw connection with `ErrMinimalDirectDatabaseUnsupported`; pass a configured adapter instead.

## Context-bound adapters

`AdapterForContext` returns the active transaction adapter carried by a context. Outside a scope it returns the root adapter:

```go
err := auth.RunInTransaction(ctx, func(txCtx context.Context) error {
    tx := auth.AdapterForContext(txCtx)

    _, err := tx.Create(txCtx, storage.CreateParams{
        Model: "auditEvent",
        Data: storage.Record{
            "kind": "account.created",
        },
    })
    return err
})
```

Pass `txCtx` to every adapter call, direct invocation, dispatcher request, and plugin callback that must join the transaction. The engine also makes the active scope visible through an endpoint's Go context.

### Nested transactions

`RunInTransaction` reuses an already active transaction. A nested call does not open a second database transaction:

```go
err := auth.RunInTransaction(ctx, func(outer context.Context) error {
    outerAdapter := auth.AdapterForContext(outer)

    return auth.RunInTransaction(outer, func(inner context.Context) error {
        if auth.AdapterForContext(inner) != outerAdapter {
            return errors.New("transaction scope was not reused")
        }
        return nil
    })
})
```

When an adapter returns `storage.ErrTransactionsUnsupported`, the callback still runs against the ordinary adapter. That preserves functional behavior but cannot provide rollback or isolation; choose an adapter with real transaction support for multi-record security operations.

### Plain adapter scopes

`RunWithAdapter` binds the root adapter without marking a transaction active. A nested `RunInTransaction` still opens a real transaction:

```go
err := auth.RunWithAdapter(ctx, func(adapterCtx context.Context) error {
    return auth.RunInTransaction(adapterCtx, func(txCtx context.Context) error {
        // AdapterForContext(txCtx) is the transaction adapter.
        return updateRelatedRecords(txCtx, auth.AdapterForContext(txCtx))
    })
})
```

Nil contexts become `context.Background`. Nil callbacks are rejected. Transaction and adapter scopes are request-local and safe to use concurrently as separate calls.

## Work after a transaction scope

`QueueAfterTransactionHook` queues work on the current adapter/transaction scope and runs it after the outer scope finishes. Nested calls share the outer queue. Outside a scope, the callback runs immediately.

```go
err := auth.RunInTransaction(ctx, func(txCtx context.Context) error {
    if err := writeAccount(txCtx, auth.AdapterForContext(txCtx)); err != nil {
        return err
    }
    return singleauth.QueueAfterTransactionHook(txCtx, func() error {
        return events.Publish("account.changed")
    })
})
```

This general scope hook is different from database `After` hooks. Hook-aware adapter `After` callbacks are queued by the adapter and run only after its transaction successfully commits. Outside an adapter transaction they run after the operation completes. Do not put a non-idempotent network side effect in a general queue and assume it proves a commit; use storage outbox semantics when delivery and commit must be atomic.

## Internal adapter

`auth.InternalAdapter()` is a higher-level, hook-aware lifecycle facade. It understands secondary session storage, verification identifier hashing, account creation, session joins, and transaction scoping. It includes operations for users, accounts, sessions, and verification values, including atomic reserve/consume behavior where the configured backend supports it.

Use the raw `storage.Adapter` when implementing storage-generic infrastructure. Use `InternalAdapter` when application or plugin code must preserve the same lifecycle semantics as core authentication routes. Neither surface writes browser cookies; session cookies are response behavior owned by endpoint execution.

## Concurrency contract

`Auth`, the dispatcher, registry, built-in adapters, cookie helpers, and logger are designed for concurrent use. Configuration callbacks and custom implementations must also be concurrency-safe:

- `storage.Adapter` and `storage.TransactionAdapter`;
- secondary storage and atomic consume/increment extensions;
- `logger.Handler` and custom writers;
- `RunBackground`, mail callbacks, hooks, provider overrides, and trusted-origin resolvers;
- custom random readers, clocks, and HTTP clients.

Do not mutate a provider or plugin instance after passing it to `New`. The runtime clones public descriptors, but callback closures can still capture mutable application state.
