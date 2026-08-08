---
title: "Core runtime"
---

The native Go authentication lifecycle and the contracts shared by every transport.

`single-auth` is a native Go server runtime. One immutable `*singleauth.Auth` owns configuration, storage, sessions, security policy, routes, plugins, hooks, and a transport-neutral dispatcher. The same runtime can be mounted through `net/http`, direct `fasthttp`, or Fiber.

```go
auth, err := singleauth.New(singleauth.Options{
    AppName:    "Acme",
    Environment: "production",
    BaseURL:    "https://accounts.example.com",
    Secret:     os.Getenv("SINGLE_AUTH_SECRET"),
    Database:   adapter,
    EmailAndPassword: singleauth.EmailAndPasswordOptions{
        Enabled: true,
    },
    TrustedOrigins: []string{"https://app.example.com"},
})
if err != nil {
    return err
}
```

## What the runtime owns

- the core `user`, `session`, `account`, and `verification` models;
- credential sign-up, sign-in, password reset, and password changes;
- email verification, email changes, and account deletion;
- social sign-in, OAuth callback state, account linking, token refresh, and provider user info;
- signed cookies, optional session-data cookies, secret rotation, CSRF and redirect-origin validation;
- memory, database, or secondary-storage rate limiting;
- endpoint middleware, before/after hooks, database hooks, and plugin lifecycle stages;
- a direct server API and one dispatcher shared by all HTTP transports.

The default storage adapter is an isolated in-memory adapter. That default is useful for tests and examples, but it is not durable and is not shared between processes.

## Request lifecycle

For HTTP requests, the observable order is:

```text
initialize request context
  -> reject disabled path
  -> core rate-limit onRequest
  -> plugin onRequest handlers
  -> core security middleware
  -> user path middleware
  -> plugin path middleware
  -> match endpoint
  -> user before hooks
  -> plugin before hooks
  -> endpoint-local Use middleware
  -> endpoint handler
  -> user after hooks
  -> plugin after hooks
  -> plugin onResponse handlers
  -> transport writes the response
```

Direct invocation starts at context initialization, then runs before hooks, endpoint-local `Use`, the handler, and after hooks. It deliberately skips disabled-path routing, HTTP rate limiting, path middleware, plugin `OnRequest`, plugin `OnResponse`, and transport observers.

## Authentication levels

Core endpoints use five session policies:

| Policy | Meaning |
| --- | --- |
| Public | No session is required. |
| Optional | A valid session is used when present, but absence is accepted. |
| Session | The signed session token is required. A valid `session_data` cache may satisfy the lookup. |
| Authoritative | The signed token is required and stateful mode reads authoritative storage, bypassing `session_data`. |
| Fresh | A session is required and its `createdAt` must be younger than `Session.FreshAge`. |

`FreshAge` defaults to 24 hours. A configured zero means every valid session is fresh. Sensitive operations such as changing a password use authoritative storage; listing sessions and unlinking an account additionally require freshness.

## Public runtime surface

The root runtime exposes:

- construction: `New`, `MustNew`, `NewWithSQLiteDatabase`, `NewMinimal`, and `NewMinimalWithDatabase`;
- HTTP and transport access: `Handler`, `ServeHTTP`, `Dispatch`, `Dispatcher`, and `Registry`;
- trusted server invocation: `API` and `Invoke`;
- storage and context: `Adapter`, `InternalAdapter`, `AdapterForContext`, `Context`, `RunWithAdapter`, and `RunInTransaction`;
- configuration and services: `Options`, `Logger`, `RateLimiter`, `ErrorCodes`, and `ResolveBaseURL`;
- migrations: `RunMigrations` and `RunMigrationsContext`;
- OAuth-token helpers: `EncodeOAuthToken` and `DecodeOAuthToken`.

Returned options, headers, responses, registry descriptions, and error-code maps are independent snapshots. Treat the constructed runtime as immutable and safe for concurrent calls; custom callbacks, log handlers, HTTP clients, and storage implementations must provide their own concurrency safety.

- [Runtime and transactions](./runtime-and-transactions.md)
- [Sessions](./sessions.md)
- [Security](./security.md)
- [HTTP route reference](../reference/http-routes.md)
