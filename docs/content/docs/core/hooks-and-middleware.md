---
title: "Hooks and middleware"
---

Exact dispatcher ordering, short-circuit rules, endpoint middleware, and database lifecycle hooks.

`single-auth` has distinct extension stages. Choose the narrowest stage that matches the behavior: path middleware for HTTP routing, endpoint `Use` for request-local preparation in every dispatch mode, before/after hooks for endpoint policy, and database hooks for model lifecycle invariants.

## Exact HTTP order

```text
context initializer
disabled-path check
core rate-limit OnRequest
plugin OnRequest (plugin order)
core security path middleware
user path middleware (declaration order)
plugin path middleware (plugin order, declaration order)
route match
user Before hooks
plugin Before hooks
endpoint Use middleware
endpoint handler
user After hooks
plugin After hooks
plugin OnResponse (plugin order)
```

`Options.Middleware` is inserted after the core security middleware. Static plugins and plugin factories contribute middleware and hooks in their configured order.

Direct `Invoke`/`API` execution initializes context, then runs user/plugin before hooks, endpoint `Use`, the handler, and user/plugin after hooks. It skips disabled paths, rate limiting, all path middleware, plugin `OnRequest`, and plugin `OnResponse`.

`engine.RunEndpointIsolated` is narrower still: it clones request-local values and runs only the target endpoint's `Use` middleware and handler. It does not run registry hooks, path middleware, or response stages.

## Path middleware

```go
Middleware: []engine.Middleware{
    {
        Name: "tenant-context",
        Path: "/**",
        Handler: func(ctx *engine.Context, next engine.Next) (contract.Response, error) {
            tenantID, ok := ctx.Request().Headers().Get("X-Tenant-ID")
            if ok && strings.TrimSpace(tenantID) != "" {
                ctx.Set("tenant-id", strings.TrimSpace(tenantID))
            }
            response, err := next()
            return response.WithHeader("X-Auth-Pipeline", "completed"), err
        },
    },
},
```

Paths are endpoint-relative, not prefixed by `BasePath`. They support dynamic parameters and a final wildcard such as `/oauth/**`. Middleware wraps downstream execution; code before `next` runs on entry and code after it runs on unwind.

Returning without calling `next` short-circuits matching and the endpoint pipeline. A middleware error is converted to a stable response; an unknown error is redacted on the wire.

## Before hooks

```go
Hooks: engine.Hooks{
    Before: []engine.BeforeHook{
        {
            Name: "block-disabled-tenant",
            Matcher: func(ctx *engine.Context) (bool, error) {
                return ctx.RoutePath() == "/sign-in/email", nil
            },
            Handler: func(ctx *engine.Context) (*contract.Response, error) {
                disabled, _ := ctx.Request().Headers().Get("X-Tenant-Disabled")
                if strings.EqualFold(strings.TrimSpace(disabled), "true") {
                    err := contract.NewAPIError(403, "TENANT_DISABLED", "Tenant is disabled")
                    response := contract.ResponseFromError(err)
                    return &response, nil
                }
                return nil, nil
            },
        },
    },
},
```

A nil matcher means always. Matcher failure becomes `500 HOOK_MATCHER_ERROR` with the original cause retained server-side. A non-nil response from a before hook stops remaining before hooks, endpoint `Use`, the handler, and all after hooks. Response headers accumulated before the short circuit are preserved.

User before hooks run before plugin before hooks. Within each source, declaration order is preserved.

## Endpoint-local `Use`

Endpoint middleware is part of an `engine.Endpoint`, so it runs for HTTP, direct, and isolated invocation:

```go
endpoint := engine.Endpoint{
    Name:    "profileExport",
    Path:    "/profile/export",
    Methods: []string{"POST"},
    Use: []engine.EndpointMiddlewareFunc{
        func(ctx *engine.Context) (engine.EndpointMiddlewareResult, error) {
            principalID, ok := ctx.Request().Headers().Get("X-Principal-ID")
            if !ok || strings.TrimSpace(principalID) == "" {
                return engine.EndpointMiddlewareResult{}, contract.NewAPIError(
                    401,
                    "UNAUTHORIZED",
                    "Authentication required",
                )
            }
            return engine.EndpointMiddlewareResult{
                Values: map[string]any{"principal-id": strings.TrimSpace(principalID)},
            }, nil
        },
    },
    Handler: func(ctx *engine.Context) (contract.Response, error) {
        principalID, _ := ctx.Value("principal-id")
        return contract.JSONResponse(200, map[string]any{
            "principalId": principalID,
            "exported":    true,
        })
    },
}
```

Each result's values are merged before the next `Use` function. A non-nil response merges the values and short-circuits the remaining `Use` functions plus handler. Nil functions fail with `ENDPOINT_MIDDLEWARE_REQUIRED`.

Endpoint `Use` runs after before hooks. A before hook therefore cannot read values produced by `Use`; move prerequisite parsing to a path middleware or the before hook itself when that ordering is required.

## After hooks

After hooks receive the current immutable response and may preserve it by returning nil or replace it by returning a response. Accumulated headers are merged, with `Set-Cookie` appended and other response fields replaced by name.

```go
After: []engine.AfterHook{
    {
        Name: "security-headers",
        Handler: func(
            ctx *engine.Context,
            response contract.Response,
        ) (*contract.Response, error) {
            updated := response.WithHeader("X-Content-Type-Options", "nosniff")
            return &updated, nil
        },
    },
},
```

After hooks run for successful handlers and typed `contract.APIError` failures. Unknown handler errors skip after hooks and escape directly. A typed error returned by an after hook becomes the current error and later after hooks may replace it; an unknown after-hook error stops the pipeline.

The request-local context exposes the returned response/error to later hooks. A hook may deliberately remove pending headers, including session cookies, before returning a replacement.

Plugin `OnResponse` runs only on the HTTP path after the complete endpoint pipeline, including early HTTP failures that reached response finishing. It may replace the response. Direct calls do not execute it.

## Disabled paths and trailing slashes

`DisabledPaths` are exact endpoint-relative paths. They are checked before rate-limit/plugin `OnRequest` and return 404. They are not wildcard patterns.

`Advanced.SkipTrailingSlashes` allows declared and requested trailing-slash variants to match. The request-local `RoutePath` remains the path received on the wire, so hook matching can still distinguish it.

## Database hooks

Database hooks are keyed by canonical model name and create/update/delete lifecycle:

```go
DatabaseHooks: singleauth.DatabaseHooks{
    "user": {
        Create: singleauth.DatabaseOperationHooks{
            Before: func(
                data storage.Record,
                hook singleauth.DatabaseHookContext,
            ) (singleauth.DatabaseHookResult, error) {
                email, _ := data["email"].(string)
                if strings.HasSuffix(email, "@blocked.example") {
                    return singleauth.DatabaseHookResult{Cancel: true}, nil
                }
                tenantID := "public"
                if strings.HasSuffix(email, "@acme.example") {
                    tenantID = "acme"
                }
                return singleauth.DatabaseHookResult{
                    Data: storage.Record{"tenantId": tenantID},
                }, nil
            },
            After: func(value any, hook singleauth.DatabaseHookContext) error {
                user, _ := value.(storage.Record)
                slog.InfoContext(hook.Context, "auth user created", "userId", user["id"])
                return nil
            },
        },
    },
},
```

`DatabaseHookContext` contains:

- ordinary `Context` with cancellation and transaction scope;
- `Endpoint`, which is nil for adapter work outside dispatch;
- `Source` (`user` or a plugin identity);
- canonical `Model`;
- `Operation`: `create`, `update`, `updateMany`, or `delete`.

Before hooks receive cloned data. `Cancel` stops the write without an error. `Data` is merged over the effective write. Create and delete hooks are chained so later hooks see prior patches where relevant. Update hooks each receive the original update object, while all returned patches are merged in source order.

Plugin-factory database hooks are registered before `Options.DatabaseHooks`, so plugin hooks run first and user hooks run afterward. Registrations are frozen during `New`; late registration is rejected.

Delete hooks receive a snapshot of the row. Delete-many runs before hooks for each discovered row before performing the bulk delete, then after hooks for each row. `ConsumeOne` uses delete lifecycle hooks because it atomically removes a single-use record.

Database after hooks run after the write. Inside a hook-aware adapter transaction they are queued and run only after a successful commit; outside a transaction they run immediately after the operation. If an after hook fails after commit, its error is observable but the committed data cannot be rolled back.

## Header and context safety

`contract.Request`, `contract.Response`, and accessor-returned `contract.Headers` are snapshots. Use `Clone`, `WithHeader`, `WithAddedHeader`, and `WithMergedHeaders` instead of mutating shared values.

An `engine.Context` belongs to one request and must not escape into a background goroutine. Copy the values you need and use `ctx.GoContext()` according to the cancellation semantics of your job runner. Every middleware/hook callback must be concurrency-safe because the same function may serve many requests simultaneously.
