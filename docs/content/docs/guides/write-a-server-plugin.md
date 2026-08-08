---
title: "Write a server plugin"
description: "Build a native Go PluginFactory with schema-first initialization, authenticated endpoints, hooks, errors, and transport-neutral tests."
---

A server plugin is an immutable descriptor merged into the same route registry,
security pipeline, schema, and direct API as core authentication. Use a
`PluginFactory` when the plugin needs root sessions, storage, cookies, secrets,
OAuth helpers, email lifecycle, or another runtime-bound service.

Use a static `engine.Plugin` only for a descriptor whose dependencies are
already complete and whose schema does not depend on final root configuration.

## Factory lifecycle

Every factory implements:

```go
type PluginFactory interface {
    PluginID() string
    Schema() (storage.Schema, error)
    Build(PluginHost) (engine.Plugin, error)
}
```

Initialization has two phases:

1. `Schema` runs while single-auth composes core, application, and plugin
   models. It must be deterministic and describe every field/model used by the
   plugin.
2. The root adapter and internal services are created from that final schema.
3. `Build` receives a `PluginHost` bound to those services and returns the
   frozen engine descriptor.

Do not read request state or perform migrations in `Schema`. Do not return a
schema from `Build` that differs from the factory's first-phase schema.

## Minimal authenticated endpoint

This complete factory adds `GET /who-am-i` relative to the configured base
path:

```go
package customplugin

import (
    "fmt"
    "net/http"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/contract"
    "github.com/pers0na2dev/single-auth/core/engine"
    "github.com/pers0na2dev/single-auth/storage"
)

type Factory struct{}

func NewFactory() *Factory { return &Factory{} }

func (*Factory) PluginID() string { return "who-am-i" }

func (*Factory) Schema() (storage.Schema, error) {
    return storage.Schema{}, nil
}

func (*Factory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
    if host.ResolveSession == nil || host.SerializeUser == nil {
        return engine.Plugin{}, fmt.Errorf("who-am-i: session host is incomplete")
    }

    return engine.Plugin{
        ID:      "who-am-i",
        Version: "1.0.0",
        Endpoints: []engine.Endpoint{{
            Name:        "whoAmI",
            Path:        "/who-am-i",
            Methods:     []string{http.MethodGet},
            OperationID: "whoAmI",
            Handler: func(ctx *engine.Context) (contract.Response, error) {
                state, err := host.ResolveSession(
                    ctx,
                    singleauth.PluginSessionAuthoritative,
                )
                if err != nil {
                    return contract.Response{}, err
                }
                return contract.JSONResponse(http.StatusOK, map[string]any{
                    "user": host.SerializeUser(state.User),
                })
            },
        }},
    }, nil
}

var _ singleauth.PluginFactory = (*Factory)(nil)
```

Register it before runtime construction:

```go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
    PluginFactories: []singleauth.PluginFactory{
        customplugin.NewFactory(),
    },
})
```

With the default base path, the public URL is
`/api/auth/who-am-i`. Endpoint paths and middleware paths are always relative
to `Options.BasePath`.

The example is compile-checked in `docs/examples/customplugin` and exercises a
real sign-up cookie through the plugin endpoint.

## Choose session authority

`PluginHost.ResolveSession` centralizes root cookie, cache, secondary-storage,
expiry, and serialization behavior:

| Mode | Use |
| --- | --- |
| `PluginSessionOptional` | Anonymous and authenticated requests are both valid. |
| `PluginSessionRequired` | A logical session is required; the stateful cookie cache may satisfy the read. |
| `PluginSessionAuthoritative` | Require a session and bypass a stateful cookie cache. Use for sensitive changes or revocation decisions. |
| `PluginSessionFresh` | Require the root freshness policy in addition to authentication. |

Do not parse the raw session cookie in a plugin. That bypasses chunking,
signatures, secondary authority, cache policy, and revocation behavior.

Use `host.SerializeUser` and `host.SerializeSession` for public results. They
apply configured additional fields and returned-field policy. Never serialize a
raw adapter record containing hashes, tokens, internal fields, or plugin-only
state without an explicit public schema.

## Endpoint contract

Every endpoint needs:

- a globally unique `Name` used by the direct API registry;
- one endpoint-relative `Path`;
- an explicit method set;
- a concurrency-safe handler;
- an `OperationID` when it should appear in generated OpenAPI output;
- optional endpoint-local `Use` middleware that must run in HTTP and direct
  dispatch.

Unknown methods on a known path return 405. Set `ServerOnly: true` for a trusted
direct operation that must never become an HTTP route. The engine also honors
the `SERVER_ONLY` metadata marker as defense in depth.

Return `contract.APIError` for a stable public failure:

```go
return contract.Response{}, contract.NewAPIError(
    http.StatusForbidden,
    "PROFILE_EXPORT_FORBIDDEN",
    "Profile export is not allowed",
)
```

Unknown errors are redacted to `INTERNAL_SERVER_ERROR`. Attach an internal
cause to a typed error when logs need it; never put database/provider details in
the public message.

Plugin-level `ErrorCodes` documents definitions for tooling, but handlers still
choose the appropriate status and return the actual typed error.

## Add a model or field

Return the extension during the schema phase:

```go
func (*Factory) Schema() (storage.Schema, error) {
    return storage.Schema{Models: map[string]storage.ModelSchema{
        "user": {
            Fields: map[string]storage.FieldAttribute{
                "supportTier": {
                    Type:     storage.FieldString,
                    Required: storage.Bool(false),
                    Input:    storage.Bool(false),
                    Index:    true,
                },
            },
        },
    }}, nil
}
```

`Input:false` keeps the field server-controlled. Choose `Returned` separately
when a field must remain private. References must name canonical models/fields
and specify deletion behavior explicitly.

After adding or changing schema, run the final runtime's migration method:

```go
if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

Migrations are additive. Renames, removals, destructive type conversions, and
required-field backfills need an application migration plan.

## Use the bound adapter correctly

`host.Adapter` is the final public adapter. `host.InternalAdapter` preserves
root model aliases, transforms, hooks, and lifecycle behavior for plugins that
need the same semantics as core endpoints. Use
`host.AdapterForContext(ctx.GoContext())` when work must participate in a
context-bound transaction.

For multi-row invariants, use the host transaction helper or the current
transaction adapter. Do not open an unrelated transaction on the raw database;
that loses root hook and context coordination.

Single-use values should use `CreateVerification`, `PeekVerification`, and
`ConsumeVerification`. The host routes them through primary or secondary
storage and uses atomic consume extensions where available.

## Hooks and middleware

A plugin descriptor can contribute:

- `Middleware` for path-scoped HTTP wrapping;
- before/after `Hooks` for endpoint policy and response transformation;
- endpoint `Use` middleware for preparation shared by HTTP and direct calls;
- `OnRequest` and `OnResponse` for outer HTTP-only stages;
- database hooks registered through the host;
- `RateLimit` matcher rules;
- trusted origins and exact protocol callback origin-skip paths.

Use the narrowest mechanism. For example, authentication that must also protect
direct calls belongs in endpoint `Use` or the handler, not only path middleware.

The full HTTP order is documented in
[Hooks and middleware](../core/hooks-and-middleware.md). Direct calls skip HTTP
rate limiting, path middleware, `OnRequest`, `OnResponse`, and origin/CSRF
checks.

## Security review

Before publishing a plugin, answer:

- Which endpoints are public, optional-session, authoritative, or fresh?
- Which input fields are browser-controlled, and how are they decoded and
  bounded?
- Which redirect URLs require root validation?
- Which secrets need hashing, signing, encryption, expiry, and atomic consume?
- What must be transactionally rolled back?
- Can two replicas race the same mutation?
- Which external callback skips browser origin checks, and what protocol proof
  replaces them?
- Are direct helpers reachable only from trusted server code?
- Are response headers and multiple `Set-Cookie` lines preserved?
- Does logging exclude credentials and protocol tokens?

Never add a broad `SkipOriginCheckPaths` entry for an ordinary application
endpoint. External protocol callbacks need their own state, signature, issuer,
audience, expiry, and replay checks.

## Test matrix

At minimum, cover:

1. factory validation and immutable option snapshots;
2. schema composition before adapter creation;
3. success and malformed-input failures;
4. missing, stale, revoked, and wrong-owner sessions;
5. hook/middleware short-circuit and ordering;
6. rollback when a later write fails;
7. replay and concurrent mutation behavior;
8. unknown method, disabled path, and server-only routing;
9. `net/http`, direct `fasthttp`, and Fiber parity;
10. every applicable real storage backend and `go test -race`.

Use [Storage testing](../storage/testing.md) for adapter-dependent work and the
[generated engine reference](../reference/packages/core--engine.md) for exact
declarations.
