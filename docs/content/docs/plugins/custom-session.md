---
title: "Custom session"
description: "Replace the public session shape with an application-defined, optionally typed projection."
---

Custom session replaces the root `GET /get-session` response with an application-defined projection. The callback receives the root's already serialized public user and session records, so additional fields and root output filtering have already run.

## Install and configure

Import `github.com/pers0na2dev/single-auth/plugins/customsession`. `Enrich` is required.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/engine"
    "github.com/pers0na2dev/single-auth/plugins/customsession"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            customsession.NewFactory(customsession.Options{
                Enrich: func(data customsession.SessionData, _ *engine.Context) (any, error) {
                    return map[string]any{
                        "user": map[string]any{
                            "id":    data.User["id"],
                            "name":  data.User["name"],
                            "email": data.User["email"],
                        },
                        "session": data.Session,
                        "features": []string{"dashboard", "export"},
                    }, nil
                },
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The factory overrides the existing root operation named `getSession`; it does not create a second route. No ordering is required for the override. If device-session list projection is enabled, register the [multi-session](./multi-session.md) factory as well; placing multi-session first makes that dependency explicit.

## HTTP contract

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| GET | `/get-session` | Root query options and session headers/cookies | Custom projection or JSON `null` | Optional session |
| GET | `/multi-session/list-device-sessions` | Multi-session cookies | Array of custom projections when mutation is enabled | Multi-session endpoint authority |

`POST /get-session` remains method-not-allowed. Query behavior from the core route, including `disableRefresh=true` and `disableCookieCache=true`, remains available because the override calls the unmodified root session endpoint internally.

### Projection input and result

`SessionData` contains two `storage.Record` values:

```go
type SessionData struct {
    User    storage.Record
    Session storage.Record
}
```

The records are cloned before the callback. Mutating them cannot mutate the root session result. The returned value must be JSON-serializable.

```http
GET /api/auth/get-session
Cookie: single-auth.session_token=...
```

```json
{
  "user": {
    "id": "user-id",
    "name": "Ada",
    "email": "ada@example.com"
  },
  "session": {
    "id": "session-id",
    "userId": "user-id",
    "expiresAt": "2026-08-11T12:00:00Z"
  },
  "features": ["dashboard", "export"]
}
```

When the core endpoint returns no usable session, the custom endpoint returns HTTP 200 with JSON `null` and does not call `Enrich`. For compatibility, a core error or non-200 core response is also collapsed to 200 `null`; diagnose unexpected nulls through root session/storage logs rather than expecting the inner error on the wire.

When enrichment succeeds, cache-control and refreshed session/cache cookies from the core response are transferred to the outer response. If `Enrich` returns an error, that error propagates and the inner response's cookies are not transferred.

## Typed server projection

Use `NewTypedFactory` when the projection has a stable Go type. The same factory is registered with the server and provides the typed direct API binding.

```go
type SessionProjection struct {
    UserID   string   `json:"userId"`
    Features []string `json:"features"`
}

factory := customsession.NewTypedFactory(
    customsession.TypedOptions[SessionProjection]{
        Enrich: func(
            data customsession.SessionData,
            _ *engine.Context,
        ) (SessionProjection, error) {
            userID, _ := data.User["id"].(string)
            return SessionProjection{
                UserID:   userID,
                Features: []string{"dashboard", "export"},
            }, nil
        },
    },
)

auth, err := singleauth.New(singleauth.Options{
    BaseURL:         "https://auth.example.com",
    Secret:          os.Getenv("SINGLE_AUTH_SECRET"),
    PluginFactories: []singleauth.PluginFactory{factory},
})
if err != nil {
    return err
}

typedAuth, err := factory.BindAuth(auth)
if err != nil {
    return err
}

session, err := typedAuth.API().GetSession(ctx, singleauth.GetSessionInput{
    Headers: requestHeaders,
})
if err != nil {
    return err
}
if session == nil {
    return errNoSession
}
fmt.Println(session.Data.UserID)
```

`TypedSessionResult` contains the concrete `Data` and the response `contract.Headers`, including any refreshed cookies. The embedded root `DirectAPI` keeps unrelated typed methods such as sign-up and sign-out available.

The untyped factory has no separately bound service. Trusted code can call the overridden `getSession` operation through `auth.API().Call`; use the typed factory when decoding the custom shape matters.

## Multi-session list projection

Set `ShouldMutateListDeviceSessionsEndpoint: true` to project every successful item returned by `GET /multi-session/list-device-sessions`:

```go
factory := customsession.NewFactory(customsession.Options{
    ShouldMutateListDeviceSessionsEndpoint: true,
    Enrich: func(data customsession.SessionData, _ *engine.Context) (any, error) {
        return map[string]any{
            "userId":    data.User["id"],
            "sessionId": data.Session["id"],
        }, nil
    },
})
```

The option defaults to false and does nothing unless the multi-session route exists. Only a 200, truthy JSON array is transformed. Items are enriched concurrently but written back in their original order. Every started callback is allowed to finish; if any callback fails, the response fails after all items complete. Because completion is concurrent, do not depend on which error is observed first.

The same live `*engine.Context` is visible to concurrent list callbacks. Reading stable request data is supported; callbacks must synchronize their own writes and must not mutate shared context state.

## Schema and migrations

Custom session changes only response shape. It adds no model, field, or migration. The projection sees whatever public user/session fields are provided by the root schema and installed plugins.

Changing the JSON projection is an API contract change even though it needs no database migration. Version consumers or roll out backward-compatible fields when consumers decode a concrete struct.

## Failure, performance, and security

- `Enrich` runs on every non-null session read. Database or network calls inside it add directly to session lookup latency.
- Device-session list mutation fans out one concurrent callback per returned item. Bound downstream work or batch lookups when the list can be large.
- Callbacks can run concurrently across requests and within one list request. Keep captured state immutable or synchronized.
- The callback receives public serialized records, not raw adapter records, but it also receives the live endpoint context. Do not copy secrets, cookies, internal headers, provider tokens, or server-only authorization state into the projection.
- Derive convenience data from authoritative server state. Do not grant access solely because a client sends a field that resembles a projected role or feature flag.
- Return intentional `contract.APIError` values for safe client-visible failures. Log underlying errors without exposing session data.

## Troubleshooting

- `GET /get-session` returning `null` can mean no session, an invalid/expired cookie, a core storage failure, or a non-200 core session result. Inspect server logs and call the unmodified session dependencies in a focused test.
- Missing refreshed cookies usually means `Enrich` returned an error before header transfer, or refresh was disabled by query/configuration.
- An unchanged device-session list means the option is false, multi-session is not installed, the route returned a non-200/null value, or the request path differs from `/multi-session/list-device-sessions`.
- A slow list with a fast single-session lookup usually means the enrichment callback performs per-item I/O.

## Related pages

- [Sessions](../core/sessions.md)
- [Multi-session](./multi-session.md)
- [Direct API](../transports/direct-api.md)
- [Additional fields](./additional-fields.md)

**Status:** implemented across `net/http`, fasthttp, Fiber, direct dispatch, typed server calls, refresh headers, and concurrent device-session projection.
