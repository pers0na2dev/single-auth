---
title: "Last login method"
description: "Remember the authentication method that most recently issued a session, in a readable cookie and optional user field."
---

Last login method records which recognized authentication flow most recently issued a session. Applications can use the readable value to preselect a sign-in button or label, but it is never proof that the user completed that method now.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/lastloginmethod` and use `NewFactory`. With cookie-only storage there is no schema change. `StoreInDatabase:true` contributes an optional user field and requires applying the composed schema before serving traffic.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/lastloginmethod"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            lastloginmethod.NewFactory(lastloginmethod.Options{
                StoreInDatabase: true,
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The root registry is finalized lazily, so the factory can discover authentication endpoints regardless of factory position. Factory order still determines after-hook order; place it before a later hook that intentionally removes session `Set-Cookie` headers. The database hooks are installed during root initialization when enabled.

## Built-in method resolution

The resolver sees the declared route pattern and path parameters, not just the concrete URL. Built-in results are:

| Endpoint path | Stored method |
| --- | --- |
| `/sign-in/email`, `/sign-up/email` | `email` |
| `/callback/:id` or another `/callback/...` path | `id` parameter, then `providerId`, then final path segment |
| `/oauth2/callback/:providerId` or another `/oauth2/callback/...` path | `id` parameter, then `providerId`, then final path segment |
| Any path containing `siwe` | `siwe` |
| Any path containing `/passkey/verify-authentication` | `passkey` |
| Any path beginning `/magic-link/verify` | `magic-link` |
| Unknown or pathless endpoint | No method; nothing is stored |

Username and phone-number sign-in are not built-in resolver cases in the current Go implementation. Add a custom resolver when they or another custom flow should be remembered:

```go
CustomResolveMethod: func(ctx lastloginmethod.HookContext) (*string, error) {
    switch ctx.Path {
    case "/sign-in/username":
        return lastloginmethod.Method("username"), nil
    case "/phone-number/verify":
        return lastloginmethod.Method("phone-number"), nil
    default:
        return nil, nil // fall back to the built-in resolver
    }
},
```

Returning nil delegates to built-in resolution. Returning `lastloginmethod.Method("")` is an explicit empty result and suppresses the fallback. A resolver error is propagated by normal/database hooks and can fail the authentication lifecycle; make recoverable misses return nil instead.

## Cookie lifecycle

After every endpoint response, the plugin resolves a method and then looks for a response `Set-Cookie` containing the request-scoped root session-cookie name. It writes the last-login cookie only when a recognized method and a newly issued session cookie are both present. Failed sign-ins and callbacks that do not issue a session therefore do not overwrite the hint.

The default cookie is:

```text
single-auth.last_used_login_method=email; Path=/; Max-Age=2592000; SameSite=Lax
```

Its actual `Path`, `Domain`, `Secure`, `SameSite`, and `Partitioned` attributes are inherited from the root session cookie. The plugin overrides `MaxAge` and forces `HTTPOnly:false` so a client can read it. `CookieName` is used verbatim and is deliberately unaffected by the root cookie prefix.

`BeforeStoreCookie` can implement consent or per-method policy:

```go
BeforeStoreCookie: func(ctx lastloginmethod.HookContext, method string) (bool, error) {
    return consent.AllowsFunctionalCookies(ctx.Request), nil
},
```

Returning false skips only the cookie. Returning an error logs `[LastLoginMethod] Error in beforeStoreCookie hook`, skips the cookie, and allows authentication to continue. This hook does not suppress database storage.

## Optional database storage

With `StoreInDatabase:true`, the factory extends `user` with canonical `lastLoginMethod`:

| Property | Value |
| --- | --- |
| Type | Optional string |
| Input | `false`; clients cannot forge it through ordinary user mutation |
| Physical field | `lastLoginMethod`, or `Schema.User.LastLoginMethod` alias |

The user-create before-hook records a resolved method on first sign-up. The session-create after-hook updates the same field on later successful logins. A session-hook update failure is logged as `Failed to update lastLoginMethod` and swallowed so the session can still succeed. A resolution error is not swallowed.

Apply a migration when enabling database storage or changing its physical alias; see [Schemas](../storage/schemas.md) and [Migrations](../storage/migrations.md). The alias must not collide with another physical user field. Disabling `StoreInDatabase` contributes no schema and installs no database hooks.

Cookie consent and database policy are independent. If the stored method is also personal data under your policy, enforce that decision in `CustomResolveMethod`, plugin registration, or application data handling rather than assuming `BeforeStoreCookie` blocks it.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `CookieName` | `single-auth.last_used_login_method` | Used verbatim; not prefixed by root cookie configuration |
| `MaxAge` | 2,592,000 seconds (30 days) | Pointer preserves omission versus explicit zero; use `lastloginmethod.Int(0)` to emit a deletion-style `Max-Age=0` cookie |
| `CustomResolveMethod` | nil | Runs before built-in resolution for cookie and database hooks |
| `StoreInDatabase` | `false` | Adds user field and database hooks |
| `BeforeStoreCookie` | nil | Consent/policy decision for only the readable cookie |
| `Schema.User.LastLoginMethod` | `lastLoginMethod` | Physical field alias when database storage is enabled |
| `Runtime` | Bound by `NewFactory` | Adapter, logger, session-cookie resolver, and database-hook registrar for standalone embedding/tests |

Option pointer values are snapshotted at construction. `CookieName` should be a valid cookie name; an invalid serialized cookie is skipped rather than creating a route error.

## Endpoints, direct API, and concurrency

There are no plugin routes, error codes, service methods, or response bodies. Cookie and database behavior is attached to whichever auth endpoint creates the session. `net/http`, direct `fasthttp`, Fiber, and `auth.API()` all run the after-hook; direct responses return `Set-Cookie` headers but do not persist them into a browser automatically.

There is no replay-sensitive credential in this plugin. A client can edit or replay the readable value at will. Database writes reflect server-side endpoint resolution and are more authoritative as history, but still do not authenticate the current request.

The compiled plugin is safe for concurrent use. `CustomResolveMethod` and `BeforeStoreCookie` may run concurrently and, when database storage is enabled, resolution can run more than once during one sign-up/login lifecycle. Keep callbacks deterministic, idempotent, and safe for repeated calls.

## Security and troubleshooting

- Never use the cookie or database field as an authentication factor, authorization claim, MFA result, or proof of account ownership.
- The cookie is intentionally readable and inherits cross-domain attributes from the session configuration. Keep its value low-sensitivity and use the narrowest appropriate domain.
- If no cookie is written, verify both that the resolver recognizes the declared route and that the response actually sets the root session cookie. Then inspect `BeforeStoreCookie` logs.
- If username or phone sign-in is missing, add a custom resolver; those routes are not built in.
- If the database updates but the cookie does not, inspect consent policy. Database storage happens independently of `BeforeStoreCookie`.
- If clearing fails across subdomains, configure the plugin cookie domain to match the server cookie domain.
- A custom resolver error can turn a successful auth operation into an error. Reserve errors for real failures and return nil for unknown paths.

See [Sessions](../core/sessions.md), [Security](../core/security.md), and the [last-login-method package reference](../reference/packages/plugins--lastloginmethod.md).

**Status:** implemented with cookie-prefix compatibility, optional database history, consent hooks, custom resolution, concurrency, and all Go transport coverage.
