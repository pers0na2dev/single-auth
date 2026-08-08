---
title: "Bearer sessions"
description: "Accept session credentials in Authorization headers and expose newly issued session cookies to HTTP callers."
---

Bearer adapts the root signed session-cookie protocol to clients that prefer `Authorization: Bearer ...`. It contributes request/response hooks only: it creates no session, endpoint, model, or alternate token type.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/bearer` and use `NewFactory` so the plugin receives the final root secret and request-scoped session-cookie name. Factory order has no schema requirement. Place it according to the hook order you want when other plugins also rewrite `Authorization`, `Cookie`, `Set-Cookie`, or exposed response headers.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/bearer"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            bearer.NewFactory(bearer.Options{RequireSignature: true}),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

## Request behavior

For every registered endpoint, the before-hook reads the combined `Authorization` header. A valid bearer credential is inserted into the request's configured session-cookie slot, so the normal root session resolver handles authentication from that point onward.

```http
GET /api/auth/get-session HTTP/1.1
Host: auth.example.com
Authorization: Bearer <session-token-or-signed-cookie-value>
```

The accepted form is intentionally precise:

- The `Bearer` scheme is ASCII case-insensitive, but it must start at byte zero and be followed by one ASCII space. Leading whitespace or a tab separator is not accepted.
- Surrounding JavaScript whitespace around the token is trimmed.
- With the default `RequireSignature:false`, a token without a dot is treated as the raw session token and signed with the root secret before it is injected as a cookie.
- A dotted value is always treated as an already signed cookie value. It is never re-signed. Percent-encoded dotted values are decoded when possible.
- With `RequireSignature:true`, only a correctly root-signed cookie value is accepted.
- Standard or URL-safe base64 HMAC signatures, with or without padding, are accepted for compatibility.

A valid bearer credential replaces only the session-cookie pair in an existing `Cookie` header and preserves the other cookies. The authorization header itself remains visible to later handlers. A non-bearer scheme, an empty value, a malformed encoding, a raw token when signatures are required, or an invalid signature is silently ignored. It does not erase a valid existing session cookie; the target endpoint then decides whether the remaining request is authenticated.

Do not send multiple `Authorization` header fields. The transport combines repeated fields with comma-space semantics, which can turn them into a different credential value.

## Response behavior

Whenever an endpoint response sets a non-empty root session cookie and the last such cookie is not a `Max-Age=0` deletion, the after-hook copies its decoded value to:

```http
set-auth-token: <signed-session-cookie-value>
Access-Control-Expose-Headers: ..., set-auth-token
```

Existing exposed-header values are preserved. A logout/deletion cookie, an empty session-cookie value, or an unrelated cookie does not produce a new token. If a response writes the session cookie more than once, the last value determines whether a token is exposed.

The header contains the signed cookie value, not necessarily the raw database session token. Feed it back unchanged when `RequireSignature` is enabled:

```http
Authorization: Bearer <value-from-set-auth-token>
```

Typed API-error responses still run the after-hook when they contain a newly issued session cookie. Unknown, non-API handler failures skip normal after-hook response processing.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `RequireSignature` | `false` | Accept raw dotless session tokens and sign them internally; when true, require a root-signed cookie value |
| `Runtime.Secret` | Bound from root | HMAC-SHA-256 signing and verification secret |
| `Runtime.SessionCookieName` / `ResolveSessionCookie` | Bound from root | Static fallback or request-scoped root session-cookie name |

Applications should configure only `RequireSignature` and use `NewFactory`. Standalone `New` requires a non-empty runtime secret and either a valid cookie name or resolver; invalid runtime cookie names fail construction or request processing.

## Direct API and transports

There are no bearer-specific routes. The hooks apply to every normal endpoint reached through `net/http`, direct `fasthttp`, and Fiber. They also run for direct dispatch when `DirectCallInput.Headers` contains `Authorization`; a headerless direct call has nothing to adapt.

HTTP callers send `Authorization: Bearer <token>`; direct callers place the same header in `DirectCallInput.Headers`. A sign-in response may expose `set-auth-token`, so forward or retain that response header when needed.

## Storage and lifecycle

The plugin has no schema and requires no migration. It uses the existing core `session` row and root cookie format. Receiving a bearer credential does not extend, rotate, or revoke a session by itself; those behaviors remain owned by the endpoint and root [session configuration](../core/sessions.md).

There is no bearer replay store. A captured raw session token or signed cookie value remains usable for as long as the underlying session remains valid. Revocation and expiry are therefore the security boundary, including in multi-replica deployments.

The hooks keep no mutable per-request state and are safe for concurrent dispatch. Dynamic cookie-name resolution is request-scoped and follows secure-prefix and custom-cookie configuration from the root runtime.

## Security and troubleshooting

- Treat both `Authorization` and `set-auth-token` as credentials. Redact them in application, reverse-proxy, tracing, error-reporting, and analytics logs.
- Use TLS. A signed cookie value protects integrity, not confidentiality or replay.
- `RequireSignature:true` narrows accepted input to root-signed values; it does not replace session lookup, expiry, revocation, CSRF, CORS, or authorization checks.
- `Access-Control-Expose-Headers` only makes the response header readable to an already permitted browser origin. Configure the host's CORS policy separately.
- If a bearer request is unexpectedly anonymous, check for a leading space, tab separator, a dot in a supposedly raw token, percent-encoding errors, the root secret, and the request-specific session-cookie name.
- If `set-auth-token` is absent, inspect the endpoint's actual `Set-Cookie` response. Deleted, empty, or differently named cookies are intentionally ignored.
- A valid bearer header takes precedence over an existing session cookie by replacing that cookie pair. Avoid sending both unless this precedence is intentional.

See [Sessions](../core/sessions.md), [Security](../core/security.md), [Direct API](../transports/direct-api.md), and the [bearer package reference](../reference/packages/plugins--bearer.md).

**Status:** implemented with signed/unsigned compatibility, request precedence, response exposure, concurrency, and all Go transport coverage.
