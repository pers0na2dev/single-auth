---
title: "One-time token"
description: "Exchange a short-lived, atomically consumed token for an existing native Go session."
---

One-time token creates a short-lived bearer credential that points to an already existing session. Verification atomically consumes that credential, loads the referenced session, returns its user/session pair, and normally issues the root session cookie to the caller.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/onetimetoken` and use `NewFactory` so generation, session lookup/refresh, randomness, clock, record serialization, and atomic verification storage come from the finalized root runtime.

```go
package main

import (
    "log"
    "net/http"
    "os"
    "time"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/onetimetoken"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            onetimetoken.NewFactory(onetimetoken.Options{
                ExpiresIn: onetimetoken.Duration(90 * time.Second),
                Storage: onetimetoken.TokenStorage{Mode: onetimetoken.StoreHashed},
                SetOTTHeaderOnNewSession: true,
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The example selects hashed-at-rest storage and enables automatic `set-ott` issuance for newly created sessions. Both are opt-in; compatibility defaults are plain storage and no response header.

All paths below are relative to the auth `BasePath` (`/api/auth` by default).

## Generate and verify

Generate from a currently authenticated session:

```http
GET /api/auth/one-time-token/generate HTTP/1.1
Host: auth.example.com
Cookie: single-auth.session_token=<signed-session-cookie>
```

```json
{"token":"<opaque-one-time-token>"}
```

Then send the token once, without needing the original session cookie:

```http
POST /api/auth/one-time-token/verify HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Origin: https://app.example.com

{"token":"<opaque-one-time-token>"}
```

```json
{
  "session": {"id":"<session-id>","userId":"<user-id>","expiresAt":"<timestamp>"},
  "user": {"id":"<user-id>","email":"ada@example.com"}
}
```

Unless disabled, verification also refreshes the normal signed session cookie in `Set-Cookie`.

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| GET | `/one-time-token/generate` | No query/body | `{"token":"..."}` | A current session; HTTP route may be disabled while direct use remains available |
| POST | `/one-time-token/verify` | JSON string `token` | Serialized `session` and `user`, plus normal root session cookie unless disabled | Possession of a live unused token that references a live session |

Generation stores `verification.identifier = "one-time-token:" + storedToken` and the underlying session token in `verification.value`. It does not clone or extend the underlying session. The one-time token and referenced session have independent expiry; both must still be valid at verification time.

## Automatic `set-ott` header

With `SetOTTHeaderOnNewSession:true`, the after-hook detects a session newly created by any endpoint, generates an OTT for it, and adds:

```http
set-ott: <one-time-token>
Access-Control-Expose-Headers: ..., set-ott
```

This is useful when a sign-up or sign-in response should immediately hand a native/browser client a single-use exchange credential. The header is absent by default and when the response did not create a session. Existing `Access-Control-Expose-Headers` values are preserved.

Generating and persisting this header token is part of response processing. A generation, hashing, or verification-storage error is returned as an endpoint failure even if earlier session work already succeeded. Reconcile the new session before retrying the entire sign-in operation.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `ExpiresIn` | nil, interpreted as three minutes | Verification-row lifetime; use `onetimetoken.Duration(value)` to preserve an explicit duration, including zero |
| `DisableClientRequest` | `false` | When true, HTTP generation returns `400`; direct `generateOneTimeToken` remains enabled but still needs session context |
| `GenerateToken` | Cryptographic 32-character generator | Receives an isolated session/user snapshot and endpoint context |
| `DisableSetSessionCookie` | `false` | When true, verification returns data without refreshing/writing the root session cookie |
| `Storage.Mode` | `StorePlain` | `StorePlain`, SHA-256 `StoreHashed`, or `StoreCustom` |
| `Storage.CustomHash` | nil | Required only with `StoreCustom`; rejected with plain/hashed modes |
| `SetOTTHeaderOnNewSession` | `false` | Generate and expose `set-ott` after any endpoint creates a session |
| `Runtime` | Bound by `NewFactory` | Adapter/session/verification services, clock, randomness, and serializers for standalone embedding/tests |

The built-in token alphabet is lowercase and uppercase ASCII letters, digits, `-`, and `_`. The generator uses rejection sampling over the root cryptographic random reader. Custom generators must provide enough entropy, must not reuse values, and may be called concurrently.

`StoreHashed` persists unpadded base64url SHA-256 instead of the presented token. `StoreCustom` calls `CustomHash` during both generation and verification; it must be deterministic for the same input and safe for concurrent calls. Prefer a one-way mode so a verification-table read does not reveal live exchange credentials.

## Direct API

There is no separately bound server service. Trusted code can call:

```go
generated, err := auth.API().Call(ctx, "generateOneTimeToken", singleauth.DirectCallInput{
    Method: http.MethodGet,
    Headers: sessionHeaders,
})

verified, err := auth.API().Call(ctx, "verifyOneTimeToken", singleauth.DirectCallInput{
    Method: http.MethodPost,
    Body:   map[string]any{"token": token},
})
```

`DisableClientRequest` checks `ctx.IsDirect()` and therefore does not disable the direct generation operation. It does not waive the current-session requirement: supply a valid session cookie/header or other root-supported session context.

Direct verification follows the same atomic consumption and session checks. When session-cookie refresh is enabled, the returned direct response contains `Set-Cookie`; applying it to a later HTTP client remains the caller's responsibility.

## Errors and consumption order

| Status | Code | Message / cause |
| --- | --- | --- |
| 401 | `UNAUTHORIZED` | Generation has no current session |
| 400 | `BAD_REQUEST` | `Client requests are disabled` on HTTP generation when configured |
| 400 | `VALIDATION_ERROR` | Invalid/oversized JSON, missing `token`, or non-string token |
| 400 | `BAD_REQUEST` | `Invalid token` when no live unused verification can be consumed |
| 400 | `BAD_REQUEST` | `Session not found` when the consumed row lacks a session value or the referenced session is gone |
| 400 | `BAD_REQUEST` | `Session expired` when the referenced session is expired |
| 500 | `INTERNAL_SERVER_ERROR` | Non-API runtime, hashing, randomness, adapter, or refresh failure |

The verification row is consumed before session lookup and before the underlying session-expiry result. A missing or expired referenced session therefore still burns the OTT. The compatibility order also refreshes/writes the session cookie before checking `session.expiresAt`; an expired-session error can consequently include `Set-Cookie`. Clients must treat the error as authoritative and discard that cookie rather than treating its presence as success.

An `ExpiresIn` of zero stores `expiresAt` at the current root clock and gives the token no positive validity window; an identical frozen clock can still observe equality as not-yet-before expiry. Expired verification rows are reported as `Invalid token`, not a separate expiry code.

## Storage, replay, and concurrency

The plugin adds no model and requires no plugin-specific migration. It uses the core `verification` and `session` models. Ensure the core schema exists and the adapter implements the root verification primitives.

Verification is single-use. The factory delegates to the root atomic `ConsumeVerification`; standalone fallback code uses a transaction and `ConsumeOne`, or adapter-level `ConsumeOne` when transactions are explicitly unsupported. Concurrent verification of one token permits one success; losers receive `Invalid token`.

With a transaction-capable fallback adapter, the newest matching verification row is consumed and older duplicates for the same identifier are deleted. Custom `GenerateToken` implementations must avoid collisions because equal presented/stored tokens share one identifier and can make generations interfere.

Atomicity across service replicas depends on the backing adapter's `ConsumeOne`/verification implementation. A process-local Go lock is not used as a substitute. See [Transactions](../storage/transactions.md) and [Multi-replica sessions](../guides/multi-replica-sessions.md).

## Security and troubleshooting

- Treat OTTs and `set-ott` as bearer credentials. Use TLS and redact URL, body, header, proxy, tracing, and analytics logs.
- Keep the lifetime short and use hashed/custom one-way storage. Plain storage is compatibility behavior, not the safest production default.
- Do not send the token in a query string. The verify contract expects a JSON body.
- `Invalid token` can mean wrong, expired, already consumed, concurrently consumed, or a storage-mode/hash mismatch.
- `Session not found` means the OTT was valid and is now consumed, but its underlying session was removed or the verification row was malformed. Generate from a new live session.
- If `set-ott` is missing, verify `SetOTTHeaderOnNewSession`, that the endpoint actually created a new session, CORS exposure, and whether response-hook storage failed.
- If verification returns success but a browser remains signed out, check `DisableSetSessionCookie`, cookie domain/secure/same-site policy, and whether the caller or browser applied `Set-Cookie`.
- Keep `GenerateToken` and `CustomHash` deterministic where required, concurrency-safe, and free of session/token logging.

See [Sessions](../core/sessions.md), [Direct API](../transports/direct-api.md), [Security](../core/security.md), and the [one-time-token package reference](../reference/packages/plugins--onetimetoken.md).

**Status:** implemented with atomic replay prevention, storage modes, header issuance, direct API, concurrency, and all Go transport coverage.
