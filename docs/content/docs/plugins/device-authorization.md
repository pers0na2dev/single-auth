---
title: "Device authorization"
description: "Implement OAuth 2.0 device authorization, user-code verification, polling, approval, denial, expiry, and replay protection."
---

Implement the RFC 8628 device-code flow for input-constrained devices.

## Installation and ordering

Import `github.com/pers0na2dev/single-auth/plugins/deviceauthorization`. The plugin has no dependency on another plugin, but it must be registered before the final storage schema is initialized. `ValidateClient` is the application trust boundary: without it, any caller can request a device code for any non-empty `client_id`.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/deviceauthorization"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            deviceauthorization.NewFactory(deviceauthorization.Options{
                ValidateClient: func(_ context.Context, clientID string) (bool, error) {
                    return clientID == "television-app", nil
                },
                VerificationURI: "https://account.example.com/device",
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

## How the flow works

1. The device calls `POST /device/code` with its client ID and optional scope.
2. The server returns a device code, a human-readable user code, and verification URLs.
3. A user opens the verification URL while signed in. `GET /device` validates and claims the user code for that session.
4. The user approves or denies the claimed code.
5. The device polls `POST /device/token`. Approval atomically consumes the code and creates a normal single-auth session token.

All paths below are relative to `Options.BasePath`, which defaults to `/api/auth`.

## Endpoints

| Method | Path | Input | Result and authority |
| --- | --- | --- | --- |
| POST | `/device/code` | `client_id`, optional `scope`, optional trusted `user_id` | Validated client; returns codes, verification URLs, expiry, and polling interval. |
| POST | `/device/token` | device grant type, `device_code`, `client_id` | Public polling endpoint; returns a bearer session only after approval. |
| GET | `/device` | Query `user_code` | Returns `{user_code,status}` and, when a session is present, claims a pending code for that user. |
| POST | `/device/approve` | `userCode` | Requires a signed-in user who previously claimed the code; returns `{success:true}`. |
| POST | `/device/deny` | `userCode` | Same authority as approval; returns `{success:true}`. |

### Request a code

```http
POST /api/auth/device/code HTTP/1.1
Content-Type: application/json

{
  "client_id": "television-app",
  "scope": "profile offline_access"
}
```

```json
{
  "device_code": "opaque-device-code",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://account.example.com/device",
  "verification_uri_complete": "https://account.example.com/device?user_code=ABCD-EFGH",
  "expires_in": 1800,
  "interval": 5
}
```

`user_id` is supported for trusted pre-binding, but ordinary devices should omit it and let the signed-in verification request claim the code.

### Poll for a token

```http
POST /api/auth/device/token HTTP/1.1
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "opaque-device-code",
  "client_id": "television-app"
}
```

Before approval the endpoint returns an OAuth error body:

```json
{
  "error": "authorization_pending",
  "error_description": "Authorization pending"
}
```

After approval it returns `access_token`, `token_type: "Bearer"`, `expires_in`, and the originally requested `scope`. The access token is a regular single-auth session token, not a JWT.

## Errors and polling behavior

| OAuth error | Meaning |
| --- | --- |
| `invalid_client` / `invalid_grant` | Client validation failed, the client does not own the code, or the code is invalid. |
| `authorization_pending` | The user has not approved or denied the request. |
| `slow_down` | The device polled before the stored interval elapsed. |
| `access_denied` | The user denied the request; the record is removed. |
| `expired_token` | The device or user code expired. |
| `invalid_request` | The user code is invalid, already processed, or was not claimed by the current session. |

Protocol endpoints use `{error,error_description}`. Construction/validation errors and trusted direct calls retain typed `contract.APIError` values.

## Options and defaults

Zero lifetimes and lengths select the native 1.6.26 defaults.

| Option | Default | Purpose |
| --- | --- | --- |
| `ExpiresIn` | 30 minutes | Device and user-code lifetime. |
| `Interval` | 5 seconds | Minimum polling interval. |
| `DeviceCodeLength` | 40 | Opaque device-code length. |
| `UserCodeLength` | 8 | Human-readable code length before display formatting. |
| `VerificationURI` | Resolved `BaseURL + BasePath + /device` | Verification page advertised to the device. |
| `GenerateDeviceCode` / `GenerateUserCode` | Cryptographic random generators | Custom code generation. |
| `ValidateClient` | No callback | Client allow-list or registry lookup. |
| `OnDeviceAuthRequest` | No callback | Audit/policy hook after client validation and before persistence. |

Callbacks may run concurrently and must be deterministic and concurrency-safe. A custom generator must provide enough entropy and avoid collisions.

## Schema and migrations

The plugin adds one `deviceCode` model with `deviceCode`, `userCode`, optional `userId`, `expiresAt`, `status`, optional `lastPolledAt`, `pollingInterval`, optional `clientId`, and optional `scope`. The frozen schema deliberately does not add a foreign-key relation for `userId`.

Register the factory before constructing the adapter, then apply the merged schema. With a root SQL constructor, run `auth.RunMigrationsContext(ctx)`; otherwise merge `deviceauthorization.Schema()` into the adapter schema before initialization. See [Migrations](../storage/migrations.md) and [Schemas](../storage/schemas.md).

## Direct API

Trusted server code can also call the registered names through `auth.API().Call`. Direct dispatch skips HTTP rate limiting and origin checks, so do not proxy it as an unprotected device endpoint.

## Security, replay, and concurrency

- Approval and denial require the code to have been claimed by the same signed-in user.
- Token redemption uses an atomic consume operation; concurrent successful polls can issue at most one session.
- A denied or expired code is removed when observed by the token endpoint.
- Poll timing is persisted, so the `slow_down` decision is shared by instances using the same primary database.
- Display the client identity and requested scope before approval; never trust values supplied only by the device UI.
- Keep codes out of logs and analytics, and use HTTPS for the verification and polling endpoints.

## Troubleshooting

- `invalid_client`: verify `ValidateClient` accepts the exact `client_id` on both code issuance and token polling.
- `DEVICE_CODE_NOT_CLAIMED`: call `GET /device?user_code=...` while authenticated before approving or denying.
- Repeated `slow_down`: wait at least the returned `interval` after every poll, including errors.
- Approval succeeds but token redemption fails: confirm all instances share the same primary storage and session configuration.

## Related pages

- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Storage schemas](../storage/schemas.md)
- [Go package reference](../reference/packages/plugins--deviceauthorization.md)

**Status:** implemented across net/http, fasthttp, Fiber, and direct dispatch.
