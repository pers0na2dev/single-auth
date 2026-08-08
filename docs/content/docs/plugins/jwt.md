---
title: "JWT and JWKS"
description: "Issue and verify JWTs, publish JWKS, rotate signing keys, configure claims, and understand storage and cache behavior."
---

Issue asymmetric JWTs, publish rotating public keys, and validate tokens on the server.

## Installation and ordering

Import `github.com/pers0na2dev/single-auth/plugins/jwt`. Register the factory before `oauthprovider` when that plugin uses JWT signing. The default key pair is Ed25519/EdDSA, the default JWT lifetime is 15 minutes, and private keys are encrypted with the root secret before persistence.

```go
package main

import (
    "log"
    "net/http"
    "os"
    "time"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/jwt"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            jwt.NewFactory(jwt.Options{
                JWKS: jwt.JWKSOptions{
                    RotationInterval: jwt.Duration(30 * 24 * time.Hour),
                    GracePeriod:      jwt.Duration(7 * 24 * time.Hour),
                },
                Token: jwt.TokenOptions{
                    Audience:       "https://api.example.com",
                    ExpirationTime: "15m",
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

## Usage

### Retrieve a session JWT

`GET /token` requires a valid single-auth session cookie. It returns a signed token containing the configured subject, issuer, audience, expiry, and payload.

```http
GET /api/auth/token HTTP/1.1
Cookie: better-auth.session_token=token.signature
```

```json
{"token":"eyJhbGciOiJFZERTQSIsImtpZCI6Ii4uLiJ9..."}
```

Unless `DisableSettingJWTHeader` is true, successful `/get-session` responses also include the same credential in `set-auth-jwt` and expose that header through CORS. Treat it as a bearer credential and exclude it from proxy and application logs.

### Publish and consume JWKS

`GET /jwks` is public by default and returns only active or grace-period public keys:

```json
{
  "keys": [
    {"kid":"key-id","kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"..."}
  ]
}
```

Change the path with `JWKS.Path`. When `JWKS.RemoteURL` is configured, the local JWKS route returns not found because verification and custom signing are expected to use the remote key service.

## Endpoints and server APIs

| Method | Path | Input | Result and authority |
| --- | --- | --- | --- |
| GET | `/jwks` by default | None | Public `{keys:[...]}` unless remote JWKS mode is active. |
| GET | `/token` | Session cookie/header | Authenticated `{token}`. |
| no HTTP route | `signJWT` | `payload`, optional trusted override options | Server-only `{token}`. |
| no HTTP route | `verifyJWT` | `token`, optional issuer override | Server-only `{payload}`; an invalid token produces an empty payload. |

The server-only operations are available to composed plugins through the endpoint registry and to trusted Go code through `auth.API().Call`. They are intentionally unreachable over HTTP. Exported lower-level helpers include `SignJWT`, `VerifyJWT`, `GetJWTToken`, `CreateJWK`, `GenerateExportedKeyPair`, `VerifyAccessToken`, and `ToExpJWT`; use them only when you can supply the same runtime and claim policy as the installed factory.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `JWKS.KeyPair` | EdDSA with Ed25519 | Supports EdDSA, ES256, ES512, PS256, and RS256. RSA modulus defaults to 2048 bits. |
| `JWKS.Path` | `/jwks` | Must be absolute, non-empty, and contain no `..`. |
| `JWKS.RemoteURL` | Empty | Uses local persisted keys; remote mode requires an explicit key algorithm and custom signer. |
| `JWKS.RotationInterval` | No automatic expiry | When set, a new key is created after the latest key expires. |
| `JWKS.GracePeriod` | 30 days | Expired public keys remain published for verification during this period. |
| `JWKS.DisablePrivateKeyEncryption` | `false` | Persist private JWK JSON without root-secret encryption only when the storage boundary already provides equivalent protection. |
| `Token.Issuer` | Resolved auth origin | Explicit empty string is distinct from omission. |
| `Token.Audience` | Resolved auth origin | Accepts a string or `[]string`. |
| `Token.ExpirationTime` | `15m` | Accepts seconds, `time.Time`, or a Better Auth-style duration string. |
| `Token.DefinePayload` / `GetSubject` | Built-in user payload / user ID | Customize claims and subject. |
| `Token.Sign` | Local private key | Remote signing callback; requires `JWKS.RemoteURL`. |
| `DisableSettingJWTHeader` | `false` | Suppresses `set-auth-jwt` on `/get-session`. |

Custom callbacks can run concurrently. Do not mutate option-owned maps or shared payloads after construction.

## Claims and verification

Local signing always adds protected `alg` and `kid` values and applies the configured `iss`, `aud`, `sub`, `iat`, and `exp`. `DefinePayload` can add application claims; avoid putting secrets or rapidly changing authorization state into a token whose lifetime outlasts that state.

`VerifyJWT` checks the signature and configured issuer/audience/expiry policy. `VerifyAccessToken` additionally supports explicit verification dispositions for JWT and opaque OAuth-provider access tokens. Callers must still authorize the returned subject, scopes, and application claims.

## Schema and migrations

The plugin adds a `jwks` model with `publicKey`, encrypted `privateKey`, `createdAt`, and optional `expiresAt`. Register the factory before adapter initialization so this model is part of the merged schema. With root SQL constructors, run `auth.RunMigrationsContext(ctx)`; otherwise merge `jwt.Schema()` before creating the adapter.

Key IDs come from the persisted record ID. All application instances must share the same primary storage and root secret rotation set or they may publish different keys or fail to decrypt an existing private key.

See [Migrations](../storage/migrations.md), [Schemas](../storage/schemas.md), and [Secret rotation](../core/security.md).

## Rotation, replay, and concurrency

- Signing selects the latest non-expired key and creates a new one when no usable key exists.
- Public keys remain in JWKS until `expiresAt + GracePeriod`; make the grace period at least as long as the longest token lifetime plus clock skew.
- The adapter must enforce normal record uniqueness and transaction behavior. Multiple instances may race to create an initial/rotated key, so use shared durable storage and monitor duplicate-key failures.
- JWTs are bearer credentials and are not individually revocable. Use short lifetimes, narrow audiences, and server-side authorization checks for sensitive operations.
- Changing issuer, audience, algorithm, subject logic, or the root encryption secret is a compatibility/security migration, not only a configuration edit.

## Errors and troubleshooting

HTTP route failures use normal single-auth `{code,message}` errors. Common setup failures are explicit at construction:

- `JWKS.Path` must start with `/` and cannot contain traversal.
- Remote signing requires `JWKS.RemoteURL` and an explicit key algorithm.
- Local signing requires a primary adapter or a complete custom JWK adapter.
- Private-key encryption requires the root secret or explicit encrypt/decrypt callbacks.
- `Token.Audience` must be a string or string slice.

If verification starts failing after rotation, inspect the published `kid`, confirm old public keys are still inside the grace period, and verify every instance shares storage, issuer, audience, clock, and the decryptable secret set.

## Related pages

- [OAuth provider](./oauth-provider.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Storage migrations](../storage/migrations.md)
- [Go package reference](../reference/packages/plugins--jwt.md)

**Status:** implemented with local/remote signing, key rotation, and native verification.
