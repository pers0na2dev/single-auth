---
title: "Magic link"
description: "Deliver short-lived, single-use sign-in links with trusted redirects and atomic verification."
---

Magic link authenticates an email owner through a short-lived link delivered by your application. Verification is single-use, can create a user when permitted, marks an existing email as verified, and issues the normal root session cookies.

## Install and configure

Register `magiclink.NewFactory` with the root runtime. `SendMagicLink` is required and is awaited by the endpoint; complete a durable send or queue write before returning.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/engine"
    "github.com/pers0na2dev/single-auth/plugins/magiclink"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "https://auth.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{
            "https://app.example.com",
            "https://admin.example.com",
        },
        PluginFactories: []singleauth.PluginFactory{
            magiclink.NewFactory(magiclink.Options{
                SendMagicLink: func(
                    ctx context.Context,
                    message magiclink.MagicLinkMessage,
                    endpoint *engine.Context,
                ) error {
                    return mailer.EnqueueMagicLink(ctx, message.Email, message.URL)
                },
                Storage: magiclink.TokenStorage{Mode: magiclink.StoreHashed},
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

`message.URL` already contains the token and validated redirect parameters. Treat the URL and `message.Token` as credentials: exclude both from logs, traces, analytics, and provider metadata.

## HTTP routes

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/sign-in/magic-link` | JSON `email`; optional `name`, `callbackURL`, `newUserCallbackURL`, `errorCallbackURL`, `metadata` | `{"status":true}` | Public form request with root CSRF/origin and redirect checks |
| GET | `/magic-link/verify` | Query `token`; optional callback URLs | JSON session or `302` redirect | Possession of a live token; redirect URLs are checked again |

The send route passes `metadata` to `MagicLinkMessage` but does not store it in the verification row or return it to the verifier. Use it only for delivery-provider context that contains no secret data.

### Send a link

```http
POST /api/auth/sign-in/magic-link
Content-Type: application/json
Origin: https://app.example.com

{
  "email": "ada@example.com",
  "name": "Ada Lovelace",
  "callbackURL": "https://app.example.com/dashboard",
  "newUserCallbackURL": "https://app.example.com/welcome",
  "errorCallbackURL": "https://app.example.com/sign-in",
  "metadata": {"campaign": "account-login"}
}
```

The generated delivery URL includes `callbackURL=/` when no callback was supplied. Following a delivered link therefore normally returns a redirect.

### Verify without a redirect

Call verify without a `callbackURL` query parameter to receive JSON instead of a redirect:

```http
GET /api/auth/magic-link/verify?token=plain-delivered-token
```

```json
{
  "token": "session-token",
  "user": {
    "id": "user-id",
    "email": "ada@example.com",
    "emailVerified": true
  },
  "session": {
    "token": "session-token",
    "userId": "user-id"
  }
}
```

With a callback parameter, an existing user is redirected to `callbackURL`; a newly created user is redirected to `newUserCallbackURL`, falling back to `callbackURL`. Invalid and expired tokens redirect to `errorCallbackURL`, falling back to `callbackURL` and then the root origin.

Error redirects preserve existing query values and append an `error` parameter. Expected values include `INVALID_TOKEN`, `new_user_signup_disabled`, `failed_to_create_user`, and `failed_to_create_session`.

## Verification behavior

For an unknown email, verification creates a verified user unless `DisableSignUp` is true. `name` from the send request becomes the new user's name. The send route remains enumeration-resistant when signup is disabled: it still returns success and calls the delivery callback; the link is rejected only at verification time.

For an existing unverified user, successful proof revokes unproven credential access and sessions before marking the email verified. It then creates a normal root session and emits the configured cookies.

The verification row is consumed before user creation, email adoption, and session creation. Any failure after consumption burns the link. Ask the user to request a new link after correcting the downstream failure.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `ExpiresIn` | 5 minutes | Verification lifetime |
| `SendMagicLink` | required | Awaited delivery callback receiving email, URL, token, metadata, and endpoint context |
| `DisableSignUp` | `false` | Reject unknown users during verification without changing send-time response |
| `RateLimit.Window` / `Max` | 60 seconds / 5 | HTTP rule covering send and verify paths |
| `GenerateToken` | Cryptographic 32-character token | Custom token generator receiving context and email |
| `Storage.Mode` | `StorePlain` | Store the token identifier as plaintext or SHA-256 base64url |
| `Storage.CustomHash` | none | Custom one-way token transform; only valid with plain mode |
| `AllowedAttempts` | ignored | Deprecated compatibility pointer; every token is always single-use |

Setting deprecated `AllowedAttempts` to a value other than `1` emits a warning but never permits replay. Remove the option instead of using it as a retry policy.

`NewFactory` derives the adapter, clock, random source, base URL/base path, trusted origins, form validation, redirects, user/session serialization, and secondary-storage-aware invalidation from the root runtime. Prefer it over the explicit-runtime `New` constructor.

## Redirect and CSRF policy

The send middleware validates all three callback fields before creating or delivering a link. The verify middleware validates them again before consuming the token. Relative paths such as `/dashboard` are accepted; protocol-relative paths, backslashes, encoded path separators, and untrusted absolute origins are rejected.

The root base origin is trusted automatically, and root `TrustedOrigins` and dynamic trusted-origin resolution are honored. Do not add a wildcard broader than the applications that are allowed to receive a session-bearing redirect.

Browser-like send requests must satisfy the root form-CSRF policy. Depending on headers, failures use `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`, `MISSING_OR_NULL_ORIGIN`, or `INVALID_ORIGIN`. Validation and invalid-email failures are JSON API errors; token-flow failures described above are redirects.

## Storage, migrations, replay, and concurrency

The plugin adds no table or field. It uses the core `verification`, `user`, and `session` models, so a database with the core schema needs no magic-link migration.

Plain mode stores the link token as `verification.identifier`. Hashed mode stores SHA-256 base64url instead; a custom hash can implement an application-specific one-way identifier. The verification value contains the email and optional name, and expiry is stored in the core row.

Token consumption is atomic. Concurrent verification of the same link produces one session and one `INVALID_TOKEN` redirect. Replay, expiry, disabled signup, and failed session creation all leave the token unusable. Issuing another random link does not rely on or extend the earlier token; each token has its own verification record.

Cross-process correctness depends on the root storage backend's atomic `ConsumeVerification` implementation. The plugin's keyed lock only coordinates requests inside one process.

## Direct API

There is no bound server service. Trusted code can call `signInMagicLink` and `magicLinkVerify` through `auth.API().Call`. Direct verification must provide the query token and, for dynamic-base-URL deployments, a scheme/host or configured fallback.

Direct calls run endpoint middleware but bypass outer HTTP rate limiting. Preserve origin and redirect validation inputs and add independent abuse controls before exposing a direct call through another transport.

## Troubleshooting

- An immediate `INVALID_TOKEN` usually means the link was already consumed, expired, or was transformed with a different hashing configuration.
- A `failed_to_create_session` redirect means the email proof succeeded but session issuance failed; the original token cannot be retried.
- A callback validation error occurs before delivery or token consumption. Compare the exact origin with root `TrustedOrigins`, including scheme and port.
- If an HTTP caller unexpectedly receives the destination HTML, disable automatic redirects for the verification request.
- Custom token generators must return high-entropy, unique values. Reusing a token can collide with verification identifiers and invalidate isolation assumptions.

## Related pages

- [Direct API](../transports/direct-api.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Storage transactions](../storage/transactions.md)
- [Magic-link package reference](../reference/packages/plugins--magiclink.md)

**Status:** implemented with redirect, replay, concurrency, transport, and storage-backend coverage.
