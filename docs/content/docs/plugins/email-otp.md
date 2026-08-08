---
title: "Email OTP"
description: "Send and verify single-use email codes for sign-in, email verification, password reset, and email changes."
---

Email OTP adds purpose-bound codes for passwordless sign-in, email verification, password reset, and authenticated email changes. The implementation uses the root user, account, session, and verification services, so the same behavior is available through `net/http`, fasthttp, Fiber, and the direct API.

## Install and configure

Register `emailotp.NewFactory` before constructing the adapter. `SendVerificationOTP` is required. The callback receives the plain code; delivery remains application-owned.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/engine"
    "github.com/pers0na2dev/single-auth/plugins/emailotp"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "https://auth.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{
            Enabled: true,
        },
        TrustedOrigins: []string{"https://app.example.com"},
        PluginFactories: []singleauth.PluginFactory{
            emailotp.NewFactory(emailotp.Options{
                SendVerificationOTP: func(
                    ctx context.Context,
                    message emailotp.OTPMessage,
                    endpoint *engine.Context,
                ) error {
                    return mailer.EnqueueOTP(ctx, message.Email, string(message.Type), message.OTP)
                },
                Storage: emailotp.OTPStorage{Mode: emailotp.StoreHashed},
                ChangeEmail: emailotp.ChangeEmailOptions{
                    Enabled:            true,
                    VerifyCurrentEmail: true,
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

The example's `mailer` is application code. Finish a durable enqueue before returning; do not detach request-context work that can disappear after the handler completes, and never log production OTPs.

When `SendVerificationOnSignUp` is enabled, place the factory after any plugin whose successful sign-up response must be observed by the email-OTP after-hook. `OverrideDefaultEmailVerification` instead installs OTP delivery into the root email-verification flow.

## HTTP routes

All bodies are JSON. Emails are normalized before lookup. Successful command-only routes return `{"success":true}`.

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/email-otp/send-verification-otp` | `email`, `type` | `success` | Public form request; `type` is `sign-in`, `email-verification`, or `forget-password` |
| POST | `/email-otp/check-verification-otp` | `email`, `type`, `otp` | `success` | Possession of the matching code; validates without consuming it |
| POST | `/email-otp/verify-email` | `email`, `otp` | `status`, nullable `token`, `user` | Matching `email-verification` code |
| POST | `/sign-in/email-otp` | `email`, `otp`, optional `name`, `image`, and declared user fields | `token`, `user` | Matching `sign-in` code |
| POST | `/email-otp/request-password-reset` | `email` | `success` | Public, enumeration-resistant request |
| POST | `/forget-password/email-otp` | `email` | `success` | Deprecated alias of the preceding route |
| POST | `/email-otp/reset-password` | `email`, `otp`, `password` | `success` | Matching `forget-password` code |
| POST | `/email-otp/request-email-change` | `newEmail`, optional current-email `otp` | `success` | Fresh authoritative session; feature must be enabled |
| POST | `/email-otp/change-email` | `newEmail`, `otp` | `success` | Fresh authoritative session and matching `change-email` code |

`change-email` is deliberately rejected by the public send route. It is generated only after `request-email-change` has authenticated the current user and bound the code to both the current and new addresses.

### Sign in with a code

Request a code:

```http
POST /api/auth/email-otp/send-verification-otp
Content-Type: application/json
Origin: https://app.example.com

{"email":"ada@example.com","type":"sign-in"}
```

Then consume it:

```http
POST /api/auth/sign-in/email-otp
Content-Type: application/json

{"email":"ada@example.com","otp":"431902","name":"Ada"}
```

```json
{
  "token": "session-token",
  "user": {
    "id": "user-id",
    "email": "ada@example.com",
    "emailVerified": true,
    "name": "Ada"
  }
}
```

When the email is unknown, sign-in creates a verified user unless `DisableSignUp` is true. Extra fields are accepted only when they are declared as writable user fields in the root schema.

### Verify an address

`verify-email` consumes the code before running verification hooks. With the factory, `AutoSignInAfterVerification` follows the root `EmailVerification.AutoSignInAfterVerification` setting. If it is false, `token` is JSON `null`; an existing session for the same user is refreshed instead.

### Reset a password

`request-password-reset` returns the same success body for known and unknown addresses and sends only for a known user. `reset-password` applies the root password length and hashing chain, invokes the root password-reset callback, marks the email verified, and follows `EmailAndPassword.RevokeSessionsOnReset`.

### Change an email

With `ChangeEmail.Enabled`, use this sequence:

1. If `VerifyCurrentEmail` is true, send an `email-verification` code to the current address.
2. Call `request-email-change` with `newEmail` and that current-address `otp`.
3. Deliver the resulting `change-email` code to the new address.
4. Call `change-email` with the new address and new-address code.

The request route returns success without sending when the target address is already used. The final route rechecks uniqueness, runs the root before/after email-verification hooks, updates the user, and refreshes the current session.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `OTPLength` | `6` | Positive number of decimal digits generated by the built-in generator |
| `ExpiresIn` | 5 minutes | Lifetime of a newly generated code |
| `GenerateOTP` | Cryptographic decimal generator | Custom purpose-aware generator |
| `Storage.Mode` | `StorePlain` | Plain, SHA-256 hashed, or root-secret encrypted verification value |
| `Storage.CustomHash` | none | One-way custom transform; cannot be combined with encryption or a non-plain mode |
| `Storage.CustomEncrypt` / `CustomDecrypt` | none | Both are required together and cannot be combined with hashing or a non-plain mode |
| `ResendStrategy` | `ResendRotate` | Rotate every send or reuse a live recoverable code and extend its expiry |
| `AllowedAttempts` | `3` | Stored failed checks before the next attempt returns `TOO_MANY_ATTEMPTS` |
| `DisableSignUp` | `false` | Prevent unknown-email OTP sign-in from creating a user |
| `SendVerificationOnSignUp` | `false` | Send an email-verification OTP after successful sign-up routes |
| `OverrideDefaultEmailVerification` | `false` | Replace the root default verification sender with this OTP flow |
| `ChangeEmail.Enabled` | `false` | Enable both email-change routes |
| `ChangeEmail.VerifyCurrentEmail` | `false` | Require a valid current-address verification code before sending to the new address |
| `RateLimit.Window` / `Max` | 60 seconds / 3 | Plugin HTTP rule applied independently to each public route |

`ResendReuse` can recover plaintext, encrypted, or custom-encrypted values. Hashed and custom-hashed values cannot be recovered, so a resend generates a new code. An expired or attempts-exhausted value is also rotated.

With `NewFactory`, password bounds, password hashing, reset callbacks, reset-time session revocation, automatic sign-in after verification, and the form CSRF/origin validator are inherited from the root configuration. Prefer the factory over `New`; `New` is for explicit-runtime embedding and tests.

## Errors

The most important stable codes are:

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Missing, mistyped, or unsupported input |
| 400 | `INVALID_EMAIL` | Invalid email syntax |
| 400 | `INVALID_OTP` | Wrong, already consumed, replayed, or otherwise non-live matching code |
| 400 | `OTP_EXPIRED` | Matching record exists but is expired |
| 403 | `TOO_MANY_ATTEMPTS` | Failure budget was already exhausted |
| 400 | `USER_NOT_FOUND` | A valid check/reset/verification code has no matching user |
| 401 | `UNAUTHORIZED` | A sensitive email-change route has no authoritative session |
| 400 | `BAD_REQUEST` | Disabled email change, invalid purpose, same address, or an already-used target |
| 400 | `PASSWORD_TOO_SHORT` / `PASSWORD_TOO_LONG` | New password violates root bounds measured in UTF-16 code units |

The send, password-reset request, and email-change request flows intentionally hide account existence. Do not replace their generic success responses with provider-specific details.

## Direct API

There is no separately bound server service. Trusted Go code can call the registered names through `auth.API().Call`: `sendVerificationOTP`, `checkVerificationOTP`, `verifyEmailOTP`, `signInEmailOTP`, `requestPasswordResetEmailOTP`, `forgetPasswordEmailOTP`, `resetPasswordEmailOTP`, `requestEmailChangeEmailOTP`, and `changeEmailEmailOTP`.

Two additional operations, `createVerificationOTP` and `getVerificationOTP`, are marked server-only and have no HTTP route. The former returns the newly created plain code; the latter returns a live recoverable code and fails for hashed storage. Restrict both to trusted in-process code.

Direct calls still run endpoint middleware and hooks, but they bypass outer HTTP rate limiting. Supply realistic request headers for origin- or session-sensitive calls and apply independent abuse controls.

## Storage, replay, and concurrency

The plugin adds no model. It uses the core `verification`, `user`, `account`, and `session` models, so no plugin-specific migration is required once the core schema exists.

Verification identifiers include both purpose and normalized email; change-email identifiers also include the current and new addresses. Consuming endpoints use the root atomic verification primitive plus a keyed process lock, and concurrent verification of one code permits one success. Wrong-code attempt increments are serialized. A code is consumed before later user, hook, password, or session work, so a downstream failure does not make the code reusable.

`check-verification-otp` is intentionally different: a correct check does not consume the code, while an incorrect check increments attempts. Use a consuming endpoint for the final state transition.

For multi-process deployments, use a storage backend whose verification consumption is atomic across replicas. Process-local locks alone do not coordinate separate service instances.

## Troubleshooting and security

- `INVALID_OTP` immediately after resend usually means `ResendRotate` issued a replacement code. Deliver only the newest message.
- `ResendReuse` still rotates under hashed storage because the server cannot recover the prior plaintext code.
- A send request rejected with `INVALID_ORIGIN`, `MISSING_OR_NULL_ORIGIN`, or `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED` failed the root form-CSRF policy. Configure root `TrustedOrigins` and preserve browser `Origin` headers.
- If verification succeeds but session creation fails, the code remains consumed. Fix the session/storage failure, then issue a new code.
- Store codes hashed when recovery is unnecessary, or encrypted when resend reuse is required. Plain storage is compatibility behavior, not the safest production choice.
- Delivery callbacks receive secrets and a live endpoint context. Keep logs, traces, queues, and provider metadata free of OTP values.

## Related pages

- [Direct API](../transports/direct-api.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Storage transactions](../storage/transactions.md)
- [Email OTP package reference](../reference/packages/plugins--emailotp.md)

**Status:** implemented with replay, concurrency, transport, and storage-backend coverage.
