---
title: "Phone number"
description: "Add phone/password sign-in, OTP verification, optional signup, phone updates, and password reset."
---

Phone number extends users with a unique phone identity and provides password sign-in plus OTP verification and reset flows. The root factory binds password policy, sessions, verification storage, callbacks, and secondary-storage invalidation.

## Install and configure

Register the factory before adapter construction so its user fields are included in the final schema.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "strings"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/engine"
    "github.com/pers0na2dev/single-auth/plugins/phonenumber"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "https://auth.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            phonenumber.NewFactory(phonenumber.Options{
                RequireVerification: true,
                SendOTP: func(
                    ctx context.Context,
                    message phonenumber.OTPMessage,
                    endpoint *engine.Context,
                ) error {
                    return sms.SendCode(ctx, message.PhoneNumber, message.Code)
                },
                SendPasswordResetOTP: func(
                    ctx context.Context,
                    message phonenumber.OTPMessage,
                    endpoint *engine.Context,
                ) error {
                    return sms.SendResetCode(ctx, message.PhoneNumber, message.Code)
                },
                PhoneNumberValidator: func(value string) (bool, error) {
                    return strings.HasPrefix(value, "+") && len(value) >= 8, nil
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

The `sms` object is application-owned. Authenticate provider callbacks, enqueue durably, and never write codes to production logs.

## HTTP routes

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/sign-in/phone-number` | `phoneNumber`, `password`, optional `rememberMe` | `token`, `user` | Public credential request |
| POST | `/phone-number/send-otp` | `phoneNumber` | `{"message":"code sent"}` | Public; requires `SendOTP` |
| POST | `/phone-number/verify` | `phoneNumber`, `code`, optional `disableSession`, `updatePhoneNumber`, declared user fields | `status`, nullable `token`, `user` | Matching OTP; session required only for phone update |
| POST | `/phone-number/request-password-reset` | `phoneNumber` | `{"status":true}` | Public, enumeration-resistant request |
| POST | `/phone-number/reset-password` | `phoneNumber`, `otp`, `newPassword` | `{"status":true}` | Matching reset OTP |

### Verification and signup

```http
POST /api/auth/phone-number/verify
Content-Type: application/json

{"phoneNumber":"+15551234567","code":"482901","disableSession":false}
```

```json
{
  "status": true,
  "token": "session-token",
  "user": {
    "id": "user-id",
    "phoneNumber": "+15551234567",
    "phoneNumberVerified": true
  }
}
```

For an existing user, verification marks `phoneNumberVerified` true. For an unknown number, it creates no user by default. Set `SignUpOnVerification` and provide `GetTempEmail`; optional `GetTempName` and declared extra user fields are used during creation. `disableSession:true` completes verification or signup but returns `token:null` and emits no new session.

Set `updatePhoneNumber:true` to assign the verified number to the currently authenticated user. That branch requires a valid session, rejects a number already used by any user, invokes `CallbackOnVerification`, and returns the current session token.

### Password sign-in and reset

When `RequireVerification` is true, password sign-in for an unverified phone generates and delivers a code, then returns `PHONE_NUMBER_NOT_VERIFIED`. A successful password check issues the normal root session; `rememberMe:false` selects the root non-persistent cookie behavior.

Password-reset request returns the same body for known and unknown numbers and calls `SendPasswordResetOTP` only for a known user. Reset consumes the purpose-bound OTP, applies root password bounds and hashing, creates or updates the credential account, runs the root reset hook, and follows `EmailAndPassword.RevokeSessionsOnReset`.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `OTPLength` | `6` | Positive decimal code length |
| `ExpiresIn` | 5 minutes | Built-in verification lifetime |
| `AllowedAttempts` | `3` | Failed built-in checks before lockout |
| `SendOTP` | none | Required by `/phone-number/send-otp`; also used when verification-required sign-in is blocked |
| `VerifyOTP` | built-in verification store | Custom verification authority for `/phone-number/verify` only |
| `SendPasswordResetOTP` | none | Delivery callback for known-user reset requests |
| `PhoneNumberValidator` | none | Accept/reject application phone format before sign-in/send |
| `RequireVerification` | `false` | Block password sign-in until the phone field is verified |
| `CallbackOnVerification` | none | Runs after verified association/update and before session issuance |
| `SignUpOnVerification` | `nil` | Optional unknown-number user creation; `GetTempEmail` is required when enabled |
| `Schema.User` | canonical names | Physical aliases for the user model and both phone fields |

The plugin rate rule is fixed at 10 requests per 60 seconds for `/phone-number/*`. `/sign-in/phone-number` remains subject to the root sign-in/rate policy rather than that plugin matcher.

## Schema and migrations

The factory adds these optional user fields:

| Field | Contract |
| --- | --- |
| `phoneNumber` | String, returned, unique, sortable, request-writable except through `/update-user` |
| `phoneNumberVerified` | Boolean, returned, not request-writable |

The plugin blocks direct `/update-user` writes to `phoneNumber`; use verified `updatePhoneNumber` instead. Clearing a phone number through trusted storage hooks also clears the verified flag.

Run `auth.RunMigrationsContext(ctx)` during deployment after adding the factory. The plugin also uses the core `verification`, `account`, and `session` models. Built-in migration is additive, so backfill or deduplicate existing phone values before relying on the unique index.

## Errors

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Missing or mistyped body field |
| 400 | `INVALID_PHONE_NUMBER` | Application validator rejected the number |
| 401 | `INVALID_PHONE_NUMBER_OR_PASSWORD` | User, credential account, or password did not match |
| 401 | `PHONE_NUMBER_NOT_VERIFIED` | Verification-required sign-in was blocked |
| 501 | `SEND_OTP_NOT_IMPLEMENTED` | Public send route has no `SendOTP` callback |
| 400 | `OTP_NOT_FOUND` / `OTP_EXPIRED` / `INVALID_OTP` | Missing, expired, wrong, consumed, or replayed code |
| 403 | `TOO_MANY_ATTEMPTS` | Built-in attempt budget was exhausted |
| 400 | `PHONE_NUMBER_EXIST` | Verified update targets an existing number |
| 400 | `PHONE_NUMBER_CANNOT_BE_UPDATED` | `/update-user` tried to set a phone directly |

Root password and session errors may also be returned.

## Direct API

Trusted server code can call `signInPhoneNumber`, `sendPhoneNumberOTP`, `verifyPhoneNumber`, `requestPasswordResetPhoneNumber`, and `resetPasswordPhoneNumber` through `auth.API().Call`. There is no separately bound server service. Direct calls bypass outer HTTP rate limiting, so add explicit abuse controls.

## Delivery, replay, and concurrency

Built-in codes are stored in the core verification value with an attempt suffix. Correct verification atomically consumes the row; concurrent calls allow one success, and reset codes cannot be replayed. Wrong checks consume and recreate the row with the same expiry and an incremented attempt count.

`VerifyOTP` replaces that built-in trust decision for `/phone-number/verify`. The callback receives only phone and code; it must enforce expiry, attempts, single-use/replay, and cross-replica atomicity in its own store. Password reset always uses the internal verification store.

The explicit send endpoint returns provider errors when background execution is not configured. Verification-required sign-in and reset delivery follow the root background/await compatibility path and log delivery failures without replacing the authoritative endpoint result. Monitor those logs and queue outcomes; a success response proves only that the auth flow accepted the request.

## Troubleshooting and security

- Normalize phone numbers consistently in `PhoneNumberValidator` and at application boundaries. The plugin compares stored strings exactly and does not perform E.164 normalization itself.
- `PHONE_NUMBER_NOT_VERIFIED` after correct password is expected when `RequireVerification` is enabled; complete `/phone-number/verify` with the delivered code.
- If signup verification returns an update failure, configure `SignUpOnVerification.GetTempEmail` to generate a valid unique address.
- The built-in code is plaintext in verification storage. Protect database access and use short expiry; use `VerifyOTP` with an external one-way store when plaintext storage is unacceptable.
- A code is consumed before callbacks and session issuance. Failures after proof require a new code.

## Related pages

- [Storage migrations](../storage/migrations.md)
- [Direct API](../transports/direct-api.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Phone-number package reference](../reference/packages/plugins--phonenumber.md)

**Status:** implemented with replay, concurrency, transport, and storage-backend coverage.
