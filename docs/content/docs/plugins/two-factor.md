---
title: "Two-factor authentication"
description: "Configure and operate TOTP, delivered OTP, backup codes, trusted devices, challenge replay protection, and lockout in Go."
---

Add TOTP, out-of-band OTP, backup codes, trusted devices, and account lockout.

All paths below are relative to the auth `BasePath` (`/api/auth` by default). Credential sign-in hooks convert successful email, username, and phone first-factor responses into two-factor challenges when `user.twoFactorEnabled` is true.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/twofactor` and `github.com/pers0na2dev/single-auth/core/engine`. The root factory supplies storage, sessions, cookies, encryption, randomness, and verification services.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/core/engine"
    "github.com/pers0na2dev/single-auth/plugins/twofactor"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        AppName: "Example Account",
        BaseURL: "http://localhost:8080",
        BasePath: "/api/auth",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"http://localhost:3000"},
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            twofactor.NewFactory(twofactor.Options{
                Issuer: "Example Account",
                OTP: twofactor.OTPOptions{
                    Storage: twofactor.OTPStorage{Mode: twofactor.OTPStorageHashed},
                    SendOTP: func(ctx context.Context, message twofactor.OTPMessage, _ *engine.Context) error {
                        email, _ := message.User["email"].(string)
                        return mailOTP(ctx, email, message.OTP)
                    },
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

`mailOTP` represents an application delivery function. It must fail when delivery fails, avoid logging the code, and apply its own provider retry/observability policy. Install username or phone-number factories before two-factor when those sign-in routes are enabled so their credential response hooks are composed first.

Compose and migrate the plugin schema before serving traffic; see [Schemas](../storage/schemas.md) and [Migrations](../storage/migrations.md).

## Enroll TOTP

Enrollment starts from an ordinary authenticated session. With the default password policy, a credential account must confirm its password:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"password":"correct-horse-battery-staple"}' \
  http://localhost:8080/api/auth/two-factor/enable
```

The response returns the authenticator URI and the only plaintext copy of the initial backup-code set exposed by a public endpoint:

```json
{
  "totpURI": "otpauth://totp/Example%20Account:ada%40example.com?...",
  "backupCodes": ["Ab3dE-f7Gh1", "..."]
}
```

Display the URI as a QR code or enter it in an authenticator. Store the backup codes securely, then verify one current code using the same session:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"code":"123456"}' \
  http://localhost:8080/api/auth/two-factor/verify-totp
```

With `SkipVerificationOnEnable:false`, this verification marks the factor record verified, sets `user.twoFactorEnabled`, replaces the old session, and returns `{"token":"...","user":{...}}`. Do not treat receipt of the enrollment URI alone as completed enrollment.

Calling `enable` again replaces the stored secret and backup-code set. Build an explicit re-enrollment confirmation screen so an attacker with a stolen session cannot silently invalidate the user's existing factors.

## Sign in with a second factor

The first credential request still validates the password, but a 2FA-enabled account does not keep the session it initially created. The plugin removes that session, scrubs its cookies, stores a ten-minute challenge, and returns the available primary methods:

```bash
curl --fail-with-body \
  --cookie-jar challenge-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"email":"ada@example.com","password":"correct-horse-battery-staple"}' \
  http://localhost:8080/api/auth/sign-in/email
```

```json
{
  "twoFactorRedirect": true,
  "twoFactorMethods": ["totp", "otp"]
}
```

Preserve `challenge-cookies.txt`: it contains the signed challenge handle. Verify TOTP to consume the challenge and issue the real session:

```bash
curl --fail-with-body \
  --cookie challenge-cookies.txt \
  --cookie-jar challenge-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"code":"123456","trustDevice":true}' \
  http://localhost:8080/api/auth/two-factor/verify-totp
```

For delivered OTP, first create and deliver a code, then verify it with the same challenge cookie:

```bash
curl --fail-with-body \
  --cookie challenge-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{}' \
  http://localhost:8080/api/auth/two-factor/send-otp

curl --fail-with-body \
  --cookie challenge-cookies.txt \
  --cookie-jar challenge-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"code":"482901"}' \
  http://localhost:8080/api/auth/two-factor/verify-otp
```

`trustDevice:true` writes a signed trusted-device cookie plus a server-side verification record. A later successful first factor rotates that record and cookie and skips the second factor. The default lifetime is 30 days.

## Public endpoints

| Method | Path | Input | Result | Authority and important failures |
| --- | --- | --- | --- | --- |
| POST | `/two-factor/enable` | Optional `password`, optional one-response `issuer` label | `totpURI`, new `backupCodes` | Required session and password policy; replaces existing factor material |
| POST | `/two-factor/get-totp-uri` | Optional `password` | `totpURI` for stored secret | Required session, existing TOTP record, TOTP enabled, password policy |
| POST | `/two-factor/disable` | Optional `password` | `{"status":true}` | Authoritative session and password policy; deletes factor row and current trusted-device record |
| POST | `/two-factor/verify-totp` | `code`, optional `trustDevice` | `token` and public `user` | Active sign-in challenge or authenticated enrollment session; TOTP configured and verified |
| POST | `/two-factor/send-otp` | Empty body or `{}` | `{"status":true}` | Active challenge/session and configured `SendOTP`; creates a fresh OTP record |
| POST | `/two-factor/verify-otp` | `code`, optional `trustDevice` | `token` and public `user` | Active challenge/session, unexpired OTP, attempts remaining |
| POST | `/two-factor/verify-backup-code` | `code`, optional `disableSession`, `trustDevice` | Normally `token` and public `user` | Active challenge/session and unused stored backup code |
| POST | `/two-factor/generate-backup-codes` | Optional `password` | `status`, replacement `backupCodes` | Required session, 2FA enabled, backup-code password policy |

`disableSession:true` on backup-code verification consumes the code but skips issuing a new sign-in session. Use it only in a flow that intentionally needs verification without a session.

`generateTOTP` and `viewBackupCodes` are registered as server-only direct endpoints and have no HTTP route. `generateTOTP` accepts a trusted secret and returns a current code. `viewBackupCodes` accepts a trusted `userId` and can reveal stored codes when their configured codec is reversible. Never expose either operation through an application proxy without independent authorization, rate limiting, and audit logging.

## Backup-code lifecycle

Generate a replacement set only after the user has stored it; the previous set becomes invalid immediately:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"password":"correct-horse-battery-staple"}' \
  http://localhost:8080/api/auth/two-factor/generate-backup-codes
```

Each successful backup-code verification removes that exact code with a compare-and-set update. Concurrent reuse can produce at most one success. A competing authenticated-session request that reaches the conditional update receives 409 `CONFLICT`; a competing sign-in request may instead lose the shared challenge-attempt claim.

## Defaults and ordering

| Option | Default and behavior |
| --- | --- |
| `Issuer` | Root `AppName` when empty |
| `TOTP.Digits` / `TOTP.Period` | 6 / 30 seconds; digits may be 6 or 8; verification accepts previous, current, or next period |
| `TOTP.Disable` | `false`; when true TOTP is not advertised and TOTP endpoints return `TOTP_NOT_CONFIGURED` |
| `OTP.Digits` / `OTP.Period` | 6 / 3 minutes |
| `OTP.AllowedAttempts` | 5 per delivered OTP |
| `OTP.Storage` | Plain compatibility mode; built-in hashed/encrypted or one custom hash/encryption codec is available |
| `BackupCodes.Amount` / `Length` | 10 codes / 10 random characters, formatted with a hyphen after the first five |
| `BackupCodes.Storage` | Encrypted with the root secret service; plain or custom reversible encryption is also supported |
| `SkipVerificationOnEnable` | `false` |
| `AllowPasswordless` | `false` |
| `TwoFactorCookieMaxAge` | 10 minutes |
| `TrustDeviceMaxAge` | 30 days |
| `AccountLockout.Enabled` | nil means enabled |
| `AccountLockout.MaxFailedAttempts` / `Duration` | 10 / 15 minutes |
| HTTP rate-limit rule | 3 requests per 10 seconds for `/two-factor/*` when root HTTP limiting is enabled |

`AllowPasswordless:true` skips password confirmation only when the user has no credential account. It does not let a credential account bypass its password. `TOTP.AllowPasswordless` overrides the global value for `get-totp-uri`; `BackupCodes.AllowPasswordless` overrides it for backup-code regeneration. Enable and disable use the global value.

`SkipVerificationOnEnable:true` marks 2FA enabled before a TOTP proof and rotates the session immediately. Leave it false unless another trusted step has already verified the authenticator.

The plugin challenge cap for TOTP and backup-code sign-in is five failed attempts. Delivered OTP separately uses `OTP.AllowedAttempts`. Account lockout counts failed sign-in TOTP, delivered OTP, and backup-code checks across challenges; enrollment verification does not increment account lockout.

## Storage and secret handling

The factory adds `user.twoFactorEnabled` and a `twoFactor` model:

| Field | Behavior |
| --- | --- |
| `secret` | Encrypted TOTP secret; indexed and never returned by normal model serialization |
| `backupCodes` | Encoded code set; encrypted by default and not returned |
| `userId` | Indexed user reference with cascade delete; not returned |
| `verified` | Enrollment state, default true at the schema layer but explicitly set by enrollment |
| `failedVerificationCount` / `lockedUntil` | Server-managed lockout state; not returned |

The challenge, attempt, delivered-OTP, and trusted-device records use core verification storage. They are not extra fields on the `twoFactor` model. Schema model/field aliases are available through `Schema`, and `TwoFactorTable` overrides the canonical model name.

TOTP secrets and default backup codes are encrypted through the root secret service. Retain the required old secret entries while rotating encrypted plugin data, and plan a factor reset if the necessary decryption key is lost. Delivered OTP defaults to plaintext compatibility storage; choose `OTPStorageHashed` when the code never needs recovery, or encrypted/custom storage when delivery architecture requires it. See [Security](../core/security.md).

## Replay, concurrency, and lockout

A sign-in challenge is a signed cookie handle plus server-side verification rows. Successful verification atomically consumes the challenge before issuing a session, so the same challenge cannot create two sessions. Five-attempt bookkeeping uses consume-and-rearm semantics. Expired, malformed, already-consumed, or mismatched challenge state returns `INVALID_TWO_FACTOR_COOKIE` or the factor-specific expiry error.

Delivered OTP verification atomically consumes the OTP record. A wrong code is rearmed with an incremented counter and the original expiry; a correct code is not restored. Backup-code removal uses `Adapter.IncrementOne` with the previously observed encoded set. Lockout increments use atomic storage mutations, then set `lockedUntil` after the configured threshold.

Trusted-device records rotate on use instead of remaining as a static replay token. Disabling 2FA revokes the record referenced by the current trusted-device cookie and expires that cookie. An application that exposes account-wide device management should track and revoke any other outstanding trusted-device records itself.

## Errors and direct API

Important codes are `INVALID_TWO_FACTOR_COOKIE` (401), `INVALID_CODE` (401), `INVALID_BACKUP_CODE` (401), `OTP_HAS_EXPIRED` (400), `TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE` (400), and `ACCOUNT_TEMPORARILY_LOCKED` (429). Disabled or missing factors return the corresponding `*_NOT_ENABLED` or `*_NOT_CONFIGURED` code. Password failures use the core invalid-password error. Match on code rather than message.

Exported declarations are listed in the [two-factor package reference](../reference/packages/plugins--twofactor.md). See also [Sessions](../core/sessions.md), [Direct API](../transports/direct-api.md), and [Storage transactions](../storage/transactions.md). **Status:** implemented.
