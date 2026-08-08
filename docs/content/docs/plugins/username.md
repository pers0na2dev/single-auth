---
title: "Username"
description: "Add normalized unique usernames, display names, availability checks, and password sign-in."
---

Username adds optional normalized login names and presentation-only display usernames to the root user model. Its HTTP hooks cover email signup and profile updates, while database hooks preserve the same normalization and uniqueness rules for trusted direct user writes.

## Install and configure

Register the factory before adapter construction so the final schema includes both fields.

```go
package main

import (
    "log"
    "net/http"
    "os"
    "regexp"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/username"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "https://auth.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            username.NewFactory(username.Options{
                MinUsernameLength: 3,
                MaxUsernameLength: 24,
                UsernameValidator: func(value string) (bool, error) {
                    return usernamePattern.MatchString(value), nil
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

The factory inherits password hashing/verification, session issuance, email-verification-on-sign-in, redirect policy, serializers, and the adapter from the root runtime.

## User input hooks

Email signup accepts `username` and `displayUsername` in addition to the core fields:

```http
POST /api/auth/sign-up/email
Content-Type: application/json

{
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "password": "correct-horse-battery-staple",
  "username": "Ada_L",
  "displayUsername": "Ada_L"
}
```

The stored username is `ada_l` under the default lowercase normalizer, while the display username remains `Ada_L`.

Hook compatibility behavior is:

- if signup supplies `username` but no truthy `displayUsername`, display defaults to the submitted username before persistence;
- if signup supplies only a display username that also passes username rules, it is inferred as the username;
- an explicit empty username is not replaced by the display value;
- `/update-user` can change either field, but a username already owned by another user is rejected;
- trusted adapter create/update calls run database hooks and normalize the values even outside those two HTTP routes.

## Plugin routes

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/sign-in/username` | `username`, `password`, optional `rememberMe`, `callbackURL` | `redirect`, `token`, optional `url`, `user` | Public credential request |
| POST | `/is-username-available` | `username` | `{"available":true|false}` | Public availability query |

### Sign in

```http
POST /api/auth/sign-in/username
Content-Type: application/json

{"username":"ADA_L","password":"correct-horse-battery-staple","rememberMe":true}
```

Lookup uses the normalized username. Successful sign-in issues a normal root session. `rememberMe:false` selects non-persistent session-cookie behavior.

When `callbackURL` is present and non-empty, it must pass the root redirect policy. The response is still JSON with HTTP 200, `redirect:true`, `url`, and a `Location` header; the plugin does not itself emit a 302.

If root email/password policy requires verified email, unverified users receive `EMAIL_NOT_VERIFIED`. When root `EmailVerification.SendOnSignIn` is enabled, the plugin creates the normal signed verification URL and invokes the root sender before returning that error.

### Availability

Availability validates length and syntax, normalizes the candidate for lookup, and returns only whether a stored user exists. It does not reserve the name. Signup or update must still handle a uniqueness conflict after an earlier availability response.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `MinUsernameLength` | `3` | Minimum JavaScript-compatible UTF-16 code-unit length |
| `MaxUsernameLength` | `30` | Maximum UTF-16 code-unit length |
| `UsernameValidator` | `^[a-zA-Z0-9_.]+$` | Syntax callback after the applicable validation-order transform |
| `UsernameNormalization` | `strings.ToLower` | Value used for persistence and lookup |
| `DisableUsernameNormalization` | `false` | Preserve submitted username instead of lowercasing |
| `DisplayUsernameValidator` | none | Optional independent validator for explicitly supplied display values |
| `DisplayUsernameNormalization` | identity | Presentation-value transform |
| `ValidationOrder.Username` | pre-normalization behavior | Validate submitted username unless post-normalization is selected |
| `ValidationOrder.DisplayUsername` | pre-normalization behavior | Validate submitted display value unless post-normalization is selected |
| `Schema.User` | canonical names | Physical aliases for user model, username, and display username |

Validators return `(bool, error)`: `false` becomes a stable validation code, while an error becomes an internal failure. Normalizers and validators may run concurrently and must be deterministic and thread-safe.

The explicit `PreNormalization`/`PostNormalization` settings preserve frozen 1.6.26 ordering, including its sign-in-specific ordering. Test custom normalizers against signup, update, availability, and sign-in together rather than assuming every endpoint passes the same intermediate representation.

## Schema and migrations

| Field | Contract |
| --- | --- |
| `user.username` | Optional returned string, unique and sortable, normalized on input |
| `user.displayUsername` | Optional string, independently normalized on input |

Run `auth.RunMigrationsContext(ctx)` in a controlled deployment stage after registering the factory. Adding the unique username index can fail if existing physical data already contains duplicate normalized values; audit and backfill first. Physical aliases change generated schema names but do not rename an existing column automatically.

## Errors and security

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `INVALID_USERNAME_OR_PASSWORD` | User, credential account, or password did not match |
| 403 | `EMAIL_NOT_VERIFIED` | Root policy blocks sign-in until email proof |
| 400/422 | `USERNAME_TOO_SHORT` / `USERNAME_TOO_LONG` | Candidate violates configured UTF-16 bounds |
| 400/422 | `INVALID_USERNAME` | Username validator rejected the candidate |
| 400 | `INVALID_DISPLAY_USERNAME` | Display validator rejected an explicit value |
| 400 | `USERNAME_IS_ALREADY_TAKEN` | Signup/update conflicts with another user |
| 400 | `VALIDATION_ERROR` | Required body fields are missing or mistyped |

Unknown-user sign-in performs an expensive request-scoped password hash before returning the same credential error, reducing username-existence timing leakage. Keep availability public only if deliberate enumeration of usernames is acceptable, and rate-limit it at the application or root layer: the plugin declares no additional rate rule.

Unicode length is measured as UTF-16 code units for compatibility, while the default syntax is ASCII-only. If allowing Unicode, define normalization, confusable-character, case-folding, and moderation policy explicitly.

## Direct API

Trusted server code can call `signInUsername` and `isUsernameAvailable` through `auth.API().Call`. Core direct user create/update methods also run the installed database hooks; there is no separate bound username service. Direct calls bypass outer HTTP rate limiting and must receive independent abuse protection.

## Troubleshooting

- A mixed-case candidate can be unavailable even when no identical casing exists because uniqueness is enforced after normalization.
- An availability success is advisory, not a lock. Treat `USERNAME_IS_ALREADY_TAKEN` during write as the final result.
- If a custom normalizer changes accepted characters, use `PostNormalization` only after testing all four input paths noted above.
- A callback URL that produces an origin error is checked by the root redirect policy before password verification completes.
- Changing a normalizer after users exist requires an explicit data migration; the additive schema migrator does not rewrite stored names.

## Related pages

- [Storage migrations](../storage/migrations.md)
- [Direct API](../transports/direct-api.md)
- [Security](../core/security.md)
- [Username package reference](../reference/packages/plugins--username.md)

**Status:** implemented with schema-hook, timing-equalization, transport, and storage-backend coverage.
