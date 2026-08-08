---
title: "Email and password"
---

Credential sign-up, sign-in, password hashing, reset tokens, and anti-enumeration behavior.

Email/password authentication is disabled by default. Enable it explicitly and provide mail delivery callbacks for password reset or required email verification.

```go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://accounts.example.com",
    Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
    Database: adapter,
    EmailAndPassword: singleauth.EmailAndPasswordOptions{
        Enabled:                  true,
        RequireEmailVerification: true,
        RevokeSessionsOnReset:    true,
        SendResetPassword: func(ctx context.Context, message singleauth.PasswordResetMessage) error {
            return mailer.SendPasswordReset(ctx, message.User.Email, message.URL)
        },
    },
    EmailVerification: singleauth.EmailVerificationOptions{
        SendVerificationEmail: func(ctx context.Context, message singleauth.EmailVerificationMessage) error {
            return mailer.SendVerification(ctx, message.User.Email, message.URL)
        },
    },
})
```

## Defaults

| Option | Default and behavior |
| --- | --- |
| `Enabled` | `false`; both credential sign-up and sign-in reject requests. |
| `DisableSignUp` | `false`; meaningful only when credentials are enabled. |
| `RequireEmailVerification` | `false`; when true, sign-up does not issue a session and unverified sign-in returns `EMAIL_NOT_VERIFIED`. |
| `MinPasswordLength` | 8 UTF-16 code units. |
| `MaxPasswordLength` | 128 UTF-16 code units. |
| `AutoSignIn` | Omitted means enabled. Explicit `false` creates the user without a session. |
| `ResetPasswordTokenExpiresIn` | 1 hour. |
| `RevokeSessionsOnReset` | `false`. |
| `Password.Hash` / `Verify` | Built-in Better Auth-compatible scrypt. |

Password length uses UTF-16 code units, not Go bytes or runes, to preserve observable Better Auth validation for non-BMP characters.

## Built-in password format

The default hasher:

- normalizes the password with Unicode NFKC;
- generates a 16-byte random salt encoded as hexadecimal;
- uses scrypt with `N=16384`, `r=16`, `p=1`, and a 64-byte key;
- stores `hexSalt:hexDerivedKey`;
- verifies using a constant-time comparison;
- rejects malformed hashes without panicking.

Custom functions replace both operations:

```go
EmailAndPassword: singleauth.EmailAndPasswordOptions{
    Enabled: true,
    Password: singleauth.PasswordOptions{
        Hash: func(password string) (string, error) {
            return customHash(password)
        },
        Verify: func(hash, password string) bool {
            return customVerify(hash, password)
        },
    },
},
```

The custom verifier must be safe for untrusted malformed hashes and should use constant-time comparison. Plugin factories may wrap the hash chain during initialization; wrappers are frozen before requests start.

## Sign-up behavior

`POST /sign-up/email` accepts:

```json
{
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "password": "correct-horse-battery-staple",
  "image": null,
  "callbackURL": "/dashboard",
  "rememberMe": true
}
```

Schema fields marked as input may be included in the same object. Core-controlled or schema fields that are not allowed as input are rejected when supplied with a truthy value.

The route validates name, email, and password, lowercases the email, hashes the password, then atomically creates the user and a `credential` account. It creates a session in the same transaction unless verification is required or `AutoSignIn` is explicitly false. A storage failure rolls back adapters with transaction support.

The response is `{token,user}`. `token` is null when no session is issued. Otherwise the response also emits signed session cookies.

Duplicate sign-up deliberately performs expensive hash work before responding. When verification is required or auto sign-in is disabled, the duplicate response is the same generic successful `{token:null,user}` shape and `OnExistingUserSignUp` may run in the background. In the normal auto-sign-in mode, a duplicate returns status 422 with `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`.

`SendOnSignUp` is a pointer:

- omitted: send when `RequireEmailVerification` is true;
- explicit true: send after sign-up even when verification is not required;
- explicit false: suppress automatic sign-up delivery.

A missing `SendVerificationEmail` callback means no message can be delivered; configure both the policy and sender together.

## Sign-in behavior

`POST /sign-in/email` accepts `email`, `password`, optional `callbackURL`, and optional `rememberMe`.

The route lowercases email lookup, locates the user's `credential` account, and verifies the password. Missing users, missing credential accounts, and wrong passwords all return `INVALID_EMAIL_OR_PASSWORD`; the missing-user path performs hash work to reduce timing disclosure.

When email verification is required, an unverified user is rejected. If `EmailVerification.SendOnSignIn` is true, a fresh verification email is sent first. Successful sign-in creates a session and returns:

```json
{
  "redirect": true,
  "token": "session-token",
  "url": "/dashboard",
  "user": {}
}
```

`redirect` is true only for a non-empty callback URL, and the response also carries `Location`. Without a callback, `url` is absent and `redirect` is false.

`rememberMe=false` creates a 24-hour logical session, makes the token cookie a browser-session cookie, and sets a signed `dont_remember` marker. Omitted or true uses `Session.ExpiresIn`, which defaults to seven days.

## Password reset

Password reset is enabled only when `SendResetPassword` is non-nil.

1. `POST /request-password-reset` validates `email` and optional `redirectTo`.
2. For an existing user it stores a single-use `reset-password:<token>` verification value with the configured lifetime and calls `SendResetPassword` with `User`, `URL`, and raw `Token`.
3. `GET /reset-password/:token?callbackURL=...` checks validity without consuming the value and redirects with either `token` or `error=INVALID_TOKEN`.
4. `POST /reset-password` accepts `newPassword` and a token in the body or query, atomically consumes it, updates or creates the credential account, and returns `{status:true}`.

The request endpoint always returns:

```json
{
  "status": true,
  "message": "If this email exists in our system, check your email for the reset link"
}
```

For an unknown email it still performs random and verification-store work. Application code must preserve the generic result and must not add an account-existence distinction.

Reset tokens are single use. Replay, missing, expired, and malformed values fail. Secondary storage should implement its atomic get-and-delete extension for cross-process replay safety. With `RevokeSessionsOnReset`, all of the user's existing sessions are removed after the password update.

`OnPasswordReset` runs after the credential update. `BeforeEmailVerification`, `AfterEmailVerification`, and password reset callbacks receive the request context and can return an error.

## Change, verify, and set password

- `POST /change-password` requires an authoritative session, `newPassword`, and `currentPassword`. It hashes the new password before checking the old one. With `revokeOtherSessions=true`, it revokes every session, creates a replacement, emits new cookies, and returns its token.
- `POST /verify-password` requires an authoritative session and returns `{status:true}` only when a credential password matches.
- `setPassword` is server-only and can be called through `auth.API().SetPassword`. It requires an authoritative session and refuses to replace an existing credential password with `PASSWORD_ALREADY_SET`.

The HTTP router never exposes `setPassword`, even if a path is accidentally attached by an override. It is intended for trusted server workflows that add credentials to a social-only account.

## Background execution

Nil `RunBackground` executes mail and lifecycle callbacks synchronously. A custom runner controls queuing:

```go
RunBackground: func(ctx context.Context, job func(context.Context) error) error {
    return durableQueue.Enqueue(ctx, func(workerCtx context.Context) error {
        return job(workerCtx)
    })
},
```

The runner's return value is observable by the endpoint. Define whether enqueue failure should fail the request, make jobs idempotent, and do not retain an `engine.Context` after dispatch; only retain ordinary data and a safe Go context.
