---
title: "Anonymous users"
description: "Create temporary first-party users, transfer application state on account linking, and delete anonymous accounts."
---

The anonymous-users plugin creates a real root user and session without collecting credentials. A later successful sign-in, signup, callback, or verification flow can transfer application data to the new account and clean up the old anonymous user.

## Install and configure

Use `NewFactory` so session resolution, cookie names, secondary storage, serializers, clock, random source, and logging come from the root runtime.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/anonymous"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "https://auth.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            anonymous.NewFactory(anonymous.Options{
                EmailDomainName: "anonymous.example.invalid",
                OnLinkAccount: func(data anonymous.LinkAccountData) error {
                    return carts.Transfer(
                        data.Context.GoContext(),
                        data.AnonymousUser.User["id"].(string),
                        data.NewUser.User["id"].(string),
                    )
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

The callback is application code. Avoid unchecked assertions in production, make the transfer idempotent, and use your database's transaction/uniqueness primitives if duplicate transfer would be harmful.

## HTTP routes

Both routes use an empty JSON body.

| Method | Path | Success result | Authority |
| --- | --- | --- | --- |
| POST | `/sign-in/anonymous` | `token`, `user` | Public; rejects an already-anonymous current user |
| POST | `/delete-anonymous-user` | `{"success":true}` | Fresh authoritative session whose user is anonymous |

```http
POST /api/auth/sign-in/anonymous
Content-Type: application/json

{}
```

```json
{
  "token": "session-token",
  "user": {
    "id": "anonymous-user-id",
    "email": "temp-random-value@anonymous.example.invalid",
    "emailVerified": false,
    "name": "Anonymous",
    "isAnonymous": true
  }
}
```

Sign-in creates the user first, issues a normal persistent session, and records that session as the request's new-session state for other after-hooks. If an authenticated regular user calls this route, a separate anonymous user is created and becomes the new active session; applications usually expose it only to unauthenticated visitors.

## Identity generation

| Option | Default | Behavior |
| --- | --- | --- |
| `EmailDomainName` | empty | With a domain: `temp-<32 random chars>@<domain>`; without one: `temp@<32 random chars>.com` |
| `GenerateName` | none | Non-empty callback result replaces `Anonymous`; empty keeps the default |
| `GenerateRandomEmail` | none | Non-empty result replaces built-in generation and must pass email validation |
| `OnLinkAccount` | none | Runs before post-link deletion with cloned old/new user and session records |
| `DisableDeleteAnonymousUser` | `false` | Disables both explicit deletion and automatic post-link user deletion |
| `Schema` | canonical extension | Optional physical schema alias/metadata merged with the frozen field contract |

Generators may run concurrently. They must be thread-safe, and custom emails must be unique enough to satisfy the root user email constraint. Generated addresses are synthetic identifiers, not verified delivery channels.

## Account linking lifecycle

The after-hook watches successful session-setting responses under sign-in, signup, OAuth/provider callbacks, magic-link, email OTP, passkey, phone verification, one-tap, SIWE, and email verification paths.

Cleanup occurs only when all of these are true:

1. the response sets a non-empty root session cookie;
2. the request's previous session belongs to an anonymous user;
3. the endpoint recorded a new user/session;
4. the new user differs from the anonymous user and is not anonymous.

`OnLinkAccount` runs first. If it returns an error, the endpoint returns an error and the anonymous user is retained. After a successful callback, the plugin deletes the old user unless deletion is disabled. A post-link deletion failure is logged and swallowed so an already-successful authentication response remains successful.

This cleanup is not one transaction with the external authentication flow or your callback. Build the callback so retrying or reconciling a partially completed transfer is safe.

## Explicit deletion

`delete-anonymous-user` resolves an authoritative session instead of trusting cached session data. It then revokes all sessions for that user, deletes the user, and expires the root session-token, session-data, don't-remember, optional account-data, optional OAuth-state, and matching chunk cookies.

Session revocation and user deletion are sequential. If deletion fails after revocation, the user may remain without live sessions and the endpoint returns a stable 500 error. Monitor and reconcile those failures rather than blindly retrying client-side.

## Schema and migrations

The plugin adds `user.isAnonymous`: an optional boolean, not request-writable, with adapter-side default `false`. Anonymous sign-in writes `true` through trusted server creation.

Register the factory before adapter construction and run `auth.RunMigrationsContext(ctx)` during deployment. A `Schema` override that specifies only `FieldName` preserves the canonical boolean type, optional/input flags, and default. Built-in migrations add fields but never rename an existing physical column.

## Errors and rate limiting

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY` | Current user is already anonymous |
| 400 | `INVALID_EMAIL_FORMAT` | Custom generated email is invalid |
| 400 | `COULD_NOT_CREATE_SESSION` | User creation succeeded but session creation did not |
| 401 | `UNAUTHORIZED` | Delete route lacks an authoritative session |
| 403 | `USER_IS_NOT_ANONYMOUS` | Authenticated user is not anonymous |
| 400 | `DELETE_ANONYMOUS_USER_DISABLED` | Explicit deletion is disabled |
| 500 | `FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS` | Session revocation failed |
| 500 | `FAILED_TO_DELETE_ANONYMOUS_USER` | User deletion failed |

The plugin declares no plugin-specific rate rule. Root global and built-in sign-in policies remain authoritative for HTTP. Add an application limit if anonymous account creation could be abused for storage or messaging amplification.

## Direct API

Trusted in-process code can call `signInAnonymous` and `deleteAnonymousUser` through `auth.API().Call`; there is no separately bound server service. For direct deletion, propagate the issued cookie header as described in the direct API guide. Direct calls bypass outer HTTP rate limiting and transport-level protections.

## Concurrency and security

The built-in cryptographic random reader is locked for concurrent generation, and concurrent sign-ins create independent users, sessions, and unique generated emails. That does not make application `OnLinkAccount` logic atomic: use durable ownership markers or uniqueness constraints for transferred rows.

Do not authorize sensitive behavior from `isAnonymous` supplied by a request; the field is non-input and the delete route rereads authoritative session/user state. Protect the root secret and cookies, because the plugin relies on the same session trust boundary as the rest of single-auth.

## Troubleshooting

- `INVALID_EMAIL_FORMAT` with `EmailDomainName` usually means the configured domain is not syntactically valid; custom domains need a valid public-style suffix even when no mail is sent.
- If linking succeeds but guest data is missing, inspect `OnLinkAccount` first. Post-link deletion runs only after that callback succeeds.
- If the old user remains after a successful link, check `DisableDeleteAnonymousUser`, whether the new user differs, and logged cleanup failures.
- If deletion returns unauthorized despite a visible UI session, the authoritative session may be expired or only cached client-side; refresh/re-authenticate before retrying.

## Related pages

- [Storage migrations](../storage/migrations.md)
- [Direct API](../transports/direct-api.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Anonymous package reference](../reference/packages/plugins--anonymous.md)

**Status:** implemented with linking, cookie cleanup, concurrency, transport, and storage-backend coverage.
