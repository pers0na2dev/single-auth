---
title: "Admin"
description: "Manage users, roles, bans, credentials, sessions, and impersonation with the native Go admin plugin."
---

Admin adds role-based user management, bans, credential replacement, session revocation, and short-lived impersonation. Every HTTP route is evaluated against the current authoritative session; a stale cached role or a revoked session does not preserve administrative access.

All paths below are relative to the auth `BasePath` (`/api/auth` by default). The same endpoint behavior is available through `net/http`, direct `fasthttp`, Fiber, and the direct API.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/admin`. Register the factory after any custom access-control declarations that its options reference.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/admin"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            admin.NewFactory(admin.Options{
                // Bootstrap an existing user independently of its stored role.
                AdminUserIDs: []string{"<existing-user-id>"},
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The factory contributes fields before the adapter is constructed. Apply the composed schema before serving traffic; see [Schemas](../storage/schemas.md) and [Migrations](../storage/migrations.md). Prefer `NewFactory` in an application. `New` and the exported `Runtime` exist for explicit embedding and focused tests.

## Roles and permissions

The default access-control vocabulary is:

| Resource | Actions |
| --- | --- |
| `user` | `create`, `list`, `set-role`, `ban`, `impersonate`, `impersonate-admins`, `delete`, `set-password`, `set-email`, `get`, `update` |
| `session` | `list`, `revoke`, `delete` |

The built-in `admin` role receives every listed action except `user:impersonate-admins`; the built-in `user` role receives none. `AdminUserIDs` bypasses permission evaluation and is useful for bootstrap or break-glass accounts. Multiple stored roles are comma-separated and authorization succeeds when any one role satisfies the complete requested permission set.

`Roles` replaces the built-in role map when non-nil. Define every role that should authorize an action, including the default user role. When `AdminRoles` is supplied explicitly, every entry must exist in `Roles` (or in the built-in map when `Roles` is nil), otherwise construction fails. `AdminRoles` also classifies impersonation targets as administrators; the actual ability to call a route still comes from the role statements or `AdminUserIDs`.

## User endpoints

All user-management routes require an authenticated actor and the permission shown. JSON IDs accept values coercible to strings; query IDs are strings.

| Method | Path | Input | Success result | Permission |
| --- | --- | --- | --- | --- |
| GET | `/admin/get-user` | Query `id` | Public user projection | `user:get` |
| POST | `/admin/create-user` | `name`, `email`; optional `password`, `role` string or string array, `data` object | `{"user":{...}}` | `user:create`; assigning a role also needs `user:set-role`, ban fields need `user:ban` |
| POST | `/admin/update-user` | `userId`, non-empty `data` | Updated public user | `user:update`; protected fields require the additional permission below |
| POST | `/admin/set-role` | `userId`, `role` string or string array | `{"user":{...}}` | `user:set-role` |
| GET | `/admin/list-users` | Search, filter, sort, `limit`, and `offset` query fields | `{"users":[...],"total":N,"limit"?:N,"offset"?:N}` | `user:list` |
| POST | `/admin/ban-user` | `userId`; optional `banReason`, `banExpiresIn` seconds | `{"user":{...}}` | `user:ban` |
| POST | `/admin/unban-user` | `userId` | `{"user":{...}}` | `user:ban` |
| POST | `/admin/remove-user` | `userId` | `{"success":true}` | `user:delete` |
| POST | `/admin/set-user-password` | `userId`, `newPassword` | `{"status":true}` | `user:set-password` |

`create-user` lowercases and validates email, passes `data` through the root user-input parser, and owns the protected `role`, `banned`, `banReason`, and `banExpires` fields. An omitted or empty password creates no credential account. A non-empty password runs the installed root password-hash chain, so password-policy plugins such as [Have I Been Pwned](./have-i-been-pwned.md) also apply.

`update-user` rejects `data.password`; use `set-user-password`. Changing `role` needs `user:set-role`, changing `banned`, `banReason`, or `banExpires` needs `user:ban`, and changing `email` or `emailVerified` needs `user:set-email`. Setting `banned:true` for the actor is rejected and revokes the target's sessions after the update. `set-user-password` enforces the root minimum and maximum password lengths before hashing.

### Listing users

`list-users` accepts:

| Query | Default | Meaning |
| --- | --- | --- |
| `searchValue` | omitted | Adds one search predicate |
| `searchField` | `email` | Field used by `searchValue` |
| `searchOperator` | `contains` | Storage comparison operator |
| `filterValue` | omitted | Adds one filter predicate; repeat for an array value |
| `filterField` | `email` | Field used by `filterValue` |
| `filterOperator` | `eq` | Storage comparison operator |
| `sortBy` | omitted | Field used for ordering |
| `sortDirection` | `asc` | Only exact `desc` selects descending order |
| `limit`, `offset` | omitted | Decimal integers; zero or an invalid value is treated as omitted |

Supported storage operators are `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`, `contains`, `starts_with`, and `ends_with`. Boolean and integer filter strings are converted to their scalar forms. Treat field names and operators as an application allowlist before forwarding arbitrary user input. For compatibility, adapter lookup or count errors produce an empty successful list; inspect server/storage logs when a seemingly valid query unexpectedly returns `users:[]` and `total:0`.

## Sessions and impersonation

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/admin/list-user-sessions` | `userId` | `{"sessions":[...]}` | `session:list`; includes persisted active and expired rows returned by the adapter |
| POST | `/admin/revoke-user-session` | `sessionToken` | `{"success":true}` | `session:revoke` |
| POST | `/admin/revoke-user-sessions` | `userId` | `{"success":true}` | `session:revoke` |
| POST | `/admin/impersonate-user` | `userId` | Impersonation `session` and target `user` | `user:impersonate`; admin targets need the extra policy below |
| POST | `/admin/stop-impersonating` | Empty object | Restored administrator `session` and `user` | A valid impersonated session plus its signed original-admin cookie |

Impersonation creates a separate don't-remember session with `impersonatedBy` and the configured expiry, stores the original administrator token in a signed `admin_session` cookie, and refreshes the response to the target session. By default, a target in `AdminUserIDs` or `AdminRoles` cannot be impersonated. Enable it globally with `AllowImpersonatingAdmins`, or give the actor `user:impersonate-admins`.

Stopping impersonation consumes the current impersonated session, verifies that the saved original session still belongs to the recorded administrator, restores it, and expires the helper cookie. The core `/list-sessions` response hides sessions with `impersonatedBy`; the explicit admin session-list route is not that filtered view.

## Permission endpoint and direct authority

`POST /admin/has-permission` accepts a `permissions` object whose keys are resources and whose values are string action arrays. An HTTP caller must have a session; supplied `role` and `userId` are ignored and the current session user is evaluated. Success is always an authorization result, not an HTTP authorization grant:

```json
{
  "permissions": {"user":["get","list"]}
}
```

```json
{"error":null,"success":true}
```

A headerless direct call may instead supply `role`, or `userId` to load the stored role. If both are present, the explicit role wins. This mode is trusted server authority and must never be exposed as a pass-through HTTP endpoint.

All endpoint names are callable through `auth.API().Call`: `setRole`, `getUser`, `createUser`, `adminUpdateUser`, `listUsers`, `listUserSessions`, `unbanUser`, `banUser`, `impersonateUser`, `stopImpersonating`, `revokeUserSession`, `revokeUserSessions`, `removeUser`, `setUserPassword`, and `userHasPermission`.

Headerless direct `createUser` is also intentionally treated as trusted provisioning and can skip the administrator-session check. Adding caller headers restores normal session authorization. Other privileged direct operations require the same authenticated session context as their HTTP equivalents unless their contract above explicitly says otherwise.

For concrete custom user results in trusted direct calls, use
`admin.NewTypedFactory`, bind it after `singleauth.New`, and call its typed
`CreateUser` and `ListUsers` wrappers. The embedded root direct API exposes the
remaining operations.

## Options and defaults

| Option | Default and behavior |
| --- | --- |
| `DefaultRole` | `user`; applied by the user-create database hook and admin create when no role is supplied |
| `AdminRoles` | `[]string{"admin"}`; identifies administrator targets and is validated when explicitly configured |
| `DefaultBanReason` | Empty; a ban with no request reason falls back to `No reason` |
| `DefaultBanExpiresIn` | `0`; no expiry is stored unless the request or this option supplies one |
| `ImpersonationSessionDuration` | One hour |
| `Schema` | No aliases; may remap the plugin-owned canonical fields |
| `Roles` | nil; uses the built-in `admin` and `user` roles |
| `AdminUserIDs` | nil; exact user IDs in this list bypass all permission checks |
| `BannedUserMessage` | `You have been banned from this application. Please contact support if you believe this is an error.` |
| `AllowImpersonatingAdmins` | `false` |
| `Runtime` | Filled by `NewFactory`; set only for standalone embedding/tests |

`banExpiresIn` is a request duration in seconds. A non-zero request value wins; otherwise `DefaultBanExpiresIn` is used. When neither is non-zero, the ban is indefinite. An expired ban is cleared lazily the next time a session is created.

## Storage and migrations

The factory extends existing core models; it adds no standalone model:

| Model | Canonical field | Type and ownership |
| --- | --- | --- |
| `user` | `role` | Optional string, server-managed |
| `user` | `banned` | Optional boolean, server-managed, default `false` |
| `user` | `banReason` | Optional string, server-managed |
| `user` | `banExpires` | Optional date, server-managed |
| `session` | `impersonatedBy` | Optional string, server-managed |

Adding the plugin or changing a physical alias requires a migration. The user/session fields are marked non-input so ordinary root user/session mutation routes cannot forge them.

The user-create hook supplies `DefaultRole`. The session-create hook reads the latest user row through the transaction-aware adapter: an active ban returns `403 BANNED_USER`; an expired ban is cleared and session creation proceeds. Banning through `ban-user` or `update-user` revokes the user's existing sessions, including secondary-storage session state through the root runtime.

## Errors and failure ordering

Match on stable `code`, not message text. Common results include:

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `UNAUTHORIZED` | No valid current session |
| 403 | `YOU_ARE_NOT_ALLOWED_TO_*` | The actor lacks the route or protected-field permission |
| 403 | `BANNED_USER` | Session creation was attempted for an active ban |
| 400 | `YOU_CANNOT_BAN_YOURSELF` / `YOU_CANNOT_REMOVE_YOURSELF` | Self-target protection |
| 403 | `YOU_CANNOT_IMPERSONATE_ADMINS` | Administrator target is protected |
| 400 | `YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE` | A role is absent from a configured `Roles` map |
| 400 | `INVALID_ROLE_TYPE` | `role` is neither a string nor a string array |
| 400 | `PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER` | Password was placed in generic update data |
| 404 | `USER_NOT_FOUND` | Target user does not exist |
| 400 | `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` | Normalized email collides with another user |
| 400 | `PASSWORD_TOO_SHORT` / `PASSWORD_TOO_LONG` | Replacement password violates root bounds |

Creating a user and then setting its optional credential are separate storage steps. If hashing or credential persistence fails, the user row may already exist. Likewise, banning updates the user before revoking sessions. Reconcile the target row after a downstream storage failure rather than blindly retrying a whole administrative workflow.

Permission checks are stateless and concurrency-safe over the snapshotted role map. Concurrent mutations rely on the selected adapter's uniqueness, update, and revocation guarantees; the plugin does not add a cross-process lock around conflicting admin writes. See [Transactions](../storage/transactions.md) and [Multi-replica sessions](../guides/multi-replica-sessions.md).

## Security and troubleshooting

- Keep bootstrap `AdminUserIDs` short, audited, and sourced from stable IDs rather than email addresses. An entry bypasses every configured permission.
- Preserve the root origin/CSRF policy on cookie-authenticated mutation routes. A direct API is not a safe public proxy.
- Treat session tokens returned by the session-list operation as credentials. Avoid logs, analytics, and broad UI exposure.
- If an administrator is suddenly forbidden, inspect the current persisted `role`, `banned` state, active session, custom `Roles`, and exact comma-separated role names. Authorization intentionally rereads authoritative state.
- If impersonation cannot be stopped, verify that the signed `admin_session` cookie reached the server and that the original administrator session still exists.
- If user listing returns an unexplained empty result, validate field names/operators against the adapter and check storage logs; compatibility behavior hides lookup/count errors behind an empty list.

See [Security](../core/security.md), [Sessions](../core/sessions.md), [Direct API](../transports/direct-api.md), and the [admin package reference](../reference/packages/plugins--admin.md).

**Status:** implemented with authorization, secondary-storage, password-plugin, replay-sensitive impersonation, concurrency, and transport coverage.
