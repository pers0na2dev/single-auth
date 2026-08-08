---
title: "Multi-session"
description: "Retain several account sessions in one client, switch the active account, and revoke retained sessions."
---

Multi-session keeps several signed session references in one browser or Go cookie jar. It is primarily an account-switching feature: one retained session per user can be listed, activated, or revoked without typing credentials again.

## Install and order plugins

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/multisession"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "https://auth.example.com",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            multisession.NewFactory(multisession.Options{
                MaximumSessions: multisession.Int(8),
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The factory must see the final root secret, cookie policy, session serializers, primary adapter, and optional secondary storage. If custom-session should project device-list entries, register `multisession.NewFactory` first and `customsession.NewFactory` afterward with `ShouldMutateListDeviceSessionsEndpoint:true`.

## How retained sessions work

Whenever an endpoint emits a new root session and records the corresponding new user/session, the after-hook writes an additional signed cookie named from the root session-cookie name and lowercased token. The cookie value contains the authoritative token plus a root-secret signature.

Signing into the same user again removes that user's older retained session rows and cookies, then retains the replacement. Sessions for other users remain. The configured maximum counts retained multi-session cookies in the current client, not all sessions stored for a user across every device.

If a new session would exceed the maximum, it remains the active root session but receives no retained multi-session cookie. It therefore does not appear in the device-session list and cannot be restored after switching away.

## HTTP routes

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| GET | `/multi-session/list-device-sessions` | No body | Array of `{session,user}` | Valid signed multi-session cookies; a primary session cookie is not required |
| POST | `/multi-session/set-active` | JSON `sessionToken` | `{session,user}` plus refreshed root cookies | Matching signed multi-session cookie; primary session is not required |
| POST | `/multi-session/revoke` | JSON `sessionToken` | `{"status":true}` | Current active session plus matching signed multi-session cookie |

The `sessionToken` body value selects the expected cookie name. It is not itself trusted as the session to activate or delete; the verified signed cookie value is authoritative.

### List retained accounts

```http
GET /api/auth/multi-session/list-device-sessions
Cookie: single-auth.session_token_multi-token-a=token-a.signature; single-auth.session_token_multi-token-b=token-b.signature
```

```json
[
  {"session":{"token":"token-a"},"user":{"id":"user-a","email":"a@example.com"}},
  {"session":{"token":"token-b"},"user":{"id":"user-b","email":"b@example.com"}}
]
```

Invalid signatures and missing/expired sessions are ignored. Results are deduplicated by user ID, and the list may be empty without producing an authorization error.

### Switch the active account

```http
POST /api/auth/multi-session/set-active
Content-Type: application/json
Cookie: single-auth.session_token_multi-token-a=token-a.signature

{"sessionToken":"token-a"}
```

The route refreshes normal root session/data cookies using the retained session. A valid signed don't-remember cookie preserves non-persistent cookie behavior. An expired target produces `INVALID_SESSION_TOKEN` and expires its multi-session cookie.

### Revoke a retained session

Revoking a non-active target deletes only that session and expires its multi-session cookie. Revoking the active target promotes the first remaining live retained session and refreshes root cookies. If no live alternative exists, the plugin clears the root session, session-data, don't-remember, optional account-data/OAuth-state, and chunk cookies.

The normal `/sign-out` after-hook verifies every retained cookie, deletes the corresponding sessions from primary or secondary storage, and expires those multi-session cookies. Forged cookies are ignored and are not used to delete another user's session.

## Options and defaults

`MaximumSessions` is the only public option. `nil` selects `5`; use `multisession.Int(n)` to preserve an explicit value. Zero and negative values are accepted for frozen compatibility but normally prevent useful retention. Use a positive production limit.

Cookie names, secure prefix, path, domain, `HttpOnly`, `SameSite`, `Secure`, and max age are resolved from the root cookie policy for every request. Dynamic base/domain configuration therefore does not need separate multi-session options.

## Errors

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `VALIDATION_ERROR` | Invalid JSON, missing `sessionToken`, or non-string token |
| 401 | `INVALID_SESSION_TOKEN` | No valid signed cookie for the selector, or target session is missing/expired |
| 401 | `UNAUTHORIZED` | Revoke has no current active session |
| 500 | `INTERNAL_SERVER_ERROR` | Session lookup, refresh, or deletion failed |

Validation happens before revoke resolves the current session, so a malformed body returns `VALIDATION_ERROR` even when unauthenticated.

## Direct API

Trusted code can call `listDeviceSessions`, `setActiveSession`, and `revokeDeviceSession` through `auth.API().Call`; there is no separately bound server service. Direct inputs must carry the same signed multi-session cookies, plus the active session cookie for revoke. Copy `Set-Cookie` output between calls manually.

Direct dispatch bypasses outer HTTP rate limiting but does not bypass endpoint signature/session checks. Do not construct or expose multi-session cookies from untrusted token strings.

## Storage, migrations, and concurrency

The plugin adds no model and needs no plugin migration. It uses root `session` records and the root session service, including secondary-storage-only configurations. Revocation and sign-out delete through those host services rather than assuming database rows exist.

List and set-active operations are safe under concurrent calls in the supported transports. Session revocation and same-user replacement use host batch operations, but a sequence spanning cookie emission and storage mutation is not a cross-request transaction. Simultaneous sign-in, switch, revoke, or sign-out responses can race in the caller's cookie store; serialize account-management UI actions when deterministic last-writer behavior matters.

## Security and troubleshooting

- A body token alone cannot activate or revoke a session. `INVALID_SESSION_TOKEN` means the matching signed cookie was absent, forged, or mapped to an expired/missing session.
- `List` returning `[]` while `/get-session` succeeds means the active session was not retained, often because the maximum was reached or multi-session was installed after that session was created.
- If switching does not persist, ensure the caller stores response cookies and accepts the auth server's domain, secure, and path attributes.
- Rotating the root secret invalidates existing multi-session cookie signatures. Users must sign in again to rebuild retained entries.
- Multi-session intentionally supports different users in one browser. Do not describe the body selector as same-user ownership; authority is possession of the signed retained cookie.
- Keep session tokens out of application logs even though cookie signatures prevent token substitution.

## Related pages

- [Custom session](./custom-session.md)
- [Direct API](../transports/direct-api.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Multi-session package reference](../reference/packages/plugins--multisession.md)

**Status:** implemented with cookie authority, secondary storage, concurrency, and all three server transports covered.
