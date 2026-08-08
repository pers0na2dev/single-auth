---
title: "Sessions"
---

Session authority, refresh, freshness, cookies, cache strategies, secondary storage, and revocation.

A session consists of an unguessable 32-character token stored in the session record and a signed browser cookie containing `token.signature`. The signature prevents an attacker from substituting a token before storage lookup.

## Defaults

| Setting | Default |
| --- | --- |
| Logical lifetime | 7 days |
| Refresh age | 24 hours |
| Fresh-session age | 24 hours |
| Stateful storage | Enabled |
| Automatic refresh | Enabled |
| Deferred refresh | Disabled |
| Cookie cache | Disabled |
| Cookie cache lifetime | 5 minutes |
| Cookie cache strategy | `compact` |
| Cookie cache version | `1` |

`Session.UpdateAge` and `Session.FreshAge` are pointers because zero is meaningful. An omitted pointer selects 24 hours. Explicit zero makes a stored session eligible for refresh on every read or makes every valid session fresh, respectively.

```go
updateAge := 6 * time.Hour
freshAge := 30 * time.Minute

Session: singleauth.SessionOptions{
    ExpiresIn: 30 * 24 * time.Hour,
    UpdateAge: &updateAge,
    FreshAge:  &freshAge,
},
```

## Session creation

Credential and social sign-in create a session record with:

- generated `id` and 32-character random `token`;
- `userId`;
- `createdAt` and `updatedAt` from the configured clock;
- `expiresAt = now + ExpiresIn`;
- resolved client `ipAddress` and request `userAgent`;
- configured/plugin session fields.

`rememberMe=false` changes the logical lifetime to 24 hours regardless of `ExpiresIn`, removes `Max-Age` from the token cookie, and writes the signed `dont_remember` cookie. The database expiry still enforces the 24-hour limit.

## Reading and refreshing

`GET /get-session` always returns `Cache-Control: no-store` and `Pragma: no-cache`. An absent, invalid, missing, or expired session returns JSON `null`, not 401. Invalid or expired state causes the relevant cookies to be expired.

For a stored session, refresh becomes due at:

```text
expiresAt - ExpiresIn + UpdateAge
```

When due, the runtime writes `updatedAt=now`, extends `expiresAt` by `ExpiresIn`, and reissues cookies. Refresh does not occur when:

- `DisableSessionRefresh` is true;
- the request asks to disable refresh;
- `rememberMe=false` was used;
- endpoint middleware marked the request to skip refresh;
- deferred refresh is enabled and the current request is GET.

The query flags are Better Auth boolean-coerced: any non-empty first value is true, including `?disableRefresh=false` and `?disableCookieCache=0`. Omit the parameter or pass an empty value to keep it false.

### Deferred refresh

With `DeferSessionRefresh`, GET remains read-only. Its response includes `needsRefresh` when the backing session is due. A POST to the same route performs the write-side refresh.

Without that option, `POST /get-session` returns status 405 and code `METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED`.

```go
Session: singleauth.SessionOptions{
    DeferSessionRefresh: true,
},
```

## Stateful and stateless modes

The default `Stateless=false` makes primary or secondary storage authoritative. `Stateless=true` makes the signed session-data cookie authoritative for regular reads.

Sensitive stateful endpoints use authoritative lookup and deliberately bypass the session-data cache so that a revoked database/secondary session cannot remain valid through a stale cookie. In stateless mode, there is no server-side authority to consult, so plan revocation, versioning, and cache lifetime accordingly.

## Session cookie cache

Enable the cache when avoiding a storage read is worth accepting its bounded staleness:

```go
Session: singleauth.SessionOptions{
    CookieCache: singleauth.CookieCacheOptions{
        Enabled:  true,
        MaxAge:   2 * time.Minute,
        Strategy: "jwe",
        Version:  "2026-08-authz-v2",
    },
},
```

Strategies:

| Strategy | Format |
| --- | --- |
| `compact` | Base64url envelope containing JSON session/user data, expiry, and URL signature. This is the default. |
| `jwt` | Signed JWT containing session, user, update time, and version. |
| `jwe` | Encrypted JWE using audience/context `better-auth-session`. |

Every strategy validates token integrity, cookie expiry, embedded session expiry, user/session structure, and version. Increment `Version` whenever cached authorization data or additional-field semantics change.

`RefreshCache` and `RefreshCacheUpdateAge` apply only to stateless mode. If enabled without an explicit age, the threshold is floor of 20% of `MaxAge` in whole seconds. Stateful mode ignores stateless cache refresh settings.

Cache values larger than one cookie are split into numbered cookies. The maximum serialized cookie size is 4,050 bytes and the maximum is 100 chunks. Writing a new value first expires stale bare/chunked values; an impossible payload is skipped and logged rather than truncated.

## Cookie names and attributes

Default names are:

| Purpose | Name |
| --- | --- |
| Session token | `better-auth.session_token` |
| Session cache | `better-auth.session_data` |
| Do-not-remember marker | `better-auth.dont_remember` |
| Short OAuth/plugin state | `better-auth.state` |
| OAuth state | `better-auth.oauth_state` |
| Account-data cache | `better-auth.account_data` |

Secure mode prepends `__Secure-`. Default attributes are `Path=/`, `HttpOnly`, and `SameSite=Lax`; `Secure` is derived from configuration. `Advanced.DefaultCookieAttributes` changes all cookies and `Advanced.Cookies` changes a canonical key such as `session_token` or `session_data`. Pointer fields let an override explicitly turn an attribute off.

Cross-subdomain cookies use `Advanced.CrossSubDomainCookies`. With a static URL, an empty domain is derived from its hostname. With a dynamic URL, the domain is resolved per allowed request. Without either source, construction fails.

## Secondary session storage

With `SecondaryStorage` or `SecondaryValueStorage`, the secondary backend is authoritative for sessions by default. `StoreSessionInDatabase` keeps an additional primary-database copy. `PreserveSessionInDatabase` retains that copy after revocation for audit use, while the secondary entry is still deleted.

Session list and revocation operations use the authoritative backend. Updates also refresh cached user data. A secondary store must honor expiry seconds and be safe for concurrent access.

The two secondary interfaces are mutually exclusive:

- `SecondaryStorage.Get` returns the canonical string;
- `SecondaryValueStorage.GetValue` supports wrappers that parse JSON into an object before returning it.

## Session-management routes

- `GET /list-sessions` requires a valid, fresh session and returns only unexpired sessions owned by the user.
- `POST /revoke-session` requires authoritative authentication and a target token. A token owned by another user is not revoked, but the response remains `{status:true}`.
- `POST /revoke-sessions` revokes every session for the current user, including the current one.
- `POST /revoke-other-sessions` retains only the current token.
- `POST /update-session` requires a session and updates only configured session fields marked as input. It rejects an empty effective update and reissues cookies.
- `POST /sign-out` is optional-auth: it removes the current token when valid, expires session cookies, and returns `{success:true}` even without a session.

List and unlink operations also check freshness. Revocation, password change, password verification, account token operations, email change, and deletion use authoritative session lookup where applicable.

## Server-side cookie propagation

Direct API calls return `Set-Cookie` in `contract.Headers`, but they do not maintain a cookie jar. Use `cookies.ApplySetCookies` when a later call must carry the issued session:

```go
signup, err := auth.API().SignUpEmail(ctx, singleauth.SignUpEmailInput{
    Name:     "Ada Lovelace",
    Email:    "ada@example.com",
    Password: "correct-horse-battery-staple",
})
if err != nil {
    return err
}

cookieHeader := cookies.ApplySetCookies("", signup.Headers.Values("Set-Cookie"))
headers := contract.NewHeaders(contract.HeaderField{
    Name:  "Cookie",
    Value: cookieHeader,
})

session, err := auth.API().GetSession(ctx, singleauth.GetSessionInput{
    Headers: headers,
})
```

For read-only inspection, `GetSessionCookie`, `GetSessionCookieFromHTTPRequest`, and `GetSessionCookieFromHeaderGetter` return the semantic cookie value. `GetCookieCache` verifies and decodes session data; a missing or invalid cookie returns nil, while a present cookie without an explicit or `SINGLE_AUTH_SECRET` secret fails closed.
