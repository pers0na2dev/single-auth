---
title: "HTTP routes"
description: "Complete core route, method, authentication, input, response, and direct-name reference."
---

Complete core route, method, authentication, input, response, and direct-name reference.

Every path in this page is relative to `Options.BasePath`, which defaults to `/api/auth`. For example, `/sign-in/email` is normally served at `/api/auth/sign-in/email`.

The same route registry is used by `net/http`, direct `fasthttp`, and Fiber. An unsupported method on a known path returns 405. An unknown path, disabled path, or HTTP attempt to reach a server-only endpoint returns 404.

## Authentication labels

| Label | Meaning |
| --- | --- |
| Public | No session lookup is required. |
| Optional | Uses a valid signed session when present; absence is allowed. |
| Session | Requires a signed token and valid session. A stateful `session_data` cache may satisfy the read. |
| Authoritative | Requires a signed token and bypasses the stateful cookie cache. |
| Fresh | Requires a session whose `createdAt` is younger than `Session.FreshAge`; zero disables the age limit. |

## Complete route table

| Method and path | Direct API name | Auth | Input and success result |
| --- | --- | --- | --- |
| `GET /ok` | `ok` | Public | No input; `{ok:true}`. |
| `GET /error` | `error` | Public | Query `error`, `error_description`; HTML or configured redirect. |
| `POST /sign-up/email` | `signUpEmail` | Public | Body `name`, `email`, `password`, optional `image`, `callbackURL`, `rememberMe`, additional user input fields; `{token,user}`. |
| `POST /sign-in/email` | `signInEmail` | Public | Body `email`, `password`, optional `callbackURL`, `rememberMe`; `{redirect,token,url?,user}`. |
| `POST /sign-in/social` | `signInSocial` | Public | Provider/OAuth body; authorization URL or direct ID-token session result. |
| `GET` or `POST /callback/:id` | `callbackOAuth` | Public | Provider callback query/form; redirects after atomic state consumption. |
| `GET /get-session` | `getSession` | Optional | Query `disableCookieCache`, `disableRefresh`; session/user object or JSON null. |
| `POST /get-session` | `getSession` | Optional | Only when deferred refresh is enabled; session/user object or JSON null. |
| `GET /list-sessions` | `listSessions` | Session + fresh | No input; array of active sessions. |
| `POST /revoke-session` | `revokeSession` | Authoritative | Body `token`; `{status:true}`. |
| `POST /revoke-sessions` | `revokeSessions` | Authoritative | Empty object; `{status:true}`. |
| `POST /revoke-other-sessions` | `revokeOtherSessions` | Authoritative | Empty object; `{status:true}`. |
| `POST /update-session` | `updateSession` | Session | Configured session input fields; `{session}`. |
| `POST /update-user` | `updateUser` | Session | `name`, `image`, configured user input fields; `{status:true}`. |
| `POST /change-password` | `changePassword` | Authoritative | `newPassword`, `currentPassword`, optional `revokeOtherSessions`; `{token,user}`. |
| no HTTP route | `setPassword` | Authoritative direct call | `newPassword`; `{status:true}`. Server-only. |
| `POST /request-password-reset` | `requestPasswordReset` | Public | `email`, optional `redirectTo`; generic `{status,message}`. |
| `GET /reset-password/:token` | `requestPasswordResetCallback` | Public | Query `callbackURL`; redirect with `token` or `error`. |
| `POST /reset-password` | `resetPassword` | Public | `newPassword`, token in body or query; `{status:true}`. |
| `POST /verify-password` | `verifyPassword` | Authoritative | `password`; `{status:true}`. |
| `POST /send-verification-email` | `sendVerificationEmail` | Optional | `email`, optional `callbackURL`; `{status:true}`. |
| `GET /verify-email` | `verifyEmail` | Public | Query `token`, optional `callbackURL`; redirect or `{status,user}`. |
| `GET /list-accounts` | `listUserAccounts` | Session | No input; array of public accounts with `scopes`. |
| `POST /link-social` | `linkSocialAccount` | Session | Provider/OAuth body; `{url,status?,redirect}`. |
| `POST /get-access-token` | `getAccessToken` | Authoritative | `providerId`, optional `accountId`; access token result. |
| `POST /refresh-token` | `refreshToken` | Authoritative | `providerId`, optional `accountId`; refreshed token result. |
| `GET /account-info` | `accountInfo` | Authoritative | Query optional `providerId`, `accountId`; `{user,data}` or null. |
| `POST /unlink-account` | `unlinkAccount` | Session + fresh | `providerId`, optional `accountId`; `{status:true}`. |
| `POST /delete-user` | `deleteUser` | Authoritative | Optional `password`, `token`, `callbackURL`; `{success,message}`. |
| `GET /delete-user/callback` | `deleteUserCallback` | Authoritative | Query `token`, optional `callbackURL`; redirect or `{success,message}`. |
| `POST /change-email` | `changeEmail` | Authoritative | `newEmail`, optional `callbackURL`; `{status:true}`. |
| `POST /sign-out` | `signOut` | Optional | Empty object; `{success:true}` and expired cookies. |

## Shared request rules

Object bodies accept JSON or `application/x-www-form-urlencoded`. A missing/empty object body on an object endpoint returns `BODY_MUST_BE_AN_OBJECT`. Malformed JSON/form data, wrong field types, missing required fields, and disallowed schema inputs return typed 4xx errors.

Cookie-authenticated unsafe HTTP requests must pass origin/CSRF validation. Redirect-bearing fields must match a trusted origin or safe relative path. These HTTP-only gates do not run for `auth.API()`/`Invoke`.

All normal errors use JSON `{code,message}` unless a protocol endpoint supplies a standardized wire body or a browser flow redirects. Unknown server errors are redacted to `500 INTERNAL_SERVER_ERROR`.

Responses may contain multiple `Set-Cookie` lines. Never comma-join them. Session responses use `Cache-Control: no-store` where applicable.

## Health and error

### `GET /ok`

Returns status 200 and:

```json
{"ok":true}
```

Use it to verify the auth mount and transport, not as a database/provider health check; the handler does not perform external dependency probes.

### `GET /error`

Query:

- `error`: safe alphanumeric/underscore/hyphen-style code; missing or unsafe becomes `UNKNOWN`;
- `error_description`: optional escaped display text.

`OnAPIError.ErrorURL` redirects to the configured URL. Otherwise explicit production mode redirects to the application root unless `CustomizeDefaultErrorPage` is true. Non-production/default-customized mode renders escaped HTML.

## Credential routes

### `POST /sign-up/email`

Required strings: `name`, valid `email`, and non-empty `password`. Password length is 8–128 UTF-16 code units by default. Email is stored lowercase.

Optional:

- `image`: string or null;
- `callbackURL`: verification callback destination;
- `rememberMe`: false selects a 24-hour logical session plus browser-session token cookie;
- user schema fields marked as input.

Disabled credentials or sign-up return `EMAIL_PASSWORD_SIGN_UP_DISABLED`. A new user and credential account are created atomically. `token` is null when verification is required or auto sign-in is explicitly disabled. Duplicate behavior is intentionally enumeration-resistant when those modes are active.

### `POST /sign-in/email`

Required `email` and `password`; optional `callbackURL` and `rememberMe`. Missing account and wrong password both return `INVALID_EMAIL_OR_PASSWORD`. Required unverified email returns 403 `EMAIL_NOT_VERIFIED` and may send a new message when configured.

A non-empty callback sets `redirect:true`, returns `url`, and emits `Location`; otherwise redirect is false.

### `POST /change-password`

Requires authoritative session, `newPassword`, and `currentPassword`. Optional `revokeOtherSessions=true` actually revokes all sessions, then creates and returns a replacement session token and cookies. Without it, response `token` is null.

### `setPassword` (direct only)

The endpoint has no HTTP path and is guarded by `ServerOnly`. It adds a credential account to an authenticated account that has no password. Existing password state returns `PASSWORD_ALREADY_SET`.

### Password reset routes

`/request-password-reset` is disabled unless `SendResetPassword` is configured. Existing and unknown users receive the exact same successful message. The callback route peeks without consuming; `/reset-password` atomically consumes. Reset token lifetime defaults to one hour. `RevokeSessionsOnReset` removes all user sessions after success.

### `POST /verify-password`

Checks the current user's credential account using authoritative session state. It returns `{status:true}` or `INVALID_PASSWORD` without returning the hash or account details.

## Session routes

### `GET|POST /get-session`

Missing/invalid/expired sessions return JSON null with status 200. A successful result is:

```json
{
  "session": {
    "id": "session_01J5P8Z4X7M2N6Q9R3T1V0WABC",
    "userId": "user_01J5P8R1A4B7C9D2E6F0G3HJKL",
    "token": "x1J7pQ4nV8cM2zK6sR9tW3yA5bD0fG2h",
    "expiresAt": "2026-08-17T00:00:00Z",
    "createdAt": "2026-08-10T00:00:00Z",
    "updatedAt": "2026-08-10T00:00:00Z",
    "ipAddress": "203.0.113.42",
    "userAgent": "Mozilla/5.0"
  },
  "user": {
    "id": "user_01J5P8R1A4B7C9D2E6F0G3HJKL",
    "name": "Ada",
    "email": "ada@example.com",
    "emailVerified": true,
    "createdAt": "2026-07-01T12:00:00Z",
    "updatedAt": "2026-08-09T18:30:00Z"
  }
}
```

Configured/plugin public fields are included. With deferred refresh, GET may also return `needsRefresh`. POST is accepted only when `Session.DeferSessionRefresh` is true.

Query coercion follows truthiness: every non-empty first value is true, even the strings `false` and `0`.

### List and revoke

`list-sessions` requires freshness and filters expired rows. `revoke-session` silently succeeds for a missing token or one not owned by the current user. `revoke-sessions` includes the current session. `revoke-other-sessions` keeps the current token.

### `POST /update-session`

Only configured session schema fields marked as input are considered. Core ownership/token/expiry/IP/user-agent/timestamp fields cannot be set through this endpoint. An empty effective update returns `No fields to update`. Success reissues cookies.

### `POST /sign-out`

Deletes the current stored token if it is valid, then expires token/cache/do-not-remember cookies. It remains idempotently successful without a session.

## User and email routes

### `POST /update-user`

Accepts `name`, `image`, and configured user inputs. A truthy `email` field is rejected with `EMAIL_CAN_NOT_BE_UPDATED`. An empty effective update fails. Secondary cached user data and current cookies are refreshed.

### Verification routes

`send-verification-email` requires a configured sender. With a session, email must match and remain unverified. Without a session it uses a minimum 500 ms anti-enumeration path for unknown/already-verified addresses.

`verify-email` validates signed JWT expiry and claims. It updates `emailVerified`, executes before/after callbacks, optionally signs the user in, then redirects or returns success. Invalid callback flows append `error=<code>` when a callback was provided.

### `POST /change-email`

Disabled by default. It requires authoritative session state. Depending on configuration, it immediately changes an unverified address, sends verification to the new address, or uses old-address confirmation followed by new-address verification. Existing target email returns generic success.

### Delete routes

Disabled deletion routes return 404. Deletion requires an authoritative session and one of password proof, a single-use deletion token, configured email confirmation, or a fresh-enough session according to the selected flow. Actual deletion removes sessions, accounts, and user data, then expires cookies.

The callback also requires the current session, so a forwarded token alone is insufficient.

## Social and account routes

### Social request body

`sign-in/social` and `link-social` share these fields:

- required `provider`;
- optional `callbackURL`, `errorCallbackURL`, `newUserCallbackURL`;
- optional boolean `disableRedirect` and `requestSignUp`;
- optional string array `scopes`;
- optional `additionalData` object;
- sign-in-only `loginHint`;
- optional `idToken` object.

The ID-token object requires `token` and may contain `accessToken`, `refreshToken`, `nonce`, `expiresAt`, `scopes`, and `user`. Provider support and token verification are mandatory.

Redirect mode returns an authorization URL. Direct ID-token sign-in returns session token/user with `url:null` and `redirect:false`.

### OAuth callback

The provider ID comes from `:id`. GET reads query values. POST accepts callback form/object values and merges recognized callback keys. Database/secondary state and its signed cookie binding are validated and atomically consumed before account/session effects. Cookie strategy validates encrypted state and expires the cookie in the response, but has no server-side consumed marker for a copied cookie. Success/error destinations come only from validated state.

### Accounts and tokens

`list-accounts` returns account objects with `scopes` array. `link-social` requires the current user and linking policy. `unlink-account` additionally requires a fresh session and refuses the last login method unless explicitly allowed.

Token and account-info HTTP routes ignore any attempted `userId` body/query shortcut and require the authenticated user's authoritative session. Only a direct call with no cookie/authorization headers may use its typed `UserID` field.

`get-access-token` may automatically refresh a token with less than five seconds remaining. `refresh-token` always requires refresh support and a stored refresh token. `account-info` obtains a valid access token and calls the configured provider user-info implementation.

## Direct API correspondence

The `Direct API name` column is the name accepted by `auth.Invoke` and `auth.API().Call`, not the HTTP path. Direct invocation runs endpoint `Use`, user/plugin before hooks, the handler, and user/plugin after hooks. It does not run HTTP rate limiting, origin/CSRF or other path middleware, plugin `OnRequest`, plugin `OnResponse`, body-size transport limits, or transport error observers.

Typed direct methods expose the same names through:

```text
SignUpEmail, SignInEmail, SignInSocial, CallbackOAuth, GetSession, SignOut,
ListSessions, RevokeSession, RevokeSessions, RevokeOtherSessions, UpdateSession,
UpdateUser, ChangePassword, SetPassword, RequestPasswordReset,
RequestPasswordResetCallback, ResetPassword, VerifyPassword,
SendVerificationEmail, VerifyEmail, ListUserAccounts, LinkSocialAccount,
GetAccessToken, RefreshToken, AccountInfo, UnlinkAccount, DeleteUser,
DeleteUserCallback, ChangeEmail
```

`Call` is the generic escape hatch. It accepts method, scheme, host, ordered headers, JSON body, query, path parameters, and request-local values. JSON decoding uses `json.Decoder.UseNumber`. Always propagate `Set-Cookie` and `Location` when adapting a direct result to a browser.
