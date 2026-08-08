---
title: "Legacy OIDC provider"
description: "Configure the legacy native OpenID Connect provider, client registration, consent, token claims, storage, and security policy."
---

Compatibility implementation of the Better Auth 1.6.26 OIDC provider surface.

> **Warning: Use OAuth provider for new deployments**
>
> `oidcprovider` is retained for compatibility. New authorization servers should use `oauthprovider`, which has stricter OAuth 2.1 behavior, broader lifecycle APIs, introspection, revocation, and refresh replay handling.

## Installation and ordering

Import `github.com/pers0na2dev/single-auth/plugins/oidcprovider`. `LoginPage` is required. Provide either `ConsentPage` or `GetConsentHTML` before a request can require consent.

When `UseJWTPlugin` is enabled, register `jwt` first so ID tokens use the root asymmetric signing keys and the advertised `/jwks` route exists. Without it, the compatibility implementation signs ID tokens with HS256 and each confidential client's secret. Do not combine this plugin with `oauthprovider` or `mcp`; they register conflicting `/oauth2/*` routes.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/jwt"
    "github.com/pers0na2dev/single-auth/plugins/oidcprovider"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"https://app.example.com"},
        PluginFactories: []singleauth.PluginFactory{
            jwt.NewFactory(jwt.Options{}),
            oidcprovider.NewFactory(oidcprovider.Options{
                LoginPage:                     "https://app.example.com/sign-in",
                ConsentPage:                   "https://app.example.com/oauth/consent",
                RequirePKCE:                   true,
                AllowPlainCodeChallengeMethod: false,
                UseJWTPlugin:                  true,
                StoreClientSecret:             oidcprovider.ClientSecretEncrypted,
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

All paths below are relative to `Options.BasePath`, which defaults to `/api/auth`.

## Register a client

The registration endpoint accepts RFC-style client metadata. With the default `AllowDynamicClientRegistration: false`, a root session is required. Setting it to true permits registration without a root session; it does not add a registration-access token or management lifecycle.

```http
POST /api/auth/oauth2/register HTTP/1.1
Content-Type: application/json
Cookie: better-auth.session_token=token.signature

{
  "client_name": "Legacy reporting client",
  "redirect_uris": ["https://client.example.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email offline_access"
}
```

```json
{
  "client_id": "generated-client-id",
  "client_secret": "generated-client-secret",
  "client_id_issued_at": 1786320000,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://client.example.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

The plaintext secret is returned once in a no-store response. Store it immediately. Registration rejects dangerous `javascript:`, `data:`, and `vbscript:` redirects, unsupported token authentication methods, inconsistent grant/response types, and malformed metadata.

The compatibility route does not issue a registration access token and has no update/delete client endpoints. For application-controlled clients, prefer `TrustedClients` or seed the `oauthApplication` model through an explicit administrative workflow.

## Trusted clients

`TrustedClients` are application-configured `oidcprovider.Client` values checked before database clients. They are useful for fixed first-party integrations and can set `SkipConsent`. They are not persisted or returned by the registration endpoint.

```go
oidcprovider.NewFactory(oidcprovider.Options{
    LoginPage:   "https://app.example.com/sign-in",
    ConsentPage: "https://app.example.com/oauth/consent",
    RequirePKCE: true,
    TrustedClients: []oidcprovider.Client{{
        ClientID:             "first-party-client",
        ClientSecret:         os.Getenv("OIDC_CLIENT_SECRET"),
        Type:                 "web",
        Name:                 "First-party client",
        RedirectURLs:         []string{"https://client.example.com/callback"},
        AuthenticationScheme: "client_secret_basic",
        SkipConsent:          true,
    }},
})
```

Treat `SkipConsent` as a trust decision. A matching client ID shadows a persisted record with the same ID.

## Authorization flow

### Start authorization

```text
GET /api/auth/oauth2/authorize
  ?client_id=generated-client-id
  &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback
  &response_type=code
  &scope=openid%20profile%20email%20offline_access
  &state=random-state
  &nonce=random-nonce
  &code_challenge=BASE64URL_SHA256_VERIFIER
  &code_challenge_method=S256
```

The endpoint validates the client, exact registered redirect URI, response type, scopes, prompt, and PKCE. If the user is not signed in, it stores the query in a signed, ten-minute `oidc_login_prompt` cookie and redirects to `LoginPage`. The root after-hook resumes the request after login by observing the new session cookie.

Supported prompts are `none`, `login`, `consent`, and `select_account`. `prompt=none` returns `login_required` or `consent_required` without showing UI. `max_age` can require a fresh login. Only the authorization-code response type is implemented even though the registration validator accepts preserved legacy metadata values.

The actual 1.6.26 compatibility default for `RequirePKCE` is `false`. Set it to `true` in production. A client with `Type: "public"` still requires a verifier at token exchange. Only S256 should be enabled; `AllowPlainCodeChallengeMethod` defaults to false.

### Consent

When `ConsentPage` is set, the browser is redirected with `consent_code`, `client_id`, and `scope`. The page submits an explicit decision while the root session is present:

```http
POST /api/auth/oauth2/consent HTTP/1.1
Content-Type: application/json
Cookie: better-auth.session_token=token.signature

{
  "accept": true,
  "consent_code": "code-from-consent-page"
}
```

```json
{
  "redirectURI": "https://client.example.com/callback?code=single-use-code&state=random-state"
}
```

The consent code may also come from the signed `oidc_consent_prompt` cookie. It is checked for expiry and consumed once. A denial returns a redirect URI with `access_denied`. Accepted scopes are persisted in `oauthConsent` and may allow a later request to skip consent.

If `ConsentPage` is empty, `GetConsentHTML` receives `ConsentHTMLInput` and must return the complete HTML document. Rendering is application code: escape all provider/client values and keep the POST action on the trusted auth origin.

### Exchange the code

```http
POST /api/auth/oauth2/token HTTP/1.1
Authorization: Basic BASE64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=generated-client-id&code=single-use-code&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&code_verifier=ORIGINAL_VERIFIER
```

```json
{
  "access_token": "opaque-access-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "opaque-refresh-token",
  "scope": "openid profile email offline_access",
  "id_token": "signed-id-token"
}
```

`openid` controls whether `id_token` is returned; `offline_access` controls whether `refresh_token` is returned. Confidential clients authenticate with Basic or body credentials. The authorization code is atomically consumed before issuance, so a concurrent replay cannot produce a second token response.

### Refresh

```http
POST /api/auth/oauth2/token HTTP/1.1
Authorization: Basic BASE64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=opaque-refresh-token&client_id=generated-client-id
```

The legacy implementation returns a new access token and a new refresh token with the same scopes. For preserved compatibility, the old refresh-token record is not atomically revoked and no replay-family detection is performed. Clients must avoid concurrent refreshes; security-sensitive deployments should migrate to `oauthprovider`, whose refresh tokens rotate and invalidate on replay.

## Endpoints

| Method | Path | Input | Result and authority |
| --- | --- | --- | --- |
| GET | `/.well-known/openid-configuration` | None | Public OpenID Provider metadata. |
| GET | `/oauth2/authorize` | Client, redirect, response type, scopes, state/nonce, optional PKCE/prompt | Root login and consent; redirects with code or protocol error. |
| POST | `/oauth2/consent` | `accept`, consent code/cookie | Authenticated resource owner; consumes consent prompt and returns redirect URI. |
| POST | `/oauth2/token` | Form code or refresh grant plus client authentication | No-store token response. |
| GET | `/oauth2/userinfo` | Bearer access token | Scope-filtered subject/profile/email claims. |
| POST | `/oauth2/register` | Client metadata | Session required by default; unauthenticated only when allowed. |
| GET | `/oauth2/client/:id` | Client ID path | Signed-in lookup returning display-safe `clientId`, `name`, and optional `icon`. |
| GET, POST | `/oauth2/endsession` | Optional hint/client/redirect/state plus current session | Deletes applicable access tokens/session or redirects after validation. |

The provider does not expose token introspection, token revocation, consent management, client update/rotation/deletion, PAR, device authorization, or client credentials. Use [OAuth provider](./oauth-provider.md) when those capabilities are required.

## Discovery and claims

Discovery advertises issuer, authorization, token, UserInfo, JWKS, registration, logout, scopes, response/grant types, authentication methods, S256, and supported claims. `Metadata` entries are applied last and can override built-in values. An override changes advertisement only; it does not implement a new grant, endpoint, signing algorithm, or validation rule.

`GetAdditionalUserInfoClaim` adds claims to both UserInfo and ID tokens. It receives the persisted user, granted scopes, and resolved client. Returned keys override normal user-derived claims in this preserved implementation, so never allow it to replace `sub`, audience, issuer, expiry, or other security claims with untrusted data.

UserInfo always returns `sub`. `profile` enables `name`, `picture`, `given_name`, and `family_name`; `email` enables `email` and `email_verified`.

## Logout behavior

`/oauth2/endsession` accepts `id_token_hint`, `client_id`, `post_logout_redirect_uri`, and `state`. A redirect requires a validated client/hint and a URI present in that client's registered redirect list. Cross-site logout must carry a valid hint for the current user or originate from a trusted/same-site context.

When a user is resolved, the endpoint deletes that user's legacy `oauthAccessToken` records. When a root session is present, it deletes the session and expires its cookie. This is broader than revoking one client token; account for it before using end-session from a multi-client application.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `LoginPage` | Required | Application login URL/path. |
| `ConsentPage` | Empty | External consent URL/path. |
| `GetConsentHTML` | None | Inline HTML renderer used when no consent page is configured. |
| `CodeExpiresIn` | 10 minutes | Authorization/consent code lifetime. |
| `AccessTokenExpiresIn` | 1 hour | Opaque access-token lifetime and ID-token expiry. |
| `RefreshTokenExpiresIn` | 7 days | Refresh-token lifetime. |
| Built-in `Scopes` | `openid`, `profile`, `email`, `offline_access` | Custom entries are appended. |
| `DefaultScope` | `openid` | Used when authorization omits scope. |
| `AllowDynamicClientRegistration` | `false` | When false, registration requires a root session; when true, it may be anonymous. |
| `RequirePKCE` | `false` | Global compatibility default; enable for production. |
| `AllowPlainCodeChallengeMethod` | `false` | Allows legacy `plain` only when explicitly enabled. |
| `StoreClientSecret` | `plain` | Persistence/verification mode for newly registered secrets. |
| `UseJWTPlugin` | `false` | Use root asymmetric JWT/JWKS instead of per-client HS256. |
| `TrustedClients` | Empty | Static clients resolved before storage. |
| `Metadata` | Empty | Discovery overrides. |

`GenerateClientID` and `GenerateClientSecret` replace cryptographic defaults. They may be called concurrently and must return unpredictable, collision-resistant values.

### Client-secret storage

| Mode | Constant | Notes |
| --- | --- | --- |
| Plain | `ClientSecretPlain` | Compatibility default; not recommended for database storage. |
| Hashed | `ClientSecretHashed` | One-way SHA-256-based comparison; suitable when recovery is unnecessary. |
| Encrypted | `ClientSecretEncrypted` | Uses root secret encryption/decryption. |
| Custom hash | `ClientSecretCustomHash` | Requires `HashClientSecret`. |
| Custom encryption | `ClientSecretCustomEncryption` | Requires both encrypt/decrypt callbacks. |

Changing modes does not transform existing rows. Migrate stored secrets before switching, or existing clients will fail authentication.

## Schema and migrations

The plugin adds:

- `oauthApplication`: client display data, transformed secret, redirects, type/authentication scheme, owner, flags, metadata, and timestamps;
- `oauthAccessToken`: opaque access/refresh values, expiries, client/user, scope string, and timestamps;
- `oauthConsent`: client/user, scope string, consent flag, and timestamps.

Authorization and consent codes use the core `verification` model. With `UseJWTPlugin`, the JWT plugin also adds `jwks`.

Register JWT first when used, then register OIDC before adapter construction and apply the merged schema. With a root SQL constructor, run `auth.RunMigrationsContext(ctx)`. Moving to `oauthprovider` is a semantic data migration: its `oauthClient`, separate access/refresh models, transformed token values, grants, consent representation, and replay-family behavior differ. See [Migrations](../storage/migrations.md) and [OAuth/OIDC server protocol](../protocols/oauth-and-oidc-server.md).

## Direct API

The root factory exposes no bound service object. Trusted code can invoke
endpoint operation names with `auth.API().Call`; direct dispatch bypasses HTTP
origin checks and rate limiting, so retain the same session and redirect
policy.

`New` and `MustNew` build an explicitly wired transport-neutral plugin. `ProviderMetadata` builds a discovery document without registering routes. These lower-level APIs require the caller to supply the full runtime contract and should not be exposed as unauthenticated administration helpers.

## Security, replay, and concurrency

- Authorization and consent codes use atomic consume operations and are single-use across instances sharing primary storage.
- Refresh tokens are a legacy exception: they are not consumed or revoked on refresh and have no family replay detection. Do not issue concurrent refresh requests.
- Enable `RequirePKCE`; keep plain challenges disabled; always send a random state and nonce from the client.
- Redirect URIs must match a registered value. The authorization endpoint refuses to redirect to an unvalidated URI.
- Prefer hashed/encrypted client-secret storage and `UseJWTPlugin`. Plain storage and per-client HS256 exist for compatibility.
- Root sessions, verification records, clients, tokens, and consents must use shared primary storage in multi-replica deployments.
- `Metadata` and custom claim callbacks are trusted server configuration. Do not let tenant/user input advertise or overwrite security-critical protocol fields.

## Troubleshooting

- `No consent page provided`: configure `ConsentPage`, implement `GetConsentHTML`, or mark only a genuinely trusted static client with `SkipConsent`.
- Login returns to the app but authorization does not resume: keep the signed login-prompt cookie, use the same root secret across instances, and ensure the login response sets the normal session cookie.
- `invalid redirect URI`: compare the exact registered string and reject application-side normalization surprises.
- `pkce is required` or `code verification failed`: use S256 and retain the original verifier for the matching authorization request.
- ID tokens fail asymmetric verification: set `UseJWTPlugin: true`, register JWT first, and fetch the advertised JWKS URL.
- Existing clients fail after changing secret mode: migrate their stored secret representation or temporarily retain the original mode.
- Duplicate refresh responses: the legacy refresh token remains reusable; serialize refresh client-side and migrate to `oauthprovider` for rotation/replay enforcement.

## Related pages

- [OAuth provider](./oauth-provider.md)
- [JWT](./jwt.md)
- [OAuth and OIDC server protocol](../protocols/oauth-and-oidc-server.md)
- [Protocol security boundaries](../protocols/security-boundaries.md)
- [Go package reference](../reference/packages/plugins--oidcprovider.md)

**Status:** compatibility-complete for the applicable preserved Go server surface; retained legacy security behavior is documented above.
