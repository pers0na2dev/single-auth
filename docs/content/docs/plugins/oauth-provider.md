---
title: "OAuth provider"
description: "Run the native OAuth authorization server with clients, consent, PKCE, tokens, userinfo, revocation, OIDC, and MCP integration."
---

Run a native OAuth 2.1 and OpenID Connect authorization server with client registration and management, authorization and consent, token issuance and rotation, introspection, revocation, UserInfo, discovery, and RP-initiated logout.

## Installation and ordering

Import `github.com/pers0na2dev/single-auth/plugins/oauthprovider`. This is the recommended authorization-server implementation for new deployments.

The normal configuration composes `github.com/pers0na2dev/single-auth/plugins/jwt`; register the JWT factory first. Set `DisableJWTPlugin` only for a deliberate compatibility deployment that accepts symmetric ID tokens and opaque access tokens. The OAuth provider owns `/oauth2/*` authorization-server routes, so do not register it with `oidcprovider` or `mcp` in the same auth instance.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/jwt"
    "github.com/pers0na2dev/single-auth/plugins/oauthprovider"
)

func main() {
    providerFactory := oauthprovider.NewFactory(oauthprovider.Options{
        LoginPage:   "https://app.example.com/sign-in",
        ConsentPage: "https://app.example.com/oauth/consent",
        Scopes:      []string{"openid", "profile", "email", "offline_access", "documents:read"},
        GrantTypes: []oauthprovider.GrantType{
            oauthprovider.GrantTypeAuthorizationCode,
            oauthprovider.GrantTypeRefreshToken,
            oauthprovider.GrantTypeClientCredentials,
        },
        ValidAudiences: []string{"https://api.example.com"},
        AllowDynamicClientRegistration: true,
    })

    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"https://app.example.com"},
        PluginFactories: []singleauth.PluginFactory{
            jwt.NewFactory(jwt.Options{}),
            providerFactory,
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    if _, err := providerFactory.Service(); err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

`LoginPage` and `ConsentPage` are required. They may be absolute trusted URLs or application paths. All endpoint paths below are relative to `Options.BasePath`, which defaults to `/api/auth`.

## Authorization-code flow

### 1. Register or create a client

For a session-owned confidential web client, call the management endpoint:

```http
POST /api/auth/oauth2/create-client HTTP/1.1
Content-Type: application/json
Cookie: better-auth.session_token=token.signature

{
  "client_name": "Acme dashboard",
  "redirect_uris": ["https://client.example.com/callback"],
  "post_logout_redirect_uris": ["https://client.example.com/signed-out"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email offline_access documents:read",
  "require_pkce": true,
  "enable_end_session": true
}
```

```json
{
  "client_id": "generated-client-id",
  "client_secret": "generated-client-secret",
  "client_secret_expires_at": 0,
  "client_name": "Acme dashboard",
  "redirect_uris": ["https://client.example.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

The plaintext secret is returned only when the client is created or rotated. Store it immediately. Public native/browser clients use `token_endpoint_auth_method: "none"` and receive no secret.

Dynamic registration uses `POST /oauth2/register` and RFC 7591 field names. It is disabled by default. When unauthenticated registration is separately enabled, the result is always a public PKCE client: it cannot request `client_credentials`, and it cannot disable PKCE.

### 2. Start authorization

Generate a high-entropy verifier and its base64url SHA-256 challenge, then redirect the resource owner's browser:

```text
GET /api/auth/oauth2/authorize
  ?client_id=generated-client-id
  &redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback
  &response_type=code
  &scope=openid%20profile%20email%20offline_access%20documents%3Aread
  &state=random-state
  &nonce=random-nonce
  &code_challenge=BASE64URL_SHA256_VERIFIER
  &code_challenge_method=S256
```

The server validates the client, exact redirect URI, response type, scopes, and PKCE before showing application UI. If no root session exists it redirects to `LoginPage`. If consent is needed it redirects to `ConsentPage`. Both redirects receive a signed `oauth_query` value; preserve it unchanged.

Supported prompt values are `none`, `consent`, `login`, `create`, and `select_account`. `none` cannot be combined with another prompt. A `request_uri` is rejected unless `RequestURIResolver` resolves it from trusted storage.

### 3. Submit consent or continue login

The consent page posts the signed query and an explicit decision:

```http
POST /api/auth/oauth2/consent HTTP/1.1
Content-Type: application/json
Cookie: better-auth.session_token=token.signature

{
  "accept": true,
  "oauth_query": "signed-query-from-consent-page",
  "scope": "openid profile email offline_access documents:read"
}
```

Accepted scopes must be a subset of the originally requested scopes. A denial returns a redirect URL carrying `access_denied`. `POST /oauth2/continue` accepts the same signed `oauth_query` after login/account-selection UI and resumes the authorization request. Signed queries expire after ten minutes and are bound to the root secret.

On success, the browser is redirected to the registered client URI with `code`, the original `state`, and issuer identification.

### 4. Exchange the code

Use form encoding and authenticate the client with HTTP Basic unless it is public:

```http
POST /api/auth/oauth2/token HTTP/1.1
Authorization: Basic BASE64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=generated-client-id&code=authorization-code&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&code_verifier=ORIGINAL_VERIFIER
```

```json
{
  "access_token": "jwt-or-opaque-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "opaque-refresh-token",
  "scope": "openid profile email offline_access documents:read",
  "id_token": "signed-id-token"
}
```

An ID token is returned for `openid`. A refresh token is returned only when `offline_access` was granted and the client permits `refresh_token`. The `resource` parameter selects an audience only when it appears in `ValidAudiences`.

## Token grants

| Grant | Requirements | Result |
| --- | --- | --- |
| `authorization_code` | Exact client/redirect match; single-use code; S256 verifier when required; active root session | User access token, optional ID token, optional rotating refresh token. |
| `refresh_token` | Same client; unexpired, unrevoked token; scope can only narrow | New access token and a replacement refresh token. The old token is revoked atomically. |
| `client_credentials` | Confidential client with the grant and secret; no OpenID/user scopes | M2M access token for configured non-user scopes. |

Public clients always require PKCE. A client with no explicit `requirePKCE` value defaults to PKCE. `offline_access` also requires PKCE. Only `S256` is supported.

Protocol failures use standard bodies:

```json
{
  "error": "invalid_grant",
  "error_description": "invalid code"
}
```

Authorization failures are redirected only after the redirect URI has been authenticated. Invalid or missing client/redirect inputs are handled locally to avoid open redirects.

## Protocol endpoints

| Method | Path | Input | Result and authority |
| --- | --- | --- | --- |
| GET | `/oauth2/authorize` | OAuth authorization query | Validates first, then root login/consent; redirects with code or protocol error. |
| POST | `/oauth2/consent` | `accept`, signed `oauth_query`, optional narrowed scope | Authenticated resource owner; returns client redirect details. |
| POST | `/oauth2/continue` | Signed `oauth_query` | Authenticated resource owner; resumes login or account-selection prompts. |
| POST | `/oauth2/token` | Form-encoded code, refresh, or client-credentials grant | Authenticated client/public PKCE client; no-store token response. |
| POST | `/oauth2/introspect` | `token`, optional `token_type_hint`, client authentication | Returns `active:false` or claims only for a token owned by that client. |
| POST | `/oauth2/revoke` | `token`, optional `token_type_hint`, client authentication | Revokes an owned access/refresh token; JWT revocation uses persisted token/session state. |
| GET, POST | `/oauth2/userinfo` | Bearer access token | Returns claims allowed by token scopes. |
| GET | `/oauth2/end-session` | Session and/or `id_token_hint`, optional client/registered redirect/state | Deletes applicable server session/token state or redirects after validation. |
| POST | `/oauth2/register` | RFC client metadata | Dynamic registration when enabled. |
| GET, HEAD | `/.well-known/oauth-authorization-server` | None | OAuth Authorization Server metadata. |
| GET, HEAD | `/.well-known/openid-configuration` | None | OpenID Provider metadata when OpenID is configured. |

Metadata is served at issuer-correct well-known paths, including both RFC 8414 authorization-server placements when the issuer contains a path: `/.well-known/oauth-authorization-server/{issuer-path}` and `{issuer-path}/.well-known/oauth-authorization-server`. It advertises actual configured endpoints, grants, scopes, claims, PKCE, token authentication methods, and JWKS behavior.

## Introspection, revocation, UserInfo, and logout

### Introspect

```http
POST /api/auth/oauth2/introspect HTTP/1.1
Authorization: Basic BASE64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=ACCESS_TOKEN&token_type_hint=access_token
```

An active response can include `active`, `client_id`, `sub`, `scope`, `token_type`, `exp`, `iat`, `iss`, and audience. Invalid, expired, revoked, or foreign-client tokens are reported as inactive without disclosing their owner.

### Revoke

Send the same client authentication to `/oauth2/revoke` with `token`. Revoking a refresh token invalidates its family. Revoking opaque access tokens updates storage; JWT access-token validity is derived from signature/claims plus the persisted authorization state used by the server.

### UserInfo

```http
GET /api/auth/oauth2/userinfo HTTP/1.1
Authorization: Bearer ACCESS_TOKEN
```

The base response always has `sub`. `profile` enables profile claims and `email` enables email claims. `CustomUserInfoClaims` may add application claims, but should not use untrusted request values as authority.

### End session

`/oauth2/end-session` accepts a valid `id_token_hint` and a client-registered `post_logout_redirect_uri`. A supplied `client_id` must match the hint audience. The client must opt into end-session support. Redirect state is echoed only after the redirect URI is authenticated.

## Management routes

### OAuth clients

| Method | Path | Input/result |
| --- | --- | --- |
| POST | `/oauth2/create-client` | Session-owned RFC client metadata; returns 201 and a one-time secret for confidential clients. |
| GET | `/oauth2/get-client?client_id=...` | Owner/reference-scoped complete metadata without secret. |
| GET | `/oauth2/public-client?client_id=...` | Public safe metadata only; omits redirect URIs, scopes, grants, owner/reference, and custom metadata. |
| GET | `/oauth2/get-clients` | All clients owned by the session user or resolved reference. |
| POST | `/oauth2/update-client` | `{client_id,update:{...}}`; client ID/secret cannot change, and confidential clients cannot become public. |
| POST | `/oauth2/client/rotate-secret` | `{client_id}`; confidential owner only, returns the new secret once. |
| POST | `/oauth2/delete-client` | `{client_id}`; owner/reference-scoped deletion. |

All routes except `public-client` require a root session, ownership or `ClientReference` match, and approval from `ClientPrivileges` when configured. Entries named in `CachedTrustedClients` are immutable through these routes.

### Consents

| Method | Path | Input/result |
| --- | --- | --- |
| GET | `/oauth2/get-consent?id=...` | One consent owned by the signed-in subject. |
| GET | `/oauth2/get-consents` | The subject's consent records and client display data. |
| POST | `/oauth2/update-consent` | `{id,scopes:[...]}`; scopes must remain allowed for that consent/client. |
| POST | `/oauth2/delete-consent` | `{id}`; removes the subject's grant. |

Deleting consent prevents silent reuse, but does not retroactively erase already issued access tokens. Revoke tokens separately when immediate invalidation is required.

## Configuration

### Defaults

| Option | Default |
| --- | --- |
| `Scopes` | `openid`, `profile`, `email`, `offline_access` |
| `GrantTypes` | authorization code, refresh token, client credentials |
| User / M2M access-token lifetime | 1 hour / 1 hour |
| ID-token lifetime | 10 hours |
| Refresh-token lifetime | 30 days |
| Authorization-code lifetime | 10 minutes |
| Dynamic client registration | disabled |
| Unauthenticated client registration | disabled |
| Registration allowed scopes | the configured server scopes |
| JWT plugin | required |

All lifetimes must be positive. Enabling `refresh_token` requires `authorization_code`. Every registration default/allowed scope must be present in the server `Scopes` list.

### Registration and client policy

| Option | Purpose |
| --- | --- |
| `AllowDynamicClientRegistration` | Enables `/oauth2/register`. |
| `AllowUnauthenticatedClientRegistration` | Permits registration without a root session; forces public/PKCE restrictions. |
| `ClientRegistrationDefaultScopes` | Defaults for dynamic clients; nil falls back to all server scopes. |
| `ClientRegistrationAllowedScopes` | Maximum dynamic-registration scope set; nil uses all server scopes. |
| `ClientCredentialGrantDefaultScopes` | Defaults only for M2M grants. |
| `CachedTrustedClients` | Identifies pre-provisioned clients that management routes must not mutate. |
| `ClientPrivileges` | Application authorization callback for create/read/update/delete/list/rotate actions. |
| `ClientReference` | Replaces user ownership with an application reference such as an organization ID. |
| `RequestURIResolver` | Resolves trusted pushed/stored authorization request identifiers. |

`GenerateClientID`, `GenerateClientSecret`, `GenerateOpaqueAccessToken`, and `GenerateRefreshToken` replace cryptographic default generators. Custom generators may run concurrently and must return unpredictable, collision-resistant values.

### Scopes, audiences, and claims

`ValidAudiences` allow-lists OAuth resource indicators. A requested resource outside the list fails with `invalid_target`. Client and consent scopes can narrow server scopes but never expand them. Client-credentials grants reject the built-in user/OpenID scopes `openid`, `profile`, `email`, and `offline_access`.

`CustomUserInfoClaims`, `CustomIDTokenClaims`, and `CustomAccessTokenClaims` add application data. Issuer, subject, audience, time, and nonce security claims are pinned by the server after ID-token customization. Keep claim callbacks deterministic, bounded, and concurrency-safe.

For pairwise subjects, set a `PairwiseSecret` of at least 32 bytes and register the client with `subject_type: "pairwise"`. All of that client's redirect URIs must share one host. Changing the pairwise secret changes subjects and is an identity migration.

`AdvertisedMetadata` customizes the supported scope/claim lists in discovery. It does not by itself implement a scope or claim; keep advertisement consistent with issuance behavior.

### Token presentation and storage

`OpaqueAccessTokenPrefix`, `RefreshTokenPrefix`, and `ClientSecretPrefix` change only presented token formats. The server stores hashes of opaque access/refresh tokens. With the JWT plugin enabled, client secrets are one-way transformed for verification. With `DisableJWTPlugin`, client secrets must be reversibly encrypted because HS256 signing needs the plaintext secret.

Do not parse opaque tokens or depend on their prefix as authorization. Use signature verification, introspection, or UserInfo as appropriate.

### Rate limits

The plugin contributes default per-path rules:

| Endpoint | Default limit |
| --- | --- |
| `/oauth2/token` | 20 requests/minute |
| `/oauth2/authorize` | 30 requests/minute |
| `/oauth2/introspect` | 100 requests/minute |
| `/oauth2/revoke` | 30 requests/minute |
| `/oauth2/register` | 5 requests/minute |
| `/oauth2/userinfo` | 60 requests/minute |

Root rate-limit configuration determines storage and identity bucketing. Direct API dispatch does not pass through HTTP rate limiting.

## Schema and migrations

The plugin adds four models:

- `oauthClient`: client identity, transformed secret, owner/reference, redirect/logout URIs, scopes, grants, response types, PKCE, subject type, flags, and metadata;
- `oauthRefreshToken`: transformed token, client/user/session/reference, expiry, revoked timestamp, auth time, and scopes;
- `oauthAccessToken`: transformed opaque token record, client/user/session/reference, refresh family, expiry, and scopes;
- `oauthConsent`: client/user/reference, granted scopes, and timestamps.

Authorization codes are stored in the core `verification` model and atomically consumed. The normal JWT composition also adds the `jwks` model.

Register JWT and OAuth factories before adapter creation, then apply the merged schema. With a root SQL constructor, run `auth.RunMigrationsContext(ctx)`. When migrating from legacy `oidcprovider`, do not only rename tables: client field formats, secret storage, token families, grants, and consent semantics differ. Migrate clients and active grants through an explicit, tested data plan. See [Migrations](../storage/migrations.md) and [OAuth/OIDC protocol storage](../protocols/oauth-and-oidc-server.md).

## Direct services

Keep the `*oauthprovider.Factory` returned by `NewFactory`. `Factory.Service()` returns the bound composed `*oauthprovider.Server` only after `singleauth.New` succeeds; one factory cannot bind twice. The composed server primarily exposes its protocol descriptor, while browser/client lifecycle calls remain the authenticated endpoints above.

Trusted application code can call registered operations through
`auth.API().Call`, but direct dispatch bypasses HTTP origin checks and rate
limits.

The MCP authorization factory exposes authorization, consent, registration,
token, and JWKS routes. Its discovery document does not advertise unsupported
introspection or revocation endpoints. The token endpoint supports
`authorization_code` and rotating `refresh_token` grants, authenticates
`client_secret_basic`, `client_secret_post`, and public `none` clients according
to registration, and verifies PKCE before consuming a code. Refresh tokens are
client-bound, expire, can only narrow scopes, and are atomically replaced so a
replay or concurrent second rotation fails.

The package exports lower-level, explicitly wired services for specialized composition: metadata, consent, revoke/token issuance, UserInfo, logout, and MCP authorization/resource services. `NewConsentFactory` exposes trusted `CreateConsent` after binding. These constructors do not inherit root session, storage, secret, or origin policy unless the caller supplies it; prefer `NewFactory` for a complete server.

## Security, replay, and concurrency

- Authorization redirect URIs are matched against the registered URI before any client-directed error redirect. Unsafe URL schemes are rejected.
- Signed `oauth_query` values bind UI round-trips to the request and expire after ten minutes. Do not decode them client-side and reconstruct parameters.
- Authorization codes are hashed/stored in verification storage and consumed once. Concurrent exchanges can succeed at most once.
- Refresh tokens rotate. Reuse of a revoked refresh token invalidates the applicable token family; atomic storage updates prevent two successful rotations.
- Public clients and `offline_access` use S256 PKCE. Client secrets are never returned by list/get endpoints.
- Scope and resource audience can narrow at authorization, token, and refresh stages but cannot expand.
- Introspection and revocation authenticate the client and do not disclose another client's token.
- Multi-replica deployments must share primary token, verification, consent, and session storage. Callback hooks and generators must be concurrency-safe.

## Troubleshooting

- Construction fails with `JWT plugin is required`: register `jwt.NewFactory(...)` before the OAuth provider or explicitly choose `DisableJWTPlugin` and its tradeoffs.
- `invalid_redirect_uri` or `INVALID_REDIRECT`: compare the complete registered URI, including scheme, host, path, port, and meaningful query values.
- `pkce is required for this client`: send both `code_challenge` and `code_challenge_method=S256`, then the original verifier at token exchange.
- `Invalid or expired oauth_query`: submit the exact signed value within ten minutes and keep the same root secret across instances.
- Refresh replay invalidates sessions/tokens: investigate duplicate client retries and serialize refresh at the client.
- Dynamic registration is denied: enable `AllowDynamicClientRegistration`; enable unauthenticated registration separately only when public self-registration is intended.
- Client credentials reject a scope: configure a non-user server scope and grant it to the client; OpenID/profile/email/offline scopes are invalid for M2M.
- Well-known issuer is unexpected behind a proxy: configure trusted proxy/base URL handling before issuing tokens. See [Deploy behind a proxy](../guides/deploy-behind-a-proxy.md).

## Related pages

- [OAuth and OIDC server protocol](../protocols/oauth-and-oidc-server.md)
- [JWT](./jwt.md)
- [MCP](./mcp.md)
- [Legacy OIDC provider](./oidc-provider.md)
- [Protocol security boundaries](../protocols/security-boundaries.md)
- [Go package reference](../reference/packages/plugins--oauthprovider.md)

**Status:** implemented across net/http, fasthttp, Fiber, real storage backends, and direct API dispatch.
