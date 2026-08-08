---
title: "OAuth 2.0 and OpenID Connect server"
---

Turn single-auth into an OAuth 2.1 authorization server and OpenID Provider.

The `plugins/oauthprovider` factory adds an authorization-server lifecycle to the existing auth runtime. It supports authorization code, refresh token, and client credentials grants; consent; PKCE; client management and optional dynamic registration; token introspection/revocation; user info; discovery; and RP-initiated logout. With the JWT plugin enabled, resource-bound access tokens and ID tokens use its signing/JWKS service. `DisableJWTPlugin` selects the separate opaque/HS256 behavior described below.

## Recommended setup

Register the JWT factory first because the OAuth provider uses its signing and JWKS service by default.

```go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://identity.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    PluginFactories: []singleauth.PluginFactory{
        jwt.NewFactory(jwt.Options{}),
        oauthprovider.NewFactory(oauthprovider.Options{
            LoginPage:   "https://app.example.com/login",
            ConsentPage: "https://app.example.com/oauth/consent",
            Scopes:      []string{"openid", "profile", "email", "offline_access"},
        }),
    },
})
```

`LoginPage` and `ConsentPage` are required non-empty values. Set `DisableJWTPlugin` only when you intentionally want the provider's alternative signing/token path. Do not register the OAuth Provider, legacy OIDC Provider, or standalone MCP OAuth plugin together: they own overlapping `/oauth2/*` and well-known routes, and endpoint conflict detection rejects the combination.

## Default grants and lifetimes

When `GrantTypes` is nil, the server advertises and accepts:

- `authorization_code`;
- `client_credentials`;
- `refresh_token`.

Refresh tokens require authorization-code support. Unsupported grant values are rejected during construction.

| Object | Default lifetime |
| --- | --- |
| Authorization code | 10 minutes |
| Access token | 1 hour |
| Machine-to-machine access token | 1 hour |
| ID token | 10 hours |
| Refresh token | 30 days |

Override the corresponding `Options` duration fields to match your policy. Token and client-secret generator callbacks allow custom entropy sources and prefixes without changing the protocol lifecycle.

## Main endpoints

All paths are under the root auth `BasePath` unless the endpoint is mounted as a well-known route for the resolved issuer.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/oauth2/authorize` | Validate a client request and begin login/consent. |
| `POST` | `/oauth2/consent` | Accept or deny requested scopes. |
| `POST` | `/oauth2/continue` | Continue a suspended authorization flow. |
| `POST` | `/oauth2/token` | Exchange codes/refresh tokens or issue client-credentials tokens. |
| `POST` | `/oauth2/introspect` | Inspect a supported token with client authentication. |
| `POST` | `/oauth2/revoke` | Revoke an access or refresh token. |
| `GET`, `POST` | `/oauth2/userinfo` | Return OIDC claims for a bearer access token. |
| `GET` | `/oauth2/end-session` | Perform RP-initiated logout for enabled clients. |
| `POST` | `/oauth2/register` | Dynamic client registration when enabled. |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 authorization-server metadata. |
| `GET` | `/.well-known/openid-configuration` | OpenID Provider metadata. |

Authenticated client-administration routes create, read, list, update, rotate, and delete clients. Consent routes let a signed-in user inspect, update, and revoke grants. The [OAuth Provider plugin reference](../plugins/oauth-provider.md) lists every route and option.

The registration route is mounted even when dynamic registration is disabled; in that state it returns `access_denied` and is omitted from discovery metadata.

## Clients and PKCE

`oauthprovider.Client` stores registered redirect/post-logout URIs, scopes, grants, response types, token endpoint authentication method, public/confidential status, consent behavior, end-session support, PKCE policy, subject type, owner/reference, and arbitrary metadata.

Authorization-code clients must have at least one exact redirect URI and support response type `code`. PKCE defaults to required when `Client.RequirePKCE` is absent. It is always required for public clients and for authorization requests containing `offline_access`, and dynamic registration rejects an explicit `require_pkce=false`. Only an application-created confidential client without `offline_access` can opt out by explicitly storing `RequirePKCE=false`. The only supported challenge method is `S256`.

The server verifies the code verifier during exchange and treats authorization codes as short-lived, single-use credentials. Keep the default unless a confidential legacy client cannot implement PKCE.

## Claims and subjects

- `CustomUserInfoClaims` adds claims to user-info responses.
- `CustomIDTokenClaims` adds claims to ID tokens.
- `CustomAccessTokenClaims` adds claims to JWT access tokens.
- `PairwiseSecret` enables stable pairwise subject derivation when clients use pairwise subjects.
- `ValidAudiences` constrains additional token audiences.

Callbacks receive the stored user, granted scopes, client, and current claim map as appropriate. ID-token and JWT access-token security claims are re-pinned after custom claim callbacks. Do not derive custom values from untrusted request data without validation. A non-empty `PairwiseSecret` must contain at least 32 bytes; pairwise clients are also restricted to one redirect host.

## Client registration policy

`AllowDynamicClientRegistration` enables registration. `AllowUnauthenticatedClientRegistration` additionally permits it without an existing authenticated session and should be enabled only with a compensating trust mechanism. An unauthenticated registration is forced to a public client with token-endpoint authentication method `none` and cannot request `client_credentials`. Dynamic registration also rejects `skip_consent`; only trusted application-side administration can set that field. Scope allow-lists and registration defaults constrain newly registered clients.

For application-managed clients, use `ClientPrivileges` to authorize create/read/update/delete/list/rotate operations and `ClientReference` to scope ownership. `CachedTrustedClients` does not skip consent. It protects the named clients from update, delete, and secret-rotation routes so they can be managed from trusted application configuration. Consent is skipped only by the client's `SkipConsent` field.

## `DisableJWTPlugin` behavior

With `DisableJWTPlugin=true`, access tokens are opaque and persisted through the OAuth token service. Confidential client secrets are stored with the runtime's reversible encryption helpers because HS256 ID-token issuance needs the original per-client secret; secret hashing is used in the normal JWT-plugin mode. ID tokens use HS256 when the client has a decryptable secret, and public clients without a secret may receive no ID token. Discovery omits `jwks_uri` because this mode has no public signing-key set.

## Legacy OIDC Provider

`plugins/oidcprovider` remains available for compatibility, but it is deprecated. New deployments should use `plugins/oauthprovider`, which owns the broader OAuth 2.1/OIDC lifecycle and has explicit client, consent, token, revocation, metadata, and logout services.

## MCP integration

The OAuth Provider package contains dedicated MCP authorization-server and protected-resource services. Prefer those when the same issuer must authorize MCP clients. The standalone `plugins/mcp` package owns overlapping routes and must be used as an alternative deployment mode, not alongside the full OAuth Provider.
