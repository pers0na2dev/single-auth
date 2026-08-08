---
title: "MCP authorization server"
description: "Protect MCP resource servers with OAuth metadata, bearer validation, audience policy, scopes, clients, and transport-neutral behavior."
---

Authorize Model Context Protocol clients with OAuth discovery, registration, PKCE, consent, and bearer sessions.

## Installation and route ownership

Import `github.com/pers0na2dev/single-auth/plugins/mcp`. `LoginPage` is required and must be a first-party URL that can resume the signed authorization request.

Do not install this plugin with `oauthprovider` or `oidcprovider` in the same `Auth`: they claim overlapping consent, discovery, registration, and token routes. Applications that need a general OAuth/OIDC server as well as MCP should use the MCP services exposed by [OAuth provider](./oauth-provider.md).

The OAuth provider's `NewMCPAuthorizationFactory` is a separate composition:
it publishes only authorization, consent, registration, token, and JWKS routes,
supports confidential Basic/post and public clients, and rotates refresh tokens
atomically. Its metadata intentionally omits introspection and revocation because
that factory does not expose those endpoints.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/mcp"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"https://app.example.com"},
        PluginFactories: []singleauth.PluginFactory{
            mcp.NewFactory(mcp.Options{
                LoginPage: "https://app.example.com/sign-in",
                Resource:  "https://api.example.com/mcp",
                OIDCConfig: mcp.OIDCOptions{
                    Scopes: []string{"mcp:read", "mcp:write"},
                    RequirePKCE: true,
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

## Authorization flow

1. A client discovers the authorization and protected-resource metadata.
2. It registers a redirect URI and receives public or confidential client credentials.
3. It opens `/mcp/authorize` with an authorization-code request and PKCE challenge.
4. An unauthenticated user is redirected to `LoginPage`; an authenticated user proceeds to consent when requested.
5. The client exchanges the single-use code at `/mcp/token` and uses the access token against the protected resource.
6. A resource server verifies the bearer token through `/mcp/get-session`.

## Endpoints

| Method | Path | Input | Result and authority |
| --- | --- | --- | --- |
| GET | `/.well-known/oauth-authorization-server` | None | Public OAuth/OIDC metadata. |
| GET | `/.well-known/oauth-protected-resource` | None | Public resource, authorization server, scopes, and bearer metadata. |
| GET | `/mcp/authorize` | `client_id`, exact `redirect_uri`, `response_type=code`, optional scopes/state/nonce and PKCE | Session or login redirect; returns an authorization redirect or consent redirect. |
| POST | `/oauth2/consent` | Signed consent code and decision | Authenticated resource owner; accepted scopes must be a subset of the original request. |
| POST | `/mcp/token` | Authorization code or refresh-token form fields and client credentials/PKCE | OAuth token response. |
| POST | `/mcp/register` | Dynamic registration metadata including `redirect_uris` | Returns client metadata and a secret only for confidential clients. |
| GET | `/mcp/get-session` | `Authorization: Bearer ...` | Access-token record or JSON `null`; never converts an invalid token into a session. |

### Register a public PKCE client

```http
POST /api/auth/mcp/register HTTP/1.1
Content-Type: application/json

{
  "client_name": "Desktop MCP client",
  "redirect_uris": ["http://127.0.0.1:45454/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

The response has status 201 and includes `client_id`, redirect/grant/response metadata, and no `client_secret` for a public client. Confidential registrations use `client_secret_basic` or `client_secret_post` and receive the secret once.

### Exchange an authorization code

```http
POST /api/auth/mcp/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=CLIENT&code=CODE&redirect_uri=http%3A%2F%2F127.0.0.1%3A45454%2Fcallback&code_verifier=VERIFIER
```

```json
{
  "access_token": "opaque-access-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "opaque-refresh-token",
  "scope": "openid profile"
}
```

Protocol errors use `{error,error_description}`. Typical codes are `invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `invalid_redirect_uri`, `unsupported_grant_type`, and `access_denied`.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `LoginPage` | Required | First-party login URL used to resume the signed authorization query. |
| `Resource` | Resolved auth origin | Protected-resource identifier advertised by discovery. |
| `OIDCConfig.CodeExpiresIn` | 10 minutes | Authorization-code lifetime. |
| `OIDCConfig.AccessTokenExpiresIn` | 1 hour | Bearer access-token lifetime. |
| `OIDCConfig.RefreshTokenExpiresIn` | 7 days | Refresh-token lifetime. |
| Scopes | `openid profile email offline_access` plus configured scopes | Server allow-list. |
| `OIDCConfig.DefaultScope` | `openid` | Used when authorize omits `scope`. |
| `OIDCConfig.ConsentPage` | Empty | When empty, consent is skipped unless the protocol request requires it. |
| `OIDCConfig.RequirePKCE` | `false` compatibility default | Require a challenge for every authorization request when enabled. |
| `AllowPlainCodeChallengeMethod` | `false` | Allow `plain`; otherwise only S256 is accepted. |
| Client ID/secret generators | Cryptographic random values | Custom registration identifiers. |
| Additional claims / metadata | Built-in values | Extend user claims or override advertised metadata. |

For internet-facing clients, enable `RequirePKCE` and keep plain challenges disabled.

## Schema and migrations

The plugin adds three models inherited from the compatibility OIDC surface:

- `oauthApplication`: client metadata, credentials, redirect URLs, ownership, and disabled state;
- `oauthAccessToken`: access/refresh tokens, expirations, client, user, and scope;
- `oauthConsent`: user/client scope grants.

Authorization codes are stored in core verification storage and consumed atomically. Register the factory before adapter initialization and apply the merged schema. With root SQL constructors, run `auth.RunMigrationsContext(ctx)`; otherwise merge `mcp.Schema()` before constructing the adapter. See [Migrations](../storage/migrations.md).

## Direct API

The server factory does not expose a bound management service. Trusted server calls can use `auth.API().Call` with registered operation names, but direct dispatch skips HTTP rate limiting and origin checks.

## Security, replay, and concurrency

- Redirect URIs are exact and dangerous schemes are rejected at registration.
- Authorization codes are single-use and bound to client, redirect URI, user, scopes, and PKCE challenge.
- Public clients have no secret and should use S256 PKCE. Confidential secrets and bearer tokens must never be logged.
- Consent cannot add scopes that were not requested.
- Access tokens are resource/scopes records in shared primary storage; all instances must use the same database and clock policy.
- `/mcp/get-session` returns JSON null for absent, unknown, or expired tokens. Resource servers must treat null as unauthorized.
- The compatibility schema stores confidential client secrets as provided by this plugin. Protect the database and prefer `oauthprovider` when stronger client-secret lifecycle controls are required.

## Troubleshooting

- Login redirects loop: ensure `LoginPage` preserves the original query and the browser returns the signed prompt cookie.
- `invalid_redirect_uri`: the authorize/token URI must exactly match a registered entry.
- `invalid_grant`: the code may already be consumed, expired, tied to another client/redirect URI, or have a failed verifier.
- A resource server always rejects the token: call `/mcp/get-session` under the auth base path, share the same primary storage, and check the access-token expiry.
- Metadata points at the wrong host: configure `BaseURL`/dynamic base URL and trusted proxy handling before overriding metadata manually.

## Related pages

- [OAuth provider](./oauth-provider.md)
- [OAuth and OIDC server](../protocols/oauth-and-oidc-server.md)
- [Security](../core/security.md)
- [Storage migrations](../storage/migrations.md)
- [Go package reference](../reference/packages/plugins--mcp.md)

**Status:** implemented for the native Go authorization server across net/http, fasthttp, Fiber, and direct dispatch.
