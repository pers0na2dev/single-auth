---
title: "Generic OAuth"
description: "Configure arbitrary OAuth 2.0 and OpenID Connect providers with native Go callbacks and discovery."
---

Generic OAuth connects an OAuth 2.0 or OpenID Connect provider that is not covered by a dedicated provider package. It supports discovery or explicit endpoints, PKCE, RFC 9207 authorization-response issuer checks, custom token and profile callbacks, sign-in, sign-up, and authenticated account linking.

## Install and configure

Import `github.com/pers0na2dev/single-auth/plugins/genericoauth`. Every config needs a non-empty `ProviderID` and enough information to resolve authorization, token, and user-profile behavior.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/genericoauth"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"https://app.example.com"},
        PluginFactories: []singleauth.PluginFactory{
            genericoauth.NewFactory(genericoauth.Options{Config: []genericoauth.Config{{
                ProviderID:              "company-idp",
                DiscoveryURL:            "https://id.example.com/.well-known/openid-configuration",
                Issuer:                  "https://id.example.com",
                RequireIssuerValidation: true,
                ClientID:                os.Getenv("OIDC_CLIENT_ID"),
                ClientSecret:            os.Getenv("OIDC_CLIENT_SECRET"),
                Scopes:                  []string{"openid", "profile", "email"},
                PKCE:                    true,
            }}}),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

Register the exact callback with the provider:

```text
https://auth.example.com/api/auth/oauth2/callback/company-idp
```

`ProviderCallbackURL` can build and validate the callback when the supplied base already includes the auth base path:

```go
callback, err := genericoauth.ProviderCallbackURL(
    "https://auth.example.com/api/auth",
    "company-idp",
)
```

The factory registers each generic config as a root social provider. A `ProviderID` must therefore be unique across generic configs and root `SocialProviders`. When a generic list repeats an ID, the first config wins and the logger warns; a collision with another registered social provider fails initialization.

## HTTP routes

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/sign-in/oauth2` | JSON sign-in options | `url`, `redirect` | Public form request; callback URLs are root-validated |
| GET | `/oauth2/callback/:providerId` | Provider `code`, `state`, optional `iss` or error | 302 to the selected callback | Signed, live OAuth state and provider authorization code |
| POST | `/oauth2/link` | JSON provider/link options | `url`, `redirect:true` | Authoritative root session |

### Start sign-in

```http
POST /api/auth/sign-in/oauth2
Content-Type: application/json
Origin: https://app.example.com

{
  "providerId": "company-idp",
  "callbackURL": "https://app.example.com/dashboard",
  "errorCallbackURL": "https://app.example.com/sign-in",
  "newUserCallbackURL": "https://app.example.com/welcome",
  "disableRedirect": true,
  "scopes": ["groups:read"],
  "requestSignUp": true,
  "additionalData": {"tenant": "acme"}
}
```

```json
{
  "url": "https://id.example.com/authorize?...",
  "redirect": false
}
```

`providerId` is required. The callback fields, `disableRedirect`, `scopes`, `requestSignUp`, and object-valued `additionalData` are optional. Reserved OAuth-state keys are removed from additional data. Requested sign-in scopes are prepended to the configured scopes; they supplement rather than replace them.

`disableRedirect` only changes the returned `redirect` flag. The server still returns the authorization URL for the application to open or navigate to.

### Callback and profile requirements

The provider redirects to `/oauth2/callback/:providerId`. The server validates and consumes state, exchanges the code, obtains a profile, creates or links the root account, refreshes the session cookies, and redirects to:

- `newUserCallbackURL` for a newly registered user when it was supplied;
- otherwise `callbackURL` from state.

The normalized profile must contain a non-empty account ID (`id` or `sub`), email, and name. Email is lowercased. Missing values redirect with `id_is_missing`, `email_is_missing`, or `name_is_missing`.

Provider errors and a missing code are converted to error redirects. The target is `errorCallbackURL` from state, falling back to root `OnAPIError.ErrorURL` and then the root `/error` page. Existing query parameters are preserved and `error` plus optional `error_description` are appended.

### Link an account

```http
POST /api/auth/oauth2/link
Content-Type: application/json
Origin: https://app.example.com
Cookie: single-auth.session_token=...

{
  "providerId": "company-idp",
  "callbackURL": "https://app.example.com/settings/accounts",
  "errorCallbackURL": "https://app.example.com/settings/accounts",
  "scopes": ["openid", "profile", "email"]
}
```

Both `providerId` and `callbackURL` are required. If `scopes` is present here, it replaces the configured list; an explicit empty array requests no scopes, while omission uses the configured defaults. The callback links the provider account to the session user. Email must match unless root account linking explicitly allows different emails, and an account already linked to another user is rejected.

## Config options

| Option | Default | Behavior |
| --- | --- | --- |
| `ProviderID` | required | Stable route/provider identifier; first duplicate in the generic list wins |
| `DiscoveryURL` | none | OIDC discovery document supplying authorization, token, user-info, and issuer metadata |
| `Issuer` | discovered or empty | Expected RFC 9207 authorization-response issuer |
| `RequireIssuerValidation` | `false` | Reject callback when an expected issuer exists but the `iss` query parameter is absent |
| `AuthorizationURL`, `TokenURL`, `UserInfoURL` | none | Explicit endpoints used without or as fallback around discovery |
| `ClientID`, `ClientSecret` | empty | Provider credentials |
| `Scopes` | nil | Default scopes |
| `RedirectURI` | generated callback | Provider-specific override where supported |
| `ResponseType` | `code` | Authorization response type |
| `ResponseMode`, `Prompt`, `AccessType` | empty | Optional authorization request parameters |
| `PKCE` | `false` | Add S256 challenge and send the verifier during code exchange |
| `AccessTokenExpiresIn` | unknown | Fallback Go duration when the token response omits `expires_in` |
| `Authentication` | `oauth2.AuthenticationPost` | Token client authentication; `AuthenticationBasic` selects HTTP Basic |
| `AuthorizationURLParams`, `TokenURLParams` | none | Static or request-scoped additional parameters; `Resolve` wins over `Static` |
| `DiscoveryHeaders`, `AuthorizationHeaders` | none | Headers for discovery GETs and token requests respectively |
| `DisableImplicitSignUp` | `false` | Require state `requestSignUp:true` before creating an unknown user |
| `DisableSignUp` | `false` | Never create an unknown user |
| `OverrideUserInfo` | `false` | Root-provider compatibility flag used by account flows |
| `HTTPClient` | root client | Provider-specific outbound client |

`Config.GetToken` replaces authorization-code exchange and receives code, redirect URI, code verifier, and device ID. `GetUserInfo` replaces built-in ID-token/user-info extraction. `MapProfileToUser` receives the raw profile and can return normalized `id`, `email`, `name`, `image`, and `emailVerified` values while retaining raw data in the provider profile.

```go
GetUserInfo: func(ctx context.Context, tokens oauth2.Tokens) (genericoauth.Profile, error) {
    return fetchVerifiedProfile(ctx, tokens.AccessToken)
},
MapProfileToUser: func(_ context.Context, profile genericoauth.Profile) (genericoauth.Profile, error) {
    return genericoauth.Profile{
        "id":            profile["employee_id"],
        "email":         profile["mail"],
        "name":          profile["display_name"],
        "emailVerified": true,
    }, nil
},
```

Callbacks and request-scoped parameter resolvers can run concurrently. Treat captured state as immutable or synchronize it.

## Discovery and trust boundaries

At sign-in, discovery is attempted when configured. A discovery failure is logged; explicit authorization and token endpoints can still allow the flow to start. At callback/token paths, missing required endpoints fail the flow.

RFC 9207 handling is exact:

- when callback `iss` is present and an expected issuer is configured or discovered, it must match exactly;
- when `iss` is absent, it is rejected only when `RequireIssuerValidation` is true;
- this validates the authorization-response parameter, not an ID-token signature.

The built-in profile path may decode an ID-token payload when it contains `sub` and `email`; that decode does not verify the JWT signature. Otherwise it calls the user-info endpoint with the access token. For providers whose identity depends on signed ID-token claims, supply a `GetUserInfo` implementation that performs complete signature, algorithm, key, issuer, audience, expiry, and nonce validation, or rely on a trusted HTTPS user-info endpoint.

Discovery and user-info URLs cause outbound HTTP requests. The package does not impose an application-specific host allowlist or response-body limit. Pin endpoints or provide an `HTTPClient` with DNS/IP, redirect, timeout, TLS, and response-size policy appropriate for untrusted configuration. Never let arbitrary tenants supply unrestricted URLs.

## Provider helpers

The package includes helpers for `Auth0`, `Okta`, `Keycloak`, `MicrosoftEntraID`, `Slack`, `Gumroad`, `HubSpot`, `Line`, `Patreon`, and `Yandex`. They return `Config` values; review and override the result for the exact tenant, issuer, scopes, and endpoints used by your provider.

## Direct API

`SignInInput` and `LinkInput` describe the direct equivalents of the two POST
bodies. There is no separately bound server service; trusted code can call
`signInWithOAuth2`, `oAuth2Callback`, and `oAuth2LinkAccount` through
`auth.API().Call`.

Direct dispatch bypasses outer HTTP origin checks and rate limiting. Supply realistic method, body, query, scheme, host, and session headers, and preserve the same callback and tenant validation before exposing it through another transport.

## Schema, state, replay, and concurrency

The plugin adds no model. Successful flows use root `user`, `account`, and `session`; database state uses the core `verification` model.

With root state strategy `database`, callback state is read, validated against its signed browser cookie unless `SkipStateCookieCheck` is enabled, and atomically consumed. This provides cross-replica single-use behavior when the adapter implements atomic verification consumption.

With state strategy `cookie`, state is authenticated-encrypted and the cookie is expired after a successful parse. It avoids a verification row, but independently copied cookie values can be replayed until expiry because there is no central consumed-state record. Prefer database state when global replay prevention matters.

PKCE protects the code exchange, but it does not replace state, exact redirect registration, trusted callback URLs, or provider-side client authentication.

## Errors and troubleshooting

Start/link validation failures are JSON API errors. Callback failures normally redirect with an `error` query value.

| Failure | Typical result |
| --- | --- |
| Unknown sign-in provider | 400 `BAD_REQUEST` with `No config found for provider ...` |
| Missing link session | 401 `SESSION_REQUIRED` |
| Missing authorization/token endpoint | `INVALID_OAUTH_CONFIGURATION`, `INVALID_OAUTH_CONFIG`, or `TOKEN_URL_NOT_FOUND` depending on phase |
| Missing, expired, mismatched, or replayed state | redirect `state_not_found` or `state_mismatch` |
| Issuer mismatch/missing | redirect `issuer_mismatch` or `issuer_missing` |
| Token exchange failure | redirect `oauth_code_verification_failed` |
| Missing usable profile | redirect `user_info_is_missing`, `email_is_missing`, `id_is_missing`, or `name_is_missing` |
| Link email/account conflict | redirect `email_doesn't_match`, `account_already_linked_to_different_user`, or `unable_to_link_account` |

- A provider redirect-URI error usually means the registered URI omitted the root base path or used `/callback/:id` instead of `/oauth2/callback/:id`.
- A discovery-only configuration that intermittently reports invalid configuration needs a reliable discovery endpoint or explicit endpoint fallbacks.
- `issuer_missing` means the provider did not send RFC 9207 `iss`; either enable provider support or leave strict presence validation off after a deliberate threat-model review.
- If custom scopes disappear during linking, remember that a supplied link scope list replaces defaults, while sign-in request scopes are prepended to defaults.
- If an HTTP caller follows callback redirects automatically, disable redirect following while diagnosing the auth server's `Location` value.

## Related pages

- [Accounts and social providers](../core/accounts-and-social.md)
- [Social OAuth end to end](../guides/social-oauth-end-to-end.md)
- [OAuth 2 client primitives](../protocols/oauth2-client-primitives.md)
- [OAuth popup](./oauth-popup.md)
- [OAuth proxy](./oauth-proxy.md)
- [Security boundaries](../protocols/security-boundaries.md)
- [Direct API](../transports/direct-api.md)

**Status:** implemented with discovery, custom callbacks, issuer checks, sign-in, linking, database/cookie state, replay, concurrency, transport, and provider-helper coverage.
