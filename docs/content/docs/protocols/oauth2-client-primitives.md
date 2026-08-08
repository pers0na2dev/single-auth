---
title: "OAuth 2.0 client primitives"
---

Authorization URLs, PKCE, token requests, refresh, JWT validation, and redirect-safe HTTP helpers.

Package `github.com/pers0na2dev/single-auth/protocol/oauth2` contains the transport-neutral OAuth 2.0 and OpenID Connect primitives used by built-in social providers. It does not register routes or store state.

## Authorization URL and PKCE

```go
authorizationURL, err := oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
    ID: "acme",
    Options: oauth2.ProviderOptions{
        ClientID: "client-id",
    },
    AuthorizationEndpoint: "https://identity.example.com/oauth/authorize",
    RedirectURI:           "https://auth.example.com/api/auth/callback/acme",
    State:                 state,
    CodeVerifier:          verifier,
    Scopes:                []string{"openid", "profile", "email"},
    Prompt:                "consent",
})
if err != nil {
    return err
}
```

When `CodeVerifier` is non-empty, `CreateAuthorizationURL` emits an RFC 7636 S256 `code_challenge` and `code_challenge_method=S256`. `GenerateCodeChallenge` exposes that conversion directly.

`AuthorizationURLOptions` also supports response type/mode, claims, duration, access type, display, login hint, hosted domain, additional parameters, and a custom scope joiner. Additional parameters are applied with `Set`, so a later entry with the same name replaces the earlier value rather than creating duplicates. `ProviderOptions.AuthorizationEndpoint` and `ProviderOptions.RedirectURI` override their top-level counterparts.

## Authorization-code exchange

```go
request := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{
    Code:         code,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/acme",
    Options: oauth2.ProviderOptions{
        ClientID:     "client-id",
        ClientSecret: "client-secret",
    },
    Authentication: oauth2.AuthenticationBasic,
})

payload, err := oauth2.DoForm(ctx, httpClient,
    "https://identity.example.com/oauth/token", request)
if err != nil {
    return err
}
tokens := oauth2.NormalizeTokens(payload, time.Now())
```

Use `AuthenticationBasic` for an HTTP Basic `Authorization` header and `AuthenticationPost` for credentials in the form body. The zero value follows the POST-body branch.

`NormalizeTokens` accepts provider JSON and populates access/refresh token values, token type, ID token, scopes, expiry timestamps, and the lossless `Raw` map. `ApplyDefaultAccessTokenExpiry` fills an absent access-token expiry without overwriting a provider value.

## Refresh token

```go
tokens, err := oauth2.RefreshAccessToken(ctx, oauth2.RefreshAccessTokenOptions{
    RefreshToken:  storedRefreshToken,
    TokenEndpoint: "https://identity.example.com/oauth/token",
    Options: oauth2.ProviderOptions{
        ClientID:     "client-id",
        ClientSecret: "client-secret",
    },
    Authentication: oauth2.AuthenticationBasic,
    Client:         httpClient,
})
```

For custom request assembly, call `CreateRefreshAccessTokenRequest`. `Resources` creates repeated `resource` parameters. `ExtraParams` are applied with `Set`, so they replace an existing value with the same name rather than preserving duplicates. `CreateClientCredentialsTokenRequest` implements the client-credentials grant.

## Ordered forms

`oauth2.Form` mirrors the parts of `URLSearchParams` needed by provider compatibility:

| Method | Behavior |
| --- | --- |
| `Set` | Replaces the first matching value, removes later duplicates, or appends a new pair. |
| `Append` | Adds another value even when the key already exists. |
| `Get` | Returns the first value and a presence boolean. |
| `Values` | Returns every value in insertion order. |
| `Has` | Reports whether a key exists. |
| `Params` | Returns a defensive copy of ordered pairs. |
| `Encode` | Produces `application/x-www-form-urlencoded` data with URLSearchParams-compatible escaping. |

## JWT and JWKS validation

```go
verified, err := oauth2.ValidateToken(
    ctx,
    httpClient,
    rawIDToken,
    "https://identity.example.com/.well-known/jwks.json",
    oauth2.ValidateTokenOptions{
        Audience: []string{"client-id"},
        Issuer:   []string{"https://identity.example.com"},
    },
)
if err != nil {
    return err
}
subject, _ := verified.Payload["sub"].(string)
```

`ValidateToken` verifies compact JWT signatures using a matching remote JWK. It rejects an expired `exp` claim and a future `nbf` claim when those claims are present, but it does not require `exp`, validate `iat`, or apply clock skew. It also checks configured audience and issuer constraints. The implemented signature set is RS256, ES256, and EdDSA with Ed25519. Empty audience or issuer slices leave that claim unconstrained; production OIDC integrations should normally constrain both and enforce any required claim/clock policy before accepting the result.

## Redirect and SSRF boundary

OAuth token, user-info, discovery, and JWKS calls are server-side requests to security-sensitive endpoints. A redirect can turn a trusted public URL into a request to an internal address.

- `RefuseRedirects` clones an HTTP client and stops on the first redirect.
- `DoRefusingRedirects` executes one request with that policy.
- `DoForm` refuses redirects before decoding a JSON object.
- `FetchJWKSet` refuses redirects and validates the JWKS envelope.
- `AssertResponseNotRedirect` and `AssertResponseMetadataNotRedirect` apply the same rule to existing responses or transport-neutral response metadata.
- `errors.Is(err, oauth2.ErrOAuthRedirect)` recognizes the redirect class; `RedirectRefusedError.Endpoint` identifies the original endpoint.

Use finite HTTP timeouts and only allow endpoint overrides from trusted server configuration. `DoForm` and `FetchJWKSet` currently read successful response bodies without a package-level byte ceiling; when remote response size is not already bounded by trusted infrastructure, enforce a limit in the HTTP transport or use an application-owned request/decoder.
