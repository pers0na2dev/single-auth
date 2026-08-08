---
title: "Common provider options"
---

Shared credentials, scopes, callbacks, overrides, and security controls for built-in social providers.

Every built-in constructor accepts `providers.Options`. It is a superset: provider-specific fields are ignored by providers that do not consume them.

## Credentials and endpoints

| Field | Type | Behavior |
| --- | --- | --- |
| `ClientID` | `any` | A `string`, `[]string`, or `[]any` containing strings. The first value is used for authorization; verifier audiences may include the full list. |
| `ClientSecret` | `string` | OAuth client secret. Required by providers that authenticate confidential clients. |
| `ClientKey` | `string` | TikTok's required application key; it is also forwarded by the Notion refresh implementation when set. |
| `RedirectURI` | `string` | Explicit OAuth redirect URI. Leave empty to let the auth runtime derive `BaseURL + BasePath + /callback/:id`. |
| `AuthorizationEndpoint` | `string` | Overrides an authorization endpoint where the provider supports that override. Prefer the provider-specific issuer/authority option when available. |
| `HTTPClient` | `*http.Client` | Per-provider HTTP client used for token, profile, and JWKS requests. Configure timeouts and a safe redirect policy. |

## Scope and authorization behavior

| Field | Default | Behavior |
| --- | --- | --- |
| `Scopes` | Empty | Additional scopes appended to provider defaults. |
| `DisableDefaultScope` | `false` | Uses only `Scopes` instead of provider defaults. |
| `Prompt` | Empty | Provider prompt value where supported. |
| `ResponseMode` | Empty | Compatibility field retained in the public option union; current built-in authorization builders do not consume it. |
| `DisableIDTokenSignIn` | `false` | Disables the provider's direct ID-token sign-in path and verifier. |
| `DisableImplicitSignUp` | `false` | Prevents creating a user as an implicit consequence of a sign-in flow. |
| `DisableSignUp` | `false` | Prevents new-user creation through this provider. |

## Mapping and network overrides

| Field | Signature | Use |
| --- | --- | --- |
| `GetUserInfo` | `func(context.Context, oauth2.Tokens) (*UserInfoResult, error)` | Replaces the provider's profile request and mapping. |
| `RefreshAccessToken` | `func(context.Context, string) (oauth2.Tokens, error)` | Replaces refresh-token exchange. |
| `VerifyIDToken` | `func(context.Context, string, string) (bool, error)` | Replaces provider ID-token verification. The second string is the expected nonce. |
| `MapProfileToUser` | `func(context.Context, map[string]any) (map[string]any, error)` | Adds or overrides `id`, `name`, `email`, `image`, `emailVerified`, and additional user fields. |
| `OverrideUserInfo` | Boolean | Compatibility field retained in the option union; it currently has no effect in built-in providers. |

When a built-in applies `MapProfileToUser`, recognized keys are applied to the normalized `oauth2.UserInfo` and unrecognized keys are retained in `UserInfo.Extra`. TikTok intentionally does not invoke this callback in the current compatibility implementation.

## Compatibility fields without current behavior

`RequestShippingAddress`, `Scheme`, and `PlatformType` remain in `providers.Options` for source compatibility but are not read by the current PayPal, VK, or WeChat implementations. `Environment` is consumed by PayPal and Salesforce only; it has no Atlassian behavior. Do not build policy around these fields until production code implements them.

## ID-token verification boundary

> **Warning: The normal callback does not invoke VerifyIDToken**
>
> `Provider.VerifyIDToken` and `Options.VerifyIDToken` are used by the direct ID-token sign-in/link path and by explicit callers. The normal authorization-code callback exchanges the code and calls `GetUserInfo` without automatically invoking the verifier. Decoding an ID token inside a profile mapper does not verify its signature.

If an authorization-code callback must cryptographically verify an ID token before accepting its claims, provide a `GetUserInfo` override that performs that verification before returning a profile, or implement a custom provider with the same rule. `DisableIDTokenSignIn` disables the separate direct ID-token path; it does not prevent a built-in callback mapper from reading an ID token returned by code exchange.

## Account and callback policy

Provider options control the remote protocol. Root `singleauth.Options` controls local security and persistence:

- `Options.TrustedOrigins` decides which browser origins and callback URLs may participate.
- `Options.Account.AccountLinking` controls implicit linking, unlinking, email ownership, and trusted providers.
- `Options.Account.EncryptOAuthTokens` encrypts persisted access and refresh tokens.
- `Options.Account.StoreStateStrategy` selects database or cookie-backed OAuth state.
- `Options.Account.SkipStateCookieCheck` weakens callback correlation and should only be used when the surrounding deployment supplies equivalent protection.
- Cookie settings determine whether OAuth state survives cross-site redirects and reverse proxies.

## HTTP client hardening

Use finite timeouts and reject redirects unless a provider explicitly requires them:

~~~go
providerHTTPClient := &http.Client{
    Timeout: 10 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse
    },
}
~~~

The low-level `oauth2` package includes redirect-refusing request helpers. Endpoint overrides remain application-controlled and must point to trusted HTTPS origins.
