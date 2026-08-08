---
title: "Microsoft Entra ID"
---

Configure Microsoft Entra ID social sign-in in the native Go server.

Import `github.com/pers0na2dev/single-auth/protocol/providers` and construct the provider with `providers.Microsoft`. The provider ID is `microsoft`, so its default callback URL is `https://<your-auth-host>/api/auth/callback/microsoft`.

> **Info: Provider console**
>
> Register an application in Microsoft Entra ID, add a Web redirect URI, and create a client secret.

## Configuration

```go
microsoftProvider, err := providers.Microsoft(providers.Options{
    ClientID:     os.Getenv("MICROSOFT_CLIENT_ID"),
    ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        microsoftProvider.ID: microsoftProvider,
    },
})
```

The provider constructor does not contact the remote service. Network activity starts when an authorization URL is created, a callback exchanges a code, profile data is fetched, a token is refreshed, or a remote JWKS is required.

## Provider behavior

| Property | Value |
| --- | --- |
| Authorization endpoint | `https://login.microsoftonline.com/common/oauth2/v2.0/authorize` |
| Token endpoint | `https://login.microsoftonline.com/common/oauth2/v2.0/token` |
| User-info endpoint | `Not used by default` |
| Default scopes | `openid, profile, email, User.Read, offline_access` |
| Token client authentication | `post (default)` |
| Refresh-token implementation | Yes |
| Direct ID-token verifier | Yes |
| JWKS URI | `https://login.microsoftonline.com/common/discovery/v2.0/keys` |

`Options.Scopes` are appended to the defaults. Set `DisableDefaultScope` only when the remote application is intentionally configured with a complete replacement scope set.

> **Warning: ID-token verification is flow-specific**
>
> `Provider.VerifyIDToken` and the verifier row above describe the direct ID-token sign-in/link path. The normal authorization-code callback currently exchanges the code and calls `GetUserInfo`; it does not automatically invoke that verifier. A provider that decodes an ID token while mapping a profile is not thereby verifying its signature. Use a verified custom profile callback when your callback trust model requires that additional check.

## Provider-specific options

| Field | Behavior |
| --- | --- |
| `TenantID` | Tenant selector; defaults to common. It may be a tenant ID, organizations, consumers, or common. |
| `Authority` | OAuth authority base URL; defaults to https://login.microsoftonline.com. |
| `ProfilePhotoSize` | Requested square Microsoft Graph profile-photo size; defaults to 48. |
| `DisableProfilePhoto` | Skips embedding the Microsoft Graph profile photo in the normalized user. |

## Start sign-in

```http
POST /api/auth/sign-in/social HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Origin: https://app.example.com

{
  "provider": "microsoft",
  "callbackURL": "https://app.example.com/account"
}
```

When `callbackURL` is accepted by trusted-origin validation, the server stores it in the OAuth state and returns to it after a successful callback. Configure `Options.TrustedOrigins` for every browser origin and callback destination your application uses.

## Direct provider API

The configured value also exposes transport-neutral primitives:

```go
authorizationURL, err := microsoftProvider.CreateAuthorizationURL(providers.AuthorizationInput{
    State:        state,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/microsoft",
})

tokens, err := microsoftProvider.ValidateAuthorizationCode(ctx, providers.CodeInput{
    Code:         code,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/microsoft",
})

profile, err := microsoftProvider.GetUserInfo(ctx, tokens)
```

Use those primitives only when implementing a custom server flow. The normal auth routes additionally enforce state, cookies, account-linking policy, session creation, hooks, rate limits, and trusted origins.

## Security and behavior notes

- Tenant-aware issuer checks prevent consumer/organization tokens from crossing a restricted tenant mode in the direct ID-token verifier.
- The default scopes include offline_access and User.Read.
- The direct verifier checks the authority JWKS, audience, token age, nonce, tenant, and issuer.
- The profile path currently requests the photo even when DisableProfilePhoto is true; the option only prevents embedding a successful response.

- Keep the client secret in server-side configuration and never expose it to a browser.
- Register the exact callback URL, including `Options.BasePath` and the provider ID.
- Preserve OAuth state and PKCE cookies through the callback; do not terminate the flow on a different hostname unless cookie and trusted-origin settings are designed for it.
- Use a redirect-refusing HTTP client policy for endpoints you override, or validate every redirect target yourself.
