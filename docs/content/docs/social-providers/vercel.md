---
title: "Vercel"
---

Configure Vercel social sign-in in the native Go server.

Import `github.com/pers0na2dev/single-auth/protocol/providers` and construct the provider with `providers.Vercel`. The provider ID is `vercel`, so its default callback URL is `https://<your-auth-host>/api/auth/callback/vercel`.

> **Info: Provider console**
>
> Create a Vercel integration and register the callback URL.

## Configuration

```go
vercelProvider, err := providers.Vercel(providers.Options{
    ClientID:     os.Getenv("VERCEL_CLIENT_ID"),
    ClientSecret: os.Getenv("VERCEL_CLIENT_SECRET"),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        vercelProvider.ID: vercelProvider,
    },
})
```

The provider constructor does not contact the remote service. Network activity starts when an authorization URL is created, a callback exchanges a code, profile data is fetched, a token is refreshed, or a remote JWKS is required.

## Provider behavior

| Property | Value |
| --- | --- |
| Authorization endpoint | `https://vercel.com/oauth/authorize` |
| Token endpoint | `https://api.vercel.com/login/oauth/token` |
| User-info endpoint | `https://api.vercel.com/login/oauth/userinfo` |
| Default scopes | `None by default` |
| Token client authentication | `post (default)` |
| Refresh-token implementation | No |
| Direct ID-token verifier | No provider-specific verifier |
| JWKS URI | `Not used by default` |

`Options.Scopes` are appended to the defaults. Set `DisableDefaultScope` only when the remote application is intentionally configured with a complete replacement scope set.

> **Warning: ID-token verification is flow-specific**
>
> `Provider.VerifyIDToken` and the verifier row above describe the direct ID-token sign-in/link path. The normal authorization-code callback currently exchanges the code and calls `GetUserInfo`; it does not automatically invoke that verifier. A provider that decodes an ID token while mapping a profile is not thereby verifying its signature. Use a verified custom profile callback when your callback trust model requires that additional check.

## Provider-specific options

This provider adds no provider-only fields beyond the [common options](./common-options.md).

## Start sign-in

```http
POST /api/auth/sign-in/social HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Origin: https://app.example.com

{
  "provider": "vercel",
  "callbackURL": "https://app.example.com/account"
}
```

When `callbackURL` is accepted by trusted-origin validation, the server stores it in the OAuth state and returns to it after a successful callback. Configure `Options.TrustedOrigins` for every browser origin and callback destination your application uses.

## Direct provider API

The configured value also exposes transport-neutral primitives:

```go
authorizationURL, err := vercelProvider.CreateAuthorizationURL(providers.AuthorizationInput{
    State:        state,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/vercel",
})

tokens, err := vercelProvider.ValidateAuthorizationCode(ctx, providers.CodeInput{
    Code:         code,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/vercel",
})

profile, err := vercelProvider.GetUserInfo(ctx, tokens)
```

Use those primitives only when implementing a custom server flow. The normal auth routes additionally enforce state, cookies, account-linking policy, session creation, hooks, rate limits, and trusted origins.

## Security and behavior notes

- PKCE is used.
- The provider normalizes Vercel account profile data into the common user shape.

- Keep the client secret in server-side configuration and never expose it to a browser.
- Register the exact callback URL, including `Options.BasePath` and the provider ID.
- Preserve OAuth state and PKCE cookies through the callback; do not terminate the flow on a different hostname unless cookie and trusted-origin settings are designed for it.
- Use a redirect-refusing HTTP client policy for endpoints you override, or validate every redirect target yourself.
