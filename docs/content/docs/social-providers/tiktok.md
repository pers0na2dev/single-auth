---
title: "TikTok"
---

Configure TikTok social sign-in in the native Go server.

Import `github.com/pers0na2dev/single-auth/protocol/providers` and construct the provider with `providers.TikTok`. The provider ID is `tiktok`, so its default callback URL is `https://<your-auth-host>/api/auth/callback/tiktok`.

> **Info: Provider console**
>
> Create a TikTok Login Kit application and register the callback URL.

## Configuration

```go
tiktokProvider, err := providers.TikTok(providers.Options{
    ClientKey:    os.Getenv("TIKTOK_CLIENT_KEY"),
    ClientSecret: os.Getenv("TIKTOK_CLIENT_SECRET"),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        tiktokProvider.ID: tiktokProvider,
    },
})
```

The provider constructor does not contact the remote service. Network activity starts when an authorization URL is created, a callback exchanges a code, profile data is fetched, a token is refreshed, or a remote JWKS is required.

## Provider behavior

| Property | Value |
| --- | --- |
| Authorization endpoint | `https://www.tiktok.com/v2/auth/authorize` |
| Token endpoint | `https://open.tiktokapis.com/v2/oauth/token/` |
| User-info endpoint | `https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_large_url,display_name,username` |
| Default scopes | `user.info.profile` |
| Token client authentication | `post (default)` |
| Refresh-token implementation | Yes |
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
  "provider": "tiktok",
  "callbackURL": "https://app.example.com/account"
}
```

When `callbackURL` is accepted by trusted-origin validation, the server stores it in the OAuth state and returns to it after a successful callback. Configure `Options.TrustedOrigins` for every browser origin and callback destination your application uses.

## Direct provider API

The configured value also exposes transport-neutral primitives:

```go
authorizationURL, err := tiktokProvider.CreateAuthorizationURL(providers.AuthorizationInput{
    State:        state,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/tiktok",
})

tokens, err := tiktokProvider.ValidateAuthorizationCode(ctx, providers.CodeInput{
    Code:         code,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/tiktok",
})

profile, err := tiktokProvider.GetUserInfo(ctx, tokens)
```

Use those primitives only when implementing a custom server flow. The normal auth routes additionally enforce state, cookies, account-linking policy, session creation, hooks, rate limits, and trusted origins.

## Security and behavior notes

- TikTok uses ClientKey, not ClientID, in authorization and token requests.
- The normalized email is the returned username and is not marked verified.
- This built-in currently does not apply MapProfileToUser to TikTok profile results.

- Keep the client secret in server-side configuration and never expose it to a browser.
- Register the exact callback URL, including `Options.BasePath` and the provider ID.
- Preserve OAuth state and PKCE cookies through the callback; do not terminate the flow on a different hostname unless cookie and trusted-origin settings are designed for it.
- Use a redirect-refusing HTTP client policy for endpoints you override, or validate every redirect target yourself.
