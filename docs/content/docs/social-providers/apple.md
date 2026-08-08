---
title: "Apple"
---

Configure Apple social sign-in in the native Go server.

Import `github.com/pers0na2dev/single-auth/protocol/providers` and construct the provider with `providers.Apple`. The provider ID is `apple`, so its default callback URL is `https://<your-auth-host>/api/auth/callback/apple`.

> **Info: Provider console**
>
> Create a Services ID and a Sign in with Apple key. The configured redirect URI must use HTTPS outside local development.

## Configuration

```go
appleProvider, err := providers.Apple(providers.Options{
    ClientID:     os.Getenv("APPLE_CLIENT_ID"),
    ClientSecret: os.Getenv("APPLE_CLIENT_SECRET"),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        appleProvider.ID: appleProvider,
    },
})
```

The provider constructor does not contact the remote service. Network activity starts when an authorization URL is created, a callback exchanges a code, profile data is fetched, a token is refreshed, or a remote JWKS is required.

## Provider behavior

| Property | Value |
| --- | --- |
| Authorization endpoint | `https://appleid.apple.com/auth/authorize` |
| Token endpoint | `https://appleid.apple.com/auth/token` |
| User-info endpoint | `Not used by default` |
| Default scopes | `email, name` |
| Token client authentication | `post (default)` |
| Refresh-token implementation | Yes |
| Direct ID-token verifier | Yes |
| JWKS URI | `https://appleid.apple.com/auth/keys` |

`Options.Scopes` are appended to the defaults. Set `DisableDefaultScope` only when the remote application is intentionally configured with a complete replacement scope set.

> **Warning: ID-token verification is flow-specific**
>
> `Provider.VerifyIDToken` and the verifier row above describe the direct ID-token sign-in/link path. The normal authorization-code callback currently exchanges the code and calls `GetUserInfo`; it does not automatically invoke that verifier. A provider that decodes an ID token while mapping a profile is not thereby verifying its signature. Use a verified custom profile callback when your callback trust model requires that additional check.

## Provider-specific options

| Field | Behavior |
| --- | --- |
| `AppBundleIdentifier` | Optional native-app bundle identifier added to the accepted ID-token audiences. |
| `Audience` | A string or list of additional accepted ID-token audiences; falls back to AppBundleIdentifier and then ClientID. |

## Start sign-in

```http
POST /api/auth/sign-in/social HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Origin: https://app.example.com

{
  "provider": "apple",
  "callbackURL": "https://app.example.com/account"
}
```

When `callbackURL` is accepted by trusted-origin validation, the server stores it in the OAuth state and returns to it after a successful callback. Configure `Options.TrustedOrigins` for every browser origin and callback destination your application uses.

## Direct provider API

The configured value also exposes transport-neutral primitives:

```go
authorizationURL, err := appleProvider.CreateAuthorizationURL(providers.AuthorizationInput{
    State:        state,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/apple",
})

tokens, err := appleProvider.ValidateAuthorizationCode(ctx, providers.CodeInput{
    Code:         code,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/apple",
})

profile, err := appleProvider.GetUserInfo(ctx, tokens)
```

Use those primitives only when implementing a custom server flow. The normal auth routes additionally enforce state, cookies, account-linking policy, session creation, hooks, rate limits, and trusted origins.

## Security and behavior notes

- Authorization uses `form_post` and requests both an authorization code and an ID token.
- Apple may only return the user's name on the first authorization; the callback-specific user object is preserved when it is present.
- The verifier used by direct ID-token sign-in checks Apple's JWKS, issuer, audience, token age, and nonce.

- Keep the client secret in server-side configuration and never expose it to a browser.
- Register the exact callback URL, including `Options.BasePath` and the provider ID.
- Preserve OAuth state and PKCE cookies through the callback; do not terminate the flow on a different hostname unless cookie and trusted-origin settings are designed for it.
- Use a redirect-refusing HTTP client policy for endpoints you override, or validate every redirect target yourself.
