---
title: "Amazon Cognito"
---

Configure Amazon Cognito social sign-in in the native Go server.

Import `github.com/pers0na2dev/single-auth/protocol/providers` and construct the provider with `providers.Cognito`. The provider ID is `cognito`, so its default callback URL is `https://<your-auth-host>/api/auth/callback/cognito`.

> **Info: Provider console**
>
> Configure an app client and hosted UI domain in the Cognito user pool.

## Configuration

```go
cognitoProvider, err := providers.Cognito(providers.Options{
    ClientID:     os.Getenv("COGNITO_CLIENT_ID"),
    ClientSecret: os.Getenv("COGNITO_CLIENT_SECRET"),
    Domain:       os.Getenv("COGNITO_DOMAIN"),
    Region:       os.Getenv("COGNITO_REGION"),
    UserPoolID:   os.Getenv("COGNITO_USER_POOL_ID"),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        cognitoProvider.ID: cognitoProvider,
    },
})
```

The provider constructor does not contact the remote service. Network activity starts when an authorization URL is created, a callback exchanges a code, profile data is fetched, a token is refreshed, or a remote JWKS is required.

## Provider behavior

| Property | Value |
| --- | --- |
| Authorization endpoint | `https://auth.example.auth.us-east-1.amazoncognito.com/oauth2/authorize` |
| Token endpoint | `https://auth.example.auth.us-east-1.amazoncognito.com/oauth2/token` |
| User-info endpoint | `https://auth.example.auth.us-east-1.amazoncognito.com/oauth2/userinfo` |
| Default scopes | `openid, profile, email` |
| Token client authentication | `post (default)` |
| Refresh-token implementation | Yes |
| Direct ID-token verifier | Yes |
| JWKS URI | `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example/.well-known/jwks.json` |

`Options.Scopes` are appended to the defaults. Set `DisableDefaultScope` only when the remote application is intentionally configured with a complete replacement scope set.

> **Warning: ID-token verification is flow-specific**
>
> `Provider.VerifyIDToken` and the verifier row above describe the direct ID-token sign-in/link path. The normal authorization-code callback currently exchanges the code and calls `GetUserInfo`; it does not automatically invoke that verifier. A provider that decodes an ID token while mapping a profile is not thereby verifying its signature. Use a verified custom profile callback when your callback trust model requires that additional check.

## Provider-specific options

| Field | Behavior |
| --- | --- |
| `Domain` | Required Cognito hosted UI domain, with or without an http(s) scheme. |
| `Region` | Required AWS region used to construct the issuer and JWKS URI. |
| `UserPoolID` | Required Cognito user-pool ID. |
| `RequireClientSecret` | When true, construction/sign-in requires a client secret in addition to the client ID. |

## Start sign-in

```http
POST /api/auth/sign-in/social HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Origin: https://app.example.com

{
  "provider": "cognito",
  "callbackURL": "https://app.example.com/account"
}
```

When `callbackURL` is accepted by trusted-origin validation, the server stores it in the OAuth state and returns to it after a successful callback. Configure `Options.TrustedOrigins` for every browser origin and callback destination your application uses.

## Direct provider API

The configured value also exposes transport-neutral primitives:

```go
authorizationURL, err := cognitoProvider.CreateAuthorizationURL(providers.AuthorizationInput{
    State:        state,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/cognito",
})

tokens, err := cognitoProvider.ValidateAuthorizationCode(ctx, providers.CodeInput{
    Code:         code,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/cognito",
})

profile, err := cognitoProvider.GetUserInfo(ctx, tokens)
```

Use those primitives only when implementing a custom server flow. The normal auth routes additionally enforce state, cookies, account-linking policy, session creation, hooks, rate limits, and trusted origins.

## Security and behavior notes

- The constructor rejects missing Domain, Region, or UserPoolID.
- Profile data is decoded from the ID token first and falls back to the user-info endpoint; that mapping step does not itself verify the token signature.
- The verifier used by direct ID-token sign-in checks the user-pool issuer, JWKS, audience, token age, and nonce.

- Keep the client secret in server-side configuration and never expose it to a browser.
- Register the exact callback URL, including `Options.BasePath` and the provider ID.
- Preserve OAuth state and PKCE cookies through the callback; do not terminate the flow on a different hostname unless cookie and trusted-origin settings are designed for it.
- Use a redirect-refusing HTTP client policy for endpoints you override, or validate every redirect target yourself.
