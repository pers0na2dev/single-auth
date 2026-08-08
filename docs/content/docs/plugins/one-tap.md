---
title: "Google One Tap"
description: "Verify a Google One Tap ID token and exchange it for a normal single-auth user and session."
---

Google One Tap accepts a Google ID token, verifies it for the configured audience, normalizes the Google profile, and routes it through the same root user, account-linking, signup, and session lifecycle as social OAuth.

## Install and configure

Import `github.com/pers0na2dev/single-auth/plugins/onetap`. The recommended setup configures the root Google provider and uses the same audience for normal Google OAuth and One Tap.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/onetap"
    "github.com/pers0na2dev/single-auth/protocol/providers"
)

func main() {
    clientID := os.Getenv("GOOGLE_CLIENT_ID")
    google, err := providers.Google(providers.Options{
        ClientID: clientID,
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    })
    if err != nil {
        log.Fatal(err)
    }
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret: os.Getenv("SINGLE_AUTH_SECRET"),
        SocialProviders: map[string]*providers.Provider{"google": google},
        PluginFactories: []singleauth.PluginFactory{
            onetap.NewFactory(onetap.Options{ClientID: clientID}),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

When `onetap.Options.ClientID` is empty, the plugin uses `socialProviders.google.Options.ClientID`, including a configured list of audiences. An explicit plugin `ClientID` takes precedence. A root Google provider is optional only when the plugin has an explicit client ID; in that standalone case, the server constructs a minimal Google provider for the root account flow.

## HTTP route

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/one-tap/callback` | JSON `idToken` | Root `token` and serialized `user` | Valid Google ID token for configured audience and hosted-domain policy |

```http
POST /api/auth/one-tap/callback
Content-Type: application/json
Origin: https://app.example.com

{"idToken":"eyJhbGciOiJSUzI1NiIs..."}
```

```json
{
  "token": "session-token",
  "user": {
    "id": "user-id",
    "name": "Ada",
    "email": "ada@example.com",
    "emailVerified": true,
    "image": "https://..."
  }
}
```

`idToken` is the only consumed body field. The JSON body limit is 4 MiB. Browser form/origin policy still runs at the root transport boundary.

The default verifier fetches Google's public keys and verifies the signature, accepted Google issuer, configured audience, expiry/time policy, and required JWT structure. A valid payload must contain non-empty `sub`. If the root Google provider has `HostedDomain` configured, the token's `hd` claim must match; `HostedDomain: "*"` requires a non-empty hosted-domain claim.

The handler lowercases email. `email_verified` is accepted as boolean `true` or string `"true"`. It maps `sub`, `name`, `email`, `picture`, and verification status into the root Google account flow, stores the ID token through the normal account contract, refreshes the root session cookies, and returns the public serialized user.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `ClientID` | root Google client ID | Expected token audience; explicit value wins |
| `DisableSignup` | `false` | Prevent unknown Google identities from creating users |
| `VerifyIDToken` | built-in Google verifier | Replace the entire ID-token trust boundary |

Root Google `DisableSignUp` is ORed with plugin `DisableSignup`; either setting prevents new-user creation. Existing users and permitted root account linking still use normal root behavior. A linking conflict is returned as 401 `UNAUTHORIZED`.

### Custom verifier

Use `VerifyIDToken` only when a specialized trusted integration requires it. It receives the raw token and resolved audience and must return a claims map only after full cryptographic and semantic verification.

```go
VerifyIDToken: func(
    ctx context.Context,
    input onetap.VerifyIDTokenInput,
) (map[string]any, error) {
    claims, err := verifier.VerifyGoogle(ctx, input.Token)
    if err != nil {
        return nil, err
    }
    if !audienceAllowed(claims["aud"], input.Audience) {
        return nil, errors.New("unexpected Google audience")
    }
    return claims, nil
},
```

A safe replacement validates the signature with trusted keys, pins allowed algorithms, accepts only Google's issuer, matches `aud`, validates expiry and applicable time claims, requires `sub`, and applies any nonce/hosted-domain policy needed by the application. It must be concurrency-safe. Returning decoded but unverified JWT claims is an account-takeover vulnerability.

The `VerifyIDTokenInput.HTTPClient` field exists for compatibility but the installed handler does not populate it. Configure outbound behavior through the root Google provider's `HTTPClient`, or close over a controlled client in the custom verifier.

## Responses and errors

| Status | Result | Meaning |
| --- | --- | --- |
| 400 `BAD_REQUEST` | `idToken is required` | Missing, empty, or non-string token |
| 400 `BAD_REQUEST` | Google client ID is required | Neither plugin nor root provider supplies an audience |
| 400 `BAD_REQUEST` | `invalid id token` | Verification failed, `sub` is missing, or hosted domain is not allowed |
| 200 JSON | `{"error":"Email not available in token"}` | Verified token has no usable email |
| 401 `UNAUTHORIZED` | root link error | Account cannot be linked under root policy |
| root OAuth error | provider/user/session-specific | Signup disabled, persistence failure, or another root social-flow failure |

The missing-email case deliberately returns HTTP 200 for compatibility. Treat the presence of top-level `error` as failure; do not assume every 2xx body contains a session token.

## Direct API

There is no separately bound server service. Trusted code can call
`oneTapCallback` through `auth.API().Call` with a POST body containing
`idToken`.

Direct dispatch runs endpoint hooks but bypasses outer HTTP origin checks, rate limiting, and transport body limits. It still invokes the configured verifier; direct invocation never makes an unverified token trustworthy. Add independent abuse controls before exposing it through another protocol.

## Schema, replay, and concurrency

The plugin adds no model or migration. It uses root `user`, `account`, and `session` models. The Google account ID is the verified `sub`, and normal root uniqueness/linking policy applies.

An ID token is not consumed by this plugin. The same still-valid token can be submitted again and may issue another session, subject to root session policy. If the application needs one-prompt/one-session semantics, add a nonce/jti replay policy around issuance and verification; do not weaken JWT checks or assume Google token reuse is automatically rejected.

Concurrent valid callbacks are isolated, but root adapter constraints determine whether account/user creation races collapse correctly. Use a transactional storage backend and retain root account uniqueness guarantees for multi-replica deployments.

## Security and troubleshooting

- Keep the browser-side Google client ID and server audience aligned. An audience mismatch intentionally returns `invalid id token`.
- Use the root Google provider's controlled `HTTPClient` with finite timeouts and TLS/redirect policy for public-key fetches.
- Set `HostedDomain` when access must be limited to a Workspace tenant; checking only the email suffix is insufficient.
- Do not log ID tokens or return raw claims to clients. The token may contain identity data and is stored as a provider credential.
- If every token fails after a client-ID change, update both browser issuance and server audience configuration before rolling traffic.
- If valid consumer Gmail users fail, check whether `HostedDomain` was accidentally configured or set to `*`.
- If a 200 response has no `token`, inspect the top-level `error`; the verified token may not contain email.
- Browser prompt rendering, cancellation, and FedCM/One Tap UI are application responsibilities. This package implements only the server exchange.

## Related pages

- [Google provider](../social-providers/google.md)
- [Accounts and social providers](../core/accounts-and-social.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)
- [Direct API](../transports/direct-api.md)

**Status:** implemented with audience, hosted-domain, malformed-token, signup, linking, concurrency, direct, and all server-transport coverage.
