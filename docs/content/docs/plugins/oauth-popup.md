---
title: "OAuth popup"
description: "Complete social OAuth in a popup and hand the resulting session to one exact trusted opener origin."
---

OAuth popup starts a configured social OAuth flow in a popup and replaces the final callback redirect with a small completion document. That document sends the result to one exact trusted opener origin with `postMessage`, then closes the popup.

## Install and configure

Import `github.com/pers0na2dev/single-auth/plugins/oauthpopup` and configure at least one root social provider or [Generic OAuth](./generic-oauth.md) provider. `NewFactory` accepts no options.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/oauthpopup"
    "github.com/pers0na2dev/single-auth/protocol/providers"
)

func main() {
    google, err := providers.Google(providers.Options{
        ClientID: os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    })
    if err != nil {
        log.Fatal(err)
    }
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"https://app.example.com"},
        SocialProviders: map[string]*providers.Provider{"google": google},
        PluginFactories: []singleauth.PluginFactory{oauthpopup.NewFactory()},
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The OAuth provider keeps its normal callback URI. The popup plugin observes successful and failed callback redirects under `/callback/` and `/oauth2/callback/`; it does not register a replacement provider callback.

For an embedded cross-site application that will authenticate with the handed-off token, also install [Bearer](./bearer.md). A same-site application can rely on normal session cookies, but must still verify the completion message.

## Start route

| Method | Path | Input | Success result | Authority |
| --- | --- | --- | --- | --- |
| GET | `/oauth-popup/start` | Query parameters below | 302 to provider authorization URL | Exact trusted `popupOrigin` and trusted callback URLs |

Open a URL shaped like this in a new browser window:

```text
https://auth.example.com/api/auth/oauth-popup/start?provider=google&popupOrigin=https%3A%2F%2Fapp.example.com&popupNonce=random-correlation-value&callbackURL=https%3A%2F%2Fapp.example.com%2Fdashboard
```

| Query parameter | Required | Behavior |
| --- | --- | --- |
| `provider` | yes | Root social/generic provider ID |
| `popupOrigin` | yes | Exact trusted origin used as the `postMessage` target |
| `popupNonce` | no at the server | Opaque correlation value echoed in the completion message |
| `callbackURL` | no | Final application redirect; defaults to the resolved root base URL |
| `errorCallbackURL` | no | OAuth error redirect carried through root state |
| `newUserCallbackURL` | no | Final redirect for a newly registered user |
| `requestSignUp` | no | Only the literal string `true` sets the state flag |
| `scopes` | no | Comma-separated provider scopes |
| `additionalData` | no | JSON object merged into OAuth state after reserved keys are removed |

`popupOrigin` is checked without relative-URL allowance. Callback URLs are checked through the root trusted-origin policy with relative paths allowed. Missing provider/origin returns a 400 JSON error; an untrusted opener returns 403 `INVALID_ORIGIN`.

An unknown provider or invalid start-stage callback does not navigate to a normal error page. When the opener origin is already trusted, the server returns the completion HTML immediately with an error payload such as `provider_not_found` or `invalid_callback_url`.

Use an object for `additionalData`. Invalid JSON becomes an empty object. Array or string JSON has compatibility coercion to numeric keys, but should not be used in new code. Internal keys such as callback URLs, verifier, OAuth state, expiry, link state, and sign-up state cannot be overwritten.

## Completion message

After the root provider callback creates a session, the after-hook reads the new session cookie from the callback response and returns HTML instead of the redirect. The page posts this object to `window.opener`, falling back to `window.parent`:

```json
{
  "type": "single-auth:oauth-popup",
  "nonce": "random-correlation-value",
  "token": "session-token",
  "redirectTo": "https://app.example.com/dashboard"
}
```

An OAuth failure carries an error instead of a token:

```json
{
  "type": "single-auth:oauth-popup",
  "nonce": "random-correlation-value",
  "error": {
    "code": "access_denied",
    "description": "The user cancelled sign-in"
  }
}
```

The completion page itself enforces:

- `targetOrigin` equal to the validated `popupOrigin`, never `*`;
- `Content-Security-Policy: default-src 'none'` with the exact inline-script SHA-256 and `base-uri 'none'`;
- `Cache-Control: no-store` and `Pragma: no-cache`;
- JSON embedded in a non-executable `application/json` element;
- immediate popup close after the message attempt.

The marker cookie contains only opener origin and correlation nonce. It is signed with the root secret, inherits root cookie attributes, expires after ten minutes, and is cleared when a matching callback is handled. The OAuth state remains the authorization-flow replay boundary.

## Browser-side responsibilities

This Go package intentionally does not provide a JavaScript client. The application opening the popup must:

1. generate a high-entropy, single-use `popupNonce`;
2. retain the expected auth origin, popup window reference, and nonce;
3. accept messages only from the exact auth origin and expected popup window;
4. require `data.type == "single-auth:oauth-popup"` and an exact nonce match;
5. handle timeout, popup-blocked, popup-closed, token, and error outcomes;
6. clear correlation state after the first accepted completion.

`POPUP_BLOCKED`, `POPUP_CLOSED`, and `POPUP_TIMEOUT` are exported compatibility codes for application-side handling. The Go server cannot observe those browser events and does not emit them from `/oauth-popup/start`. `POPUP_SIGN_IN_FAILED` covers a server-side failure to start the OAuth flow.

The completion token is an authentication credential. Keep it out of URLs, logs, analytics, persistent browser storage, and third-party messages. The server deliberately transfers it only to the validated origin, but the receiving application must still apply the checks above.

## Bearer and embedded applications

When the receiving application is embedded cross-site, third-party cookie policy may prevent the session cookie from being used. The completion message still contains the session token. Install the bearer plugin and send that token according to its documented header contract. OAuth popup logs a one-time warning when it hands off a token without bearer installed.

Do not add bearer merely to skip origin/nonce validation: bearer makes possession of the token authoritative and therefore increases the impact of a leaked or misrouted message.

## Direct API, schema, and ordering

There is no bound server service. `oauthPopupStart` can be called with
`auth.API().Call`, but a useful direct call must reproduce the same browser
state and response-cookie propagation.

The plugin adds no schema or migration. It uses root OAuth state and session cookies. It can be registered in any plugin order; install the provider configuration in the same `Auth`, and install bearer when an embedded token consumer requires it.

## Replay, failure, and troubleshooting

- The signed marker prevents an attacker from changing the opener origin or nonce, but signing is not encryption and those values are not secret.
- Clearing the marker limits ordinary browser reuse. A copied valid marker cookie remains accepted within its ten-minute lifetime; OAuth state/code validation still determines whether a callback can create a session.
- A missing/invalid marker leaves the root callback redirect unchanged. This prevents ordinary non-popup OAuth flows from being captured.
- If a callback response does not set a session cookie but redirects with `error`, the hook sends that error to the opener. Other redirects remain unchanged.
- `INVALID_ORIGIN` means `popupOrigin` is not an exact root trusted origin. Compare scheme, host, and port.
- An immediate `invalid_callback_url` completion means a callback URL failed the root trusted-origin check before OAuth state was created.
- A normal redirect instead of completion usually means the marker cookie was not returned, was invalid, expired, or had cookie attributes incompatible with the callback context.
- A completion message ignored by the application usually has the wrong event origin, window source, message type, or nonce. Reject it; do not loosen the checks.
- If embedded authentication succeeds in the popup but subsequent API calls are unauthenticated, configure bearer and attach only the received token to the intended auth requests.

## Related pages

- [Generic OAuth](./generic-oauth.md)
- [Bearer](./bearer.md)
- [Accounts and social providers](../core/accounts-and-social.md)
- [Social OAuth end to end](../guides/social-oauth-end-to-end.md)
- [Security](../core/security.md)

**Status:** implemented with trusted-origin, callback, marker-signature, CSP, token/error handoff, provider compatibility, and normal-redirect preservation coverage.
