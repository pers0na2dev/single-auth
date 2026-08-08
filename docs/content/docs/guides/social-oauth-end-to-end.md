---
title: "Social OAuth end to end"
description: "Configure a provider, start browser sign-in, validate state and PKCE, complete callbacks, and diagnose linking or redirect failures."
---

Social sign-in crosses four systems: the browser application, single-auth, the
provider authorization server, and your shared storage. Configure the public
URL and state authority before debugging provider-specific profile fields.

## 1. Fix the public callback URL

For the default base path, a Google callback is:

```text
https://accounts.example.com/api/auth/callback/google
```

Register that exact URL in the provider console. It is derived from the public
base URL, base path, and provider ID. Do not register the frontend callback URL
or the internal service address.

For one public host, use a static URL:

```go
BaseURL: "https://accounts.example.com",
```

For intentional multi-host service, constrain `DynamicBaseURL.AllowedHosts`
and supply a fallback. Read [Deploy behind a proxy](./deploy-behind-a-proxy.md)
before enabling forwarded-host resolution.

## 2. Construct and register the provider

```go
package authsetup

import (
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/protocol/providers"
    "github.com/pers0na2dev/single-auth/storage"
)

func New(primary storage.Adapter) (*singleauth.Auth, error) {
    google, err := providers.Google(providers.Options{
        ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
        ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    })
    if err != nil {
        return nil, err
    }

    return singleauth.New(singleauth.Options{
        Environment: "production",
        BaseURL:      "https://accounts.example.com",
        Secret:       os.Getenv("SINGLE_AUTH_SECRET"),
        Database:     primary,
        SocialProviders: map[string]*providers.Provider{
            "google": google,
        },
        TrustedOrigins: []string{
            "https://app.example.com",
        },
    })
}
```

Provider constructors validate and snapshot their options. The map key must
match the provider identity used by the flow. A provider-specific HTTP client
overrides the root `HTTPClient`; otherwise all provider requests share the root
client, whose default timeout is 30 seconds.

Keep the client secret server-side. Never send it to a browser or store it in a
user/account metadata field.

## 3. Start sign-in

From the browser application, send a cookie-capable POST with its real origin:

```bash
curl --fail-with-body \
  --cookie-jar oauth-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: https://app.example.com' \
  --request POST \
  --data '{
    "provider":"google",
    "callbackURL":"https://app.example.com/dashboard",
    "errorCallbackURL":"https://app.example.com/sign-in",
    "newUserCallbackURL":"https://app.example.com/welcome",
    "disableRedirect":true
  }' \
  https://accounts.example.com/api/auth/sign-in/social
```

With `disableRedirect:true`, the response returns the provider authorization
URL without requiring the HTTP client to follow it immediately:

```json
{
  "url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "redirect": false
}
```

Navigate the browser to that URL. The server has already generated random
state and PKCE material and persisted the validated callback destinations.

Redirect fields must be safe relative URLs or match a trusted origin. A string
beginning `//`, containing a backslash or encoded slash, or targeting another
origin is rejected before the provider flow begins.

## 4. Preserve state cookies

The browser must retain every `Set-Cookie` line from the sign-in response and
send matching cookies to the callback host. Common causes of state failure are:

- the callback host differs from the host that started sign-in;
- a proxy changed HTTPS to HTTP from the browser's point of view;
- `Secure`, domain, or path attributes prevent the cookie from returning;
- an HTTP client comma-joined multiple `Set-Cookie` lines;
- the active secret changed while the browser was at the provider;
- the callback arrived after state expiry;
- the callback was replayed after an atomic database/secondary consume.

The default state strategy is cookie only when no explicit primary or secondary
store was configured. With a configured store, database state is the default.
Set `Account.StoreStateStrategy` explicitly when deployment policy should not
depend on that construction detail.

Database/secondary state is atomically consumed and bound to a signed browser
cookie. Cookie state is encrypted and expired in the response, but a copied
pre-expiry cookie has no shared server-side consumed marker. Prefer database
state when cross-request replay rejection matters.

## 5. Complete the callback

The provider redirects to `GET` or `POST /callback/:id`. The runtime:

1. validates provider ID, state, cookie binding, and expiry;
2. atomically consumes stored state when applicable;
3. exchanges the authorization code using the PKCE verifier;
4. fetches or validates provider identity data;
5. resolves an existing provider account, links an eligible local user, or
   creates the user/account transactionally;
6. creates a session and writes its cookies;
7. redirects to the already validated callback, new-user, or error URL.

Do not put application authorization decisions in a callback query parameter.
Persist invitation/tenant context in trusted state or re-authorize it after the
session is established.

## Account linking rules

Implicit linking is enabled by default but requires a trusted provider identity
and, by default, a verified matching local email. Configure policy explicitly:

```go
func boolPtr(value bool) *bool { return &value }

options.Account = singleauth.AccountOptions{
    EncryptOAuthTokens: true,
    AccountLinking: singleauth.AccountLinkingOptions{
        Enabled:                   boolPtr(true),
        RequireLocalEmailVerified: boolPtr(true),
        TrustedProviders:          []string{"google"},
        AllowDifferentEmails:      false,
        AllowUnlinkingAll:         false,
        DisableImplicitLinking:    false,
    },
}
```

`TrustedProviders` is an explicit trust decision, not a list to copy from the
configured provider map. `AllowDifferentEmails` applies to explicit linking;
it does not make an untrusted implicit email match safe.

The explicit `POST /link-social` route requires a session. Unlinking requires a
fresh session and rejects removal of the last login method unless
`AllowUnlinkingAll` is enabled.

## Tokens and refresh

`UpdateAccountOnSignIn` defaults to true. Enable `EncryptOAuthTokens` when
stored access and refresh tokens must be encrypted at rest. Retain versioned
secrets until encrypted values are rewritten or expired.

Core authenticated routes provide:

- `POST /get-access-token`;
- `POST /refresh-token`;
- `GET /account-info`;
- `GET /list-accounts`;
- `POST /unlink-account`.

Near expiry, access-token lookup may serialize a refresh, call the provider,
and persist the new token set. A provider without refresh support or a stored
refresh token cannot perform that path. Inspect returned expiry values rather
than assuming every stored access token is current.

## Error diagnosis

| Symptom | First evidence to inspect |
| --- | --- |
| Provider says redirect mismatch | Exact generated `redirect_uri`, public base URL, base path, provider ID, provider-console entry. |
| `STATE_MISMATCH` or state error | State cookie domain/path/secure flag, shared store, atomic consume, active secret, expiry, callback host. |
| Callback returns an application error redirect | Query `error` and `error_description`, server typed error code, validated saved error URL. |
| User is not linked | Provider email verification, local email verification, trusted-provider policy, existing account ownership. |
| Callback loops to sign-in | Whether session `Set-Cookie` reached the browser and is returned to the application/auth host. |
| Works on one replica only | Shared state/session store, identical secrets/cookies/base URL, callback load-balancer routing. |
| Token refresh fails | Stored refresh token, provider refresh implementation, token encryption key availability, upstream response. |

Log stable error codes and provider response metadata without logging state,
authorization codes, client secrets, access tokens, refresh tokens, ID tokens,
or complete session cookies.

Continue with [Accounts and social sign-in](../core/accounts-and-social.md),
[provider common options](../social-providers/common-options.md), and the
provider-specific page in [Social providers](../social-providers/index.md).
