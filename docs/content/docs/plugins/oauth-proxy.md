---
title: "OAuth proxy"
description: "Relay OAuth callbacks through a stable production URI and finish the session on a trusted preview deployment."
---

OAuth proxy lets ephemeral preview deployments use an OAuth provider that accepts only a stable production callback URI. The production deployment exchanges the provider code and sends an authenticated-encrypted profile package back to the preview; the preview consumes its original state, creates or links the user, and issues the session locally.

## Deployment model

Configure the plugin and the same root social or [Generic OAuth](./generic-oauth.md) provider on both deployments:

- `https://auth.example.com` is the stable production auth origin registered with the OAuth provider;
- `https://preview-42.example.dev` is the current preview origin;
- both deployments share a dedicated OAuth-proxy secret or secret rotation set;
- the preview retains its own root OAuth state and creates its own session.

The two deployments may use different root auth secrets when they share an explicit proxy `Secret` or `SecretConfig`. Without a dedicated proxy secret, both must be able to decrypt the root-encrypted relay values.

Register this provider callback:

```text
https://auth.example.com/api/auth/callback/github
```

## Configure preview and production

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/oauthproxy"
    "github.com/pers0na2dev/single-auth/protocol/providers"
)

func newAuth(currentURL string) (*singleauth.Auth, error) {
    github, err := providers.GitHub(providers.Options{
        ClientID: os.Getenv("GITHUB_CLIENT_ID"),
        ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    })
    if err != nil {
        log.Fatal(err)
    }
    return singleauth.New(singleauth.Options{
        BaseURL: currentURL,
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{
            "https://auth.example.com",
            "https://preview-42.example.dev",
        },
        SocialProviders: map[string]*providers.Provider{"github": github},
        PluginFactories: []singleauth.PluginFactory{
            oauthproxy.NewFactory(oauthproxy.Options{
                CurrentURL:    currentURL,
                ProductionURL: "https://auth.example.com",
                Secret:        os.Getenv("OAUTH_PROXY_SECRET"),
            }),
        },
    })
}

func main() {
    auth, err := newAuth("https://preview-42.example.dev")
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

Deploy the same constructor at production with `currentURL == "https://auth.example.com"`. On the production origin, same-origin detection skips preview rewriting for ordinary production sign-ins while the callback hook can process an encrypted proxy state package sent by a preview flow.

## Flow

```text
preview sign-in
  -> provider authorization URL with encrypted state
  -> provider redirects to production /callback/:provider
  -> production exchanges code and reads provider profile
  -> production redirects encrypted profile to preview /oauth-proxy-callback
  -> preview consumes original state, creates session, redirects to application
```

More precisely:

1. The preview before-hook replaces the requested callback with its trusted `/oauth-proxy-callback?callbackURL=...` URL.
2. The preview after-hook packages and encrypts the original OAuth state. When `ProductionURL` is explicit and the provider has no dedicated `RedirectURI`, it rewrites `redirect_uri` to production `/callback/:provider`.
3. Production decrypts the package, validates the embedded state, exchanges the provider code, obtains user info and tokens, and redirects an authenticated-encrypted passthrough payload to the preview callback. This intercepted production path does not create the preview user/session.
4. The preview validates callback origin, decrypts and age-checks the package, atomically consumes its original state in database mode, runs the root OAuth user/account flow, issues its session cookies, and redirects to the original or new-user URL.

The hooks cover root `/sign-in/social` and `/sign-in/oauth2`. The intercepted provider callback is the root `/callback/:id` route; Generic OAuth providers work because the factory also registers them as root social providers.

## Callback endpoint

| Method | Path | Input | Result | Authority |
| --- | --- | --- | --- | --- |
| GET | `/oauth-proxy-callback` | `callbackURL`, encrypted `profile` | 302 to final/new-user/error URL | Trusted callback URL, live encrypted payload, original OAuth state |

`callbackURL` is required and checked through the root trusted-origin policy with relative URLs allowed. An untrusted value returns 403 `INVALID_CALLBACK_URL`. The encrypted `profile` is created only by the production callback; clients must not construct or modify it.

Missing, invalid, malformed, expired, future-dated, or state-mismatched packages redirect to the configured error URL with values such as `missing_profile`, `invalid_profile`, `invalid_payload`, `payload_expired`, or `state_mismatch`.

The successful preview step applies normal root signup and account-linking policy. It redirects a new user to the state `newUserURL` when supplied, otherwise to the original callback.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `CurrentURL` | resolved request/vendor/base URL | Trusted origin receiving the preview relay callback |
| `ProductionURL` | `SINGLE_AUTH_URL`, then root `BaseURL` | Stable callback origin used for provider `redirect_uri` and same-origin detection |
| `MaxAge` | 1 minute | Maximum accepted passthrough age; zero selects the default and negative values fail setup |
| `Secret` | root encryption | Dedicated legacy-compatible proxy key shared by preview and production |
| `SecretConfig` | none | Rotation-aware proxy key set; takes precedence over `Secret` and is snapshotted |

`CurrentURL` and `ProductionURL` must be absolute HTTP(S) URLs with scheme and host. An explicit current URL wins. Otherwise the plugin considers the request URL only when its origin is trusted, then supported platform environment values, then the root resolved base URL. This prevents an untrusted Host/forwarded origin from selecting the relay receiver.

`NewFactory()` with no options is valid and derives configuration from the root runtime and environment. Explicit URLs and a dedicated secret are easier to audit for a multi-environment production setup.

The non-empty `X-Skip-OAuth-Proxy` request header bypasses proxy rewriting. Reserve it for trusted internal calls and strip it at untrusted edges; do not expose it as an end-user switch.

## Secret rotation

Prefer `SecretConfig` when rotating a shared relay secret:

```go
proxySecrets, err := authcrypto.NewSecretConfig([]authcrypto.SecretEntry{
    {Version: 2, Value: os.Getenv("OAUTH_PROXY_SECRET_CURRENT")},
    {Version: 1, Value: os.Getenv("OAUTH_PROXY_SECRET_PREVIOUS")},
}, "")
if err != nil {
    return err
}

factory := oauthproxy.NewFactory(oauthproxy.Options{
    CurrentURL:    currentURL,
    ProductionURL: "https://auth.example.com",
    SecretConfig:  &proxySecrets,
})
```

Deploy the read-compatible rotation set to both sides before changing the current version. Remove the old key only after every relay encrypted with it is older than `MaxAge` and all replicas have converged.

## Schema, state, replay, and concurrency

The plugin adds no model. It uses root `user`, `account`, and `session` records and whichever root OAuth state strategy is configured.

In database state mode, the preview finds and atomically consumes the original core `verification` row. A relay can therefore produce at most one successful preview session across replicas when the adapter's verification consumption is atomic.

In cookie state mode, the preview verifies the encrypted cookie state, binds it to the OAuth state, checks expiry, and clears it. Independently copied cookies can still be replayed until expiry because there is no central consumed-state record. Prefer database state for cross-replica/global replay prevention.

Relay packages use authenticated encryption, are bound to the original state, expire after `MaxAge`, and reject timestamps more than ten seconds in the future. Authentication callbacks can run concurrently, so provider callbacks and custom root user/account behavior must be concurrency-safe.

## Token and URL security

The encrypted passthrough contains provider profile data plus access, refresh, and ID tokens needed to create the preview account. Encryption protects confidentiality and integrity, but the ciphertext is carried in a URL and can still appear in reverse-proxy, browser-history, tracing, or analytics logs.

- use HTTPS on both deployments;
- disable query-string logging and third-party analytics on callback paths;
- keep `MaxAge` short;
- share the proxy secret only with the participating deployments;
- trust only the exact preview origins that may receive a relay;
- keep production provider credentials and callback host tightly controlled;
- do not reuse the relay key for unrelated application encryption.

The production deployment receives provider tokens and profile data but does not persist the preview user in the intercepted flow. Normal production sign-ins remain normal same-origin flows.

## Direct API

There is no separately bound server service. Trusted code can call
`oAuthProxy` through `auth.API().Call` with the same inputs. The protocol
remains hook-driven: a successful call still requires the original state
storage/cookies, trusted callback URL, encrypted profile, realistic
scheme/host, and response-cookie propagation.

Direct calls bypass outer HTTP origin checks and rate limiting; the endpoint's own trusted-callback and cryptographic checks still apply.

## Troubleshooting

- A provider `redirect_uri_mismatch` usually means production `/api/auth/callback/:provider` was not registered exactly, or the provider's explicit `RedirectURI` prevented automatic rewriting.
- `invalid_profile` almost always means preview and production use different proxy secrets/rotation sets or a relay was corrupted.
- `payload_expired` means the round trip exceeded `MaxAge` or deployment clocks disagree; synchronize clocks before increasing the window.
- `state_mismatch` means the preview state was missing, expired, already consumed, or created under a different storage/cookie context.
- A flow that stays entirely on preview may have same-origin detection using the wrong production URL. Set both URLs explicitly.
- A relay sent to the root base URL instead of preview usually means `CurrentURL` was omitted and the request origin was not in `TrustedOrigins`.
- A production callback that creates a production session instead of relaying usually did not receive/decrypt the proxy state package, often because secrets differ.
- If the final redirect is rejected, add only the exact application origin to root `TrustedOrigins`; do not broadly weaken callback validation.

## Related pages

- [Generic OAuth](./generic-oauth.md)
- [Accounts and social providers](../core/accounts-and-social.md)
- [Social OAuth end to end](../guides/social-oauth-end-to-end.md)
- [Secret rotation](../guides/rotate-secrets.md)
- [Multi-replica sessions](../guides/multi-replica-sessions.md)
- [Security boundaries](../protocols/security-boundaries.md)

**Status:** implemented with cross-origin and same-origin flows, social and generic sign-in hooks, encrypted state/profile relays, dedicated/rotated secrets, database/cookie state, replay, expiry, callback trust, form-post callback, transport, and concurrency coverage.
