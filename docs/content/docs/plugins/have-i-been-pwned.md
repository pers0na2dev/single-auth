---
title: "Have I Been Pwned"
description: "Reject compromised passwords through the Pwned Passwords k-anonymity range protocol before hashing."
---

Have I Been Pwned wraps the root password-hash chain and rejects a password whose SHA-1 suffix appears in the Pwned Passwords range response. The plaintext password and full digest are never sent to the service.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/haveibeenpwned` and use `NewFactory`. The wrapper runs at the actual hash step, after each endpoint's earlier validation or proof checks and before the configured password hasher. It therefore also covers compatible password operations contributed by installed plugins.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/haveibeenpwned"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            haveibeenpwned.NewFactory(haveibeenpwned.Options{}),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

Factories that wrap password hashing compose in registration order. Keep the order stable and test the resulting failure precedence when combining this plugin with custom password-policy wrappers. `NewFactory` supplies the root request-aware hash chain and root `HTTPClient`; standalone `New` requires an explicit `Runtime.WrapPasswordHash` and is intended for embedding/tests.

## Covered password operations

With `Paths:nil`, checks run when the endpoint context's declared route path is exactly one of:

| Path | Operation |
| --- | --- |
| `/sign-up/email` | Email/password sign-up |
| `/change-password` | Authenticated password change |
| `/reset-password` | Reset-token password replacement |
| `/email-otp/reset-password` | Email-OTP password replacement |
| `/phone-number/reset-password` | Phone-number password replacement |
| `/admin/create-user` | Optional password on administrator-created user |
| `/admin/set-user-password` | Administrator credential replacement |

`Paths` replaces the complete list. Unlike CAPTCHA, nil and an explicit empty slice differ: nil selects the defaults, while `[]string{}` disables checks on every endpoint path. Custom paths are exact route-pattern matches, not raw URL substring matches.

The check runs only when all of these are true:

1. `Enabled` is nil or true.
2. The hash call has a non-nil endpoint context.
3. `ctx.Path()` is non-empty and exists in `Paths`.
4. The password is non-empty.

Calls to the underlying hasher outside an endpoint context bypass the plugin. Endpoint-level required and length validation remains authoritative for empty or malformed passwords.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `CustomPasswordCompromisedMessage` | `The password you entered has been compromised. Please choose a different password.` | Replaces only the public `PASSWORD_COMPROMISED` message |
| `Paths` | nil, selecting the seven paths above | Non-nil slice replaces the list; explicit empty protects none |
| `Enabled` | nil, interpreted as `true` | Use `haveibeenpwned.Bool(false)` for an explicit disable |
| `HTTPClient` | Root client, then `http.DefaultClient` | Performs the range request; configure timeout, proxy, TLS, and observability policy here |
| `Runtime.WrapPasswordHash` | Bound by `NewFactory` | Standalone wrapper registrar |

The range base URL is the exported constant `haveibeenpwned.RangeAPIBaseURL` and is not an option. Tests or controlled egress proxies can supply an `HTTPClient` transport that rewrites the request. Do not make routing depend on user input.

## Range protocol

For a non-empty password, the checker:

1. Computes the uppercase SHA-1 digest required by the Pwned Passwords protocol.
2. Sends only the first five hexadecimal characters in `GET https://api.pwnedpasswords.com/range/<prefix>`.
3. Adds `Add-Padding: true` and `User-Agent: Reference Password Checker`.
4. Compares the remaining digest suffix, case-insensitively, with the text before `:` on every response line.
5. Ignores breach counts; any matching suffix rejects the password.

SHA-1 here is a protocol lookup key, not the application's password storage hash. An accepted password is still passed to the configured root password hasher.

The package also exports a direct server utility:

```go
err := haveibeenpwned.CheckPassword(ctx, candidate, haveibeenpwned.Options{
    HTTPClient: client,
})
```

`CheckPassword` performs a direct range check and does not consult `Enabled` or `Paths`; it returns nil for an empty password. It does not hash or persist the password.

## Results and failure ordering

There is no success payload because the plugin owns no route. A safe password continues to the next password-hash function. A compromised password stops the current endpoint with:

| Status | Code | Message |
| --- | --- | --- |
| 400 | `PASSWORD_COMPROMISED` | Configured compromised message |

The plugin fails closed on service failures:

| Status | Code | Message |
| --- | --- | --- |
| 500 | `INTERNAL_SERVER_ERROR` | `Failed to check password. Status: <status>` for a non-2xx response |
| 500 | `INTERNAL_SERVER_ERROR` | `Failed to check password. Please try again later.` for transport, nil-response, missing-body, or read errors |

Status 300 and above is a provider failure. The cause is retained server-side for transport-style failures but the safe public message is stable.

The check occurs at each endpoint's actual hash point, not at a global request hook. Consequences visible in the current Go behavior include:

- Password length validation can reject sign-up before any range request.
- Email sign-up deliberately hashes on the duplicate-account timing path, so a compromised-password error can win over duplicate-account disclosure.
- `change-password` hashes the new password before validating the current password.
- Core reset-token validation and email-OTP/phone proof consumption happen before hashing; an invalid or replayed proof does not call the range service.
- A valid one-time proof may already be consumed when the password is then rejected. Issue a new proof for the next attempt.

## Storage, concurrency, and availability

The plugin contributes no route, model, cookie, verification row, or migration. It reads no local breach database and caches no range responses. Every applicable non-empty hash attempt performs one outbound request.

The implementation has no independent timeout; the request inherits its endpoint context and the configured HTTP client's policy. Set a finite client timeout and size/egress controls appropriate for production. Because provider/network/parser failures reject the password operation, Pwned Passwords availability is part of the write path's latency and availability budget.

The compiled wrapper keeps immutable path/options state and is safe for concurrent calls. The configured `HTTPDoer` must also be concurrency-safe. No replay primitive is needed: the service is a deterministic policy lookup, while any reset/OTP replay guarantees remain owned by the originating endpoint.

## Security and troubleshooting

- The five-character prefix is k-anonymous, not zero disclosure. It reveals a digest range and the request timing to the provider. Review the service against your privacy and network policies.
- Never log the plaintext candidate, full digest, or returned matching suffix. Ensure custom transports and tracing redact request metadata as needed.
- Use a dedicated `http.Client` with an explicit timeout. `http.DefaultClient` has no total request timeout.
- `PASSWORD_COMPROMISED` on an account that already exists can be intentional timing behavior; do not turn it into an account-existence signal in UI copy.
- If a known compromised password is accepted, inspect `Enabled`, the nil-versus-empty `Paths` distinction, the exact endpoint route path, and whether hashing happened without an endpoint context.
- If every password write returns 500, test outbound DNS/TLS/proxy access and inspect the provider status. The plugin intentionally does not fail open.
- Adding a custom password endpoint to `Paths` is effective only if that endpoint calls the root request-aware password hash chain.

See [Email and password](../core/email-and-password.md), [Security](../core/security.md), [Errors and logging](../core/errors-and-logging.md), and the [Have I Been Pwned package reference](../reference/packages/plugins--haveibeenpwned.md).

**Status:** implemented with hash-chain integration, direct checking, failure ordering, concurrency, and admin/email/phone plugin coverage.
