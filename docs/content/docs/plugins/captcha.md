---
title: "CAPTCHA"
description: "Verify Turnstile, reCAPTCHA, hCaptcha, or CaptchaFox tokens before selected HTTP authentication requests."
---

CAPTCHA blocks selected HTTP authentication requests until an external human-verification provider accepts the `x-captcha-response` token. It runs before auth route dispatch, so rejected requests do not reach endpoint validation or storage.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/captcha` and use `NewFactory` so the plugin inherits the root HTTP client, base path, trusted-proxy-aware IP resolver, and logger. Register it once; it adds no routes or schema.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/captcha"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            captcha.NewFactory(captcha.Options{
                Provider:  captcha.CloudflareTurnstile,
                SecretKey: os.Getenv("TURNSTILE_SECRET"),
                Endpoints: []string{"/sign-up/email", "/sign-in/email"},
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

The protected client request supplies the provider token in a header:

```http
POST /api/auth/sign-in/email HTTP/1.1
Content-Type: application/json
Origin: https://app.example.com
x-captcha-response: <provider-token>

{"email":"ada@example.com","password":"correct horse battery staple"}
```

The selected auth endpoint still applies its normal body validation, origin/CSRF rules, rate limits, authentication, and storage behavior after CAPTCHA succeeds.

## Protected paths

When `Endpoints` is nil **or empty**, these path fragments are protected:

- `/sign-up/email`
- `/sign-in/email`
- `/request-password-reset`

`Endpoints` replaces that list only when it contains at least one value. Matching uses path-fragment containment after removing the configured auth base path; it is not an exact route match and is not restricted by HTTP method. Prefer full auth route paths such as `/sign-in/email` and audit similarly named custom routes.

`/sign-in/email-otp` is specially exempt from the default `/sign-in/email` substring match. To protect email-OTP sign-in, include the exact `/sign-in/email-otp` entry explicitly:

```go
Endpoints: []string{
    "/sign-up/email",
    "/sign-in/email",
    "/sign-in/email-otp",
    "/request-password-reset",
},
```

An empty slice does not disable protection. If an installation must protect no paths, omit the plugin rather than relying on an empty `Endpoints` value.

## Providers

Use only the exported provider constants:

| Provider | Verification request | Additional checks/options |
| --- | --- | --- |
| `captcha.CloudflareTurnstile` | JSON to Cloudflare Turnstile | Optional `ExpectedAction` and exact `AllowedHostnames` |
| `captcha.GoogleRecaptcha` | URL-encoded form to Google reCAPTCHA | `MinScore` (0.5 when nil), optional `ExpectedAction`, exact `AllowedHostnames` |
| `captcha.HCaptcha` | URL-encoded form to hCaptcha | Optional `SiteKey` |
| `captcha.CaptchaFox` | URL-encoded form to CaptchaFox | Optional `SiteKey` |

All providers receive `SecretKey`, the client token, and the resolved client IP when non-empty. Turnstile uses the JSON field `remoteip`; Google and hCaptcha use the form field `remoteip`; CaptchaFox uses `remoteIp`. `SiteKey` is sent only to hCaptcha and CaptchaFox.

Turnstile and Google first require a truthy provider `success`. When configured, `ExpectedAction` must match exactly and `AllowedHostnames` must contain the returned hostname exactly. Google rejects a numeric score below `MinScore`; a missing/non-numeric score follows upstream compatibility and is not rejected by the score check. hCaptcha and CaptchaFox use only the provider `success` result.

> **Warning: validate `Provider` before startup**
>
> An unknown provider value is intentionally preserved for compatibility. No verification branch executes, so a protected request proceeds without CAPTCHA verification. Reject unknown configuration in application startup code and never construct provider names from request data.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `Provider` | Empty/unknown | Must be one of the four exported constants; unknown values fail open at request time |
| `SecretKey` | Empty | Required for protected requests; missing value returns `500 UNKNOWN_ERROR` |
| `Endpoints` | Three default paths above when nil or length zero | Non-empty slice replaces the protected fragments |
| `SiteVerifyURLOverride` | Provider's exported verify URL | Sends verification to a controlled proxy/test endpoint instead |
| `MinScore` | nil, interpreted as `0.5` | Google only; use `captcha.Score(0)` to preserve an explicit zero |
| `ExpectedAction` | Empty | Exact action check for Turnstile and Google |
| `AllowedHostnames` | Empty | Exact hostname allowlist for Turnstile and Google |
| `SiteKey` | Empty | Optional request field for hCaptcha and CaptchaFox |
| `Runtime.HTTPClient` | Root `HTTPClient`, then `http.DefaultClient` | Outbound provider transport |
| `Runtime.BasePath` | Root `BasePath`, then `/api/auth` | Prefix removed before fragment matching |
| `Runtime.ResolveIPAddress` | Root resolver | Supplies the provider remote-IP value |
| `Runtime.Logger` | Root logger | Records internal provider failures without exposing their detail to the client |

Every provider request receives a child context with a ten-second deadline (`captcha.VerifyTimeout`). A shorter deadline on the incoming request or custom transport may finish earlier. `SiteVerifyURLOverride` is trusted server configuration: require HTTPS in production and do not derive it from an incoming request.

## Responses and errors

CAPTCHA middleware errors use a small JSON body and intentionally do not add `Content-Type`:

| Status | Code | Message | Cause |
| --- | --- | --- | --- |
| 400 | `MISSING_RESPONSE` | `Missing CAPTCHA response` | Header is absent or the combined value is empty |
| 403 | `VERIFICATION_FAILED` | `Captcha verification failed` | Provider response is valid but verification/policy returns false |
| 500 | `UNKNOWN_ERROR` | `Something went wrong` | Missing secret, timeout, transport error, non-2xx provider status, nil/malformed response, read failure, or recovered panic |

Repeated `x-captcha-response` fields are combined with comma-space semantics before verification. Send exactly one header. Internal failures are logged with the requested endpoint and fail closed as `UNKNOWN_ERROR`; provider details are not returned to the caller.

There are no success body or CAPTCHA-specific response headers. On success the middleware returns control to the selected auth endpoint, whose normal response contract applies.

## Direct API, storage, and concurrency

`OnRequest` is an outer HTTP middleware stage. Calls through `auth.API()` deliberately bypass it, even when they invoke a path listed in `Endpoints`. Direct callers are trusted server code and must apply their own abuse controls if untrusted traffic can reach them.

The HTTP middleware is exercised through `net/http`, direct `fasthttp`, and Fiber. There is no CAPTCHA route, bound service, model, or migration.

The plugin stores only immutable option snapshots and is safe for concurrent requests. The configured `HTTPDoer`, IP resolver, and logger must also be concurrency-safe. Each protected request performs one outbound verification; there is no response cache or replay store in this plugin. Provider-side token single-use and replay behavior remains provider policy.

## Security and troubleshooting

- Keep `SecretKey` server-only and redact both it and `x-captcha-response` from logs, traces, and error reporting.
- Configure trusted proxy headers before using the resolved client IP. Otherwise the provider may receive a proxy address or a spoofable value; see [Deploy behind a proxy](../guides/deploy-behind-a-proxy.md).
- CAPTCHA is abuse resistance, not authentication or authorization. Keep endpoint rate limiting, CSRF/origin validation, password policy, and account-enumeration protections enabled.
- `MISSING_RESPONSE` usually means the frontend did not copy the widget result into `x-captcha-response`, or a proxy removed the custom header.
- `VERIFICATION_FAILED` with a provider success often indicates an `ExpectedAction`, hostname, or score mismatch. Compare exact case-sensitive configured values with the provider response in protected server diagnostics.
- `UNKNOWN_ERROR` indicates configuration or provider availability. Check the root logger, custom HTTP client's proxy/TLS policy, and the ten-second deadline.
- If a custom route is unexpectedly protected, remember that `Endpoints` uses substring matching. If email-OTP is unexpectedly unprotected, add its exact route explicitly.
- Verify unknown-provider rejection in application configuration tests; the compatibility fail-open branch is unsafe as configuration validation.

See [Security](../core/security.md), [Hooks and middleware](../core/hooks-and-middleware.md), [Rate limiting and production checks](../getting-started/production-checklist.md), and the [CAPTCHA package reference](../reference/packages/plugins--captcha.md).

**Status:** implemented with provider request parity, failure handling, concurrency, and all HTTP transport coverage.
