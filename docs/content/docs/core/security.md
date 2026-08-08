---
title: "Security"
---

Secrets, cookies, CSRF, redirect validation, trusted proxies, verification replay, and rate limiting.

Security policy is transport-neutral and lives in the shared dispatcher. `net/http`, direct `fasthttp`, and Fiber therefore enforce the same cookie, origin, redirect, host, and rate-limit behavior. Trusted direct API calls intentionally skip HTTP-only gates and must not be exposed without equivalent controls.

## Secrets

The active secret protects signed session tokens, session cache values, OAuth-state cookie bindings, email tokens, and legacy encrypted values. The versioned configuration additionally protects supported version-tagged OAuth state, account-data, stored OAuth token, and plugin-encrypted values. The precedence is:

1. `Options.Secrets`;
2. parsed `SINGLE_AUTH_SECRETS`;
3. `Options.Secret`;
4. `SINGLE_AUTH_SECRET`;
5. `AUTH_SECRET`;
6. the built-in development fallback.

The fallback is rejected only when `Environment` is explicitly `production`. Set the environment rather than relying on process naming.

### Versioned rotation

```go
import baCrypto "github.com/pers0na2dev/single-auth/security/crypto"

options.Secrets = []baCrypto.SecretEntry{
    {Version: 3, Value: os.Getenv("AUTH_SECRET_V3")},
    {Version: 2, Value: os.Getenv("AUTH_SECRET_V2")},
    {Version: 1, Value: os.Getenv("AUTH_SECRET_V1")},
}
```

The first entry becomes the active `Secret` and encrypts new version-tagged values. Retained entries decrypt those versioned envelopes. A legacy `Secret` may remain as a decoder for legacy unversioned encrypted values. Environment syntax is `3:new,2:previous,1:old`.

Rotation does not transparently preserve every format. Session-token signatures, compact/JWT/JWE session-cache values, verification-email JWTs, do-not-remember cookies, and OAuth-state cookie bindings are verified only with the active secret. Replacing the first entry invalidates those values and can interrupt an in-flight OAuth browser flow even when the encrypted state envelope remains decryptable. Retain old keys for version-tagged encrypted OAuth/account/plugin values, and separately plan reauthentication and new verification messages. The runtime warns for active secrets shorter than 32 characters or estimated below 120 bits of entropy outside test mode.

## Cookie security

The default cookie policy is:

```text
prefix:    better-auth
Path:      /
HttpOnly:  true
SameSite:  lax
Secure:    derived from configuration
```

Secure mode prepends `__Secure-` and sets `Secure`. An explicit `UseSecureCookies` wins. Otherwise a static URL derives it from its scheme, dynamic protocol `https` enables it, dynamic protocol `http` disables it, and dynamic `auto`/empty retains the initial `Environment == "production"` decision. General cookies are not re-derived per request in dynamic auto mode; dynamic cross-subdomain cookie resolution is the exception because it rebuilds cookie configuration from the resolved URL. Set `UseSecureCookies` explicitly when dynamic proxy behavior must not depend on environment defaults.

Use pointer fields in `CookieOverride` when explicitly changing false-capable attributes. A per-cookie override is keyed by canonical names such as `session_token`, `session_data`, `dont_remember`, `state`, `oauth_state`, and `account_data`.

Cross-subdomain cookies are disabled by default. When enabled, specify the narrowest domain possible. A static URL can supply an omitted domain; dynamic mode resolves it per allowed request. `AdditionalCookies` lets plugins share selected extra cookies under the same policy.

## Unsafe request CSRF checks

The core security middleware runs for every matched HTTP path before user/plugin path middleware. `GET`, `HEAD`, and `OPTIONS` skip unsafe-method CSRF processing.

For other methods:

- any request carrying a `Cookie` header must provide a non-null trusted `Origin` or `Referer`;
- cookie-free sign-up/sign-in form requests inspect `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and `Sec-Fetch-Dest`;
- cross-site navigation login (`cross-site` plus `navigate`) is rejected with `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`;
- if fetch metadata or an origin/referrer is present for a cookie-free form request, it is validated;
- other cookie-free non-form requests do not require browser-origin proof at this generic layer.

The origin must exactly match or satisfy a configured trusted-origin pattern. `Origin: null`, missing origin on a cookie request, and an untrusted referer fail closed.

## Redirect validation

Unsafe requests also validate `callbackURL`, `redirectTo`, `errorCallbackURL`, and `newUserCallbackURL` when present. `callbackURL` may also be read from the query where a route supports it.

An absolute HTTP(S) redirect must match a trusted origin. Safe relative redirects:

- begin with one `/`, never `//`;
- contain no backslash;
- contain no percent-encoded slash or backslash;
- use the supported path/query character set.

Invalid fields return their dedicated error codes. Non-string values return `BAD_REQUEST`.

Trusted origins are assembled, in order, from:

1. the static runtime origin or origins implied by dynamic allowed hosts;
2. `Options.TrustedOrigins`;
3. static plugin origins;
4. `ResolveTrustedOrigins`;
5. plugin origin resolvers;
6. comma-separated `SINGLE_AUTH_TRUSTED_ORIGINS`.

Resolvers receive a cloned request and their returned slices are copied. Errors become redacted internal errors with the server-side cause retained.

## Disabling checks

Leave these settings unset for browser authentication.

`DisableCSRFCheck: true` skips CSRF proof. `DisableOriginCheck: true` skips redirect-origin validation and also makes the current origin-based CSRF validator return without validation. Better Auth 1.6 compatibility adds a configuration distinction:

- `DisableOriginCheck=true` with `DisableCSRFCheck=nil` disables both and emits a deprecation warning;
- `DisableOriginCheck=true` with an explicit `DisableCSRFCheck=false` opts out of that compatibility branch and warning, but it does **not** restore effective CSRF origin validation in the current runtime.

`SkipOriginCheckPaths` disables both checks for an exact endpoint-relative path and slash-boundary children. `/protocol/callback` matches itself and `/protocol/callback/child`, not `/protocol/callback-evil`. Use it only for external protocol callbacks that perform their own signature, state, replay, issuer, and audience validation.

## Static and dynamic public URLs

A static `BaseURL` is the safest deployment. It must include `http://` or `https://`; invalid or non-HTTP schemes fail construction.

Dynamic mode requires `AllowedHosts` and accepts protocol `http`, `https`, or `auto`. `http` and `https` pin the scheme. `auto` and empty use a valid trusted `X-Forwarded-Proto`, then the request scheme, then HTTP for a loopback host, and finally HTTPS. Host patterns may contain wildcards. Incoming hosts are validated before matching; malformed values, unsafe characters, invalid ports, and comma-separated forwarded chains are rejected. An unallowed or missing host uses `Fallback` when set, otherwise the request fails.

`TrustedProxyHeaders` defaults to false in static/ordinary request resolution and true in dynamic mode. When enabled, `X-Forwarded-Host` and `X-Forwarded-Proto` are trusted only after syntactic validation. Ensure an untrusted client cannot reach the application while supplying those headers.

Typed direct inputs normally have no host or scheme. Dynamic deployments should set `Fallback`, or low-level direct callers must provide `Scheme` and `Host` explicitly.

## Client IP resolution

`Advanced.IPAddress` is shared by session tracking, rate limiting, and plugins. The default header is `x-forwarded-for`.

Without any valid `TrustedProxies`, only a single syntactically valid IP is accepted. A comma-separated chain is rejected. With trusted proxy IPs/CIDRs, the chain is parsed from right to left, trusted hops are stripped, and the first untrusted address is the client. Any malformed hop fails closed.

IPv4-mapped IPv6 is normalized to IPv4. IPv6 is expanded and grouped to `/64` by default. An explicit `IPv6Subnet`, including zero, is honored. Development or test mode falls back to `127.0.0.1`; production returns no IP when none is trustworthy.

Invalid trusted-proxy entries are ignored with a startup warning. `DisableTracking` returns no IP and also bypasses rate limiting.

## HTTP rate limiting

An omitted `RateLimit.Enabled` is enabled only when `Environment == "production"`. The defaults are 100 requests per 10 seconds for each normalized IP/path bucket.

Built-in sensitive rules override the default:

| Routes | Rule |
| --- | --- |
| prefixes `/sign-in`, `/sign-up`, `/change-password`, `/change-email` | 3 per 10 seconds |
| `/request-password-reset`, `/send-verification-email`, reset/OTP send equivalents | 3 per 60 seconds |

Plugin rule groups are evaluated in plugin order; the first match in the first matching group wins. Ordered `CustomRules` run afterward and can replace the rule, disable limiting for a pattern, or resolve a request-specific rule.

```go
enabled := true

RateLimit: singleauth.RateLimitOptions{
    Enabled: &enabled,
    Window:  30,
    Max:     200,
    CustomRules: []ratelimit.CustomRule{
        {
            Pattern: "/health/internal",
            Disabled: true,
        },
        {
            Pattern: "/sign-in/*",
            Rule: ratelimit.Rule{Window: 60, Max: 5},
        },
    },
},
```

Storage selection is:

1. `CustomStorage` when supplied;
2. explicit `memory`, `database`, or `secondary-storage`;
3. secondary storage when configured;
4. isolated memory.

Database mode materializes the configurable `rateLimit` model. Secondary mode requires a configured secondary backend. Strict enforcement under concurrency requires `ratelimit.AtomicStorage`; legacy get/set storage is best effort and warns once. A secondary store implementing `ratelimit.SecondaryIncrementer` provides atomic increments.

When no trusted IP is available, requests share `no-trusted-ip|<path>` and a warning is emitted. That is safer than trusting an attacker-controlled forwarded chain, but one client may throttle others until proxy configuration is fixed.

Rejected requests return status 429, `X-Retry-After` in seconds, `Content-Type: text/plain;charset=UTF-8`, and the exact body:

```json
{"message":"Too many requests. Please try again later."}
```

The limiter is an HTTP `OnRequest` stage. Direct API and `Invoke` calls bypass it.

## Verification replay protection

Verification identifiers are plain by default. Configure SHA-256 storage or a custom hasher when database disclosure should not reveal raw identifiers:

```go
Verification: singleauth.VerificationOptions{
    StoreIdentifier: singleauth.VerificationIdentifierStorage{
        Strategy: singleauth.VerificationIdentifierHashed,
        Overrides: []singleauth.VerificationIdentifierOverride{
            {
                Prefix:   "public-debug:",
                Strategy: singleauth.VerificationIdentifierPlain,
            },
        },
    },
},
```

The built-in hashed strategy stores SHA-256 as unpadded base64url. Overrides are ordered and the first matching prefix wins. A custom `Hash` takes precedence over `Strategy`.

With secondary storage, verification values are cache-only unless `StoreInDatabase` is true. Single-use consumption should be atomic through the primary adapter's `ConsumeOne` or the secondary `GetAndDelete` extension. The runtime uses scoped locks to close same-process races, but cross-process replay safety still depends on the backend.

`DisableCleanup` preserves expired database verification rows instead of deleting them during normal cleanup. It does not make an expired value valid.

## Direct API boundary

Direct calls are for already trusted server code. They run endpoint middleware, before/after hooks, provider logic, storage, and verification behavior, but skip:

- HTTP rate limiting;
- CSRF and redirect-origin security path middleware;
- user/plugin path middleware;
- plugin `OnRequest` and `OnResponse`;
- transport request/response observers.

If an HTTP route delegates to a direct call, the wrapper must independently enforce origin/CSRF, authentication, rate limiting, host policy, maximum body size, and response cookie propagation.
