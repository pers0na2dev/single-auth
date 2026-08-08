---
title: "Deploy behind a reverse proxy"
description: "Configure the public auth URL, trusted forwarded headers, client IP resolution, secure cookies, and browser origins behind a proxy."
---

A reverse proxy changes three security-relevant facts: the public scheme and
host, the apparent peer IP, and which component terminates TLS. Configure each
explicitly. A working health route is not proof that OAuth callbacks, cookies,
CSRF checks, and rate limits see the correct public request.

## Prefer one static public URL

When every request uses one public origin, set `BaseURL` to that external URL
even if the Go process listens on plain HTTP inside the network:

```go
auth, err := singleauth.New(singleauth.Options{
    Environment: "production",
    BaseURL:      "https://accounts.example.com",
    BasePath:     "/api/auth",
    Secret:       os.Getenv("SINGLE_AUTH_SECRET"),
    TrustedOrigins: []string{
        "https://app.example.com",
    },
})
```

This makes callback URLs deterministic and derives secure cookies from HTTPS.
The reverse proxy should forward `/api/auth/*` without removing or adding a
second copy of the base path.

Expected public routes include:

```text
https://accounts.example.com/api/auth/ok
https://accounts.example.com/api/auth/sign-in/email
https://accounts.example.com/api/auth/callback/google
```

Configure the provider console with the exact callback URL. A URL using the
internal host, internal HTTP scheme, or a duplicated path will fail after the
browser leaves your application.

## Trust forwarded hosts only when needed

`X-Forwarded-Host` and `X-Forwarded-Proto` are unnecessary for a static
`BaseURL`. If application code needs them for dynamic resolution, explicitly
trust them only when an untrusted client cannot connect directly to the Go
listener:

```go
func boolPtr(value bool) *bool { return &value }

options.Advanced.TrustedProxyHeaders = boolPtr(true)
```

The runtime validates forwarded host and protocol syntax, but syntax validation
does not prove that the header came from your proxy. Enforce that trust at the
load balancer, firewall, service mesh, or private listener.

Do not pass a comma-separated forwarded host chain. The runtime rejects it.
The forwarded protocol must be `http` or `https`.

## Dynamic multi-host deployments

Use `DynamicBaseURL` only when the same runtime intentionally serves more than
one public auth host:

```go
auth, err := singleauth.New(singleauth.Options{
    Environment: "production",
    DynamicBaseURL: &singleauth.DynamicBaseURLOptions{
        AllowedHosts: []string{
            "accounts.example.com",
            "*.accounts.example.com",
        },
        Protocol: "https",
        Fallback: "https://accounts.example.com",
    },
    BasePath: "/api/auth",
    Secret:   os.Getenv("SINGLE_AUTH_SECRET"),
})
```

`AllowedHosts` is mandatory. `Fallback` supplies an absolute URL for trusted
direct calls that do not carry an HTTP host and for requests whose host cannot
be resolved safely. `Protocol: "https"` is simpler than `auto` when the public
edge always uses TLS.

With `auto`, the runtime considers a valid trusted `X-Forwarded-Proto`, the
request scheme, loopback development, and finally HTTPS. Dynamic mode defaults
`TrustedProxyHeaders` to true; make sure the service cannot be reached around
the trusted proxy.

## Resolve the real client IP

Session metadata, rate limiting, and several plugins share one client-IP
resolver. Configure the header and every proxy hop that may appear on the
right-hand side of the chain:

```go
import "github.com/pers0na2dev/single-auth/security/ratelimit"

options.Advanced.IPAddress = ratelimit.IPOptions{
    Headers: []string{"x-forwarded-for"},
    TrustedProxies: []string{
        "10.20.0.0/16",
        "192.0.2.10",
    },
}
```

The resolver walks a configured chain from right to left, removes trusted
proxy hops, and selects the first untrusted address. A malformed hop fails
closed. Without a valid trusted-proxy list, only one syntactically valid IP is
accepted; a comma-separated chain is rejected rather than trusted blindly.

Do not add a public client range to `TrustedProxies`. The entries identify
infrastructure allowed to append forwarding information, not end users.

## Cookies and TLS termination

For a static HTTPS `BaseURL`, cookies are secure even when proxy-to-service
traffic uses HTTP. In dynamic deployments, make the decision explicit when
environment or forwarded-protocol behavior could vary:

```go
options.Advanced.UseSecureCookies = boolPtr(true)
```

Secure mode sets `Secure` and uses the secure cookie prefix. The default also
uses `HttpOnly`, `SameSite=Lax`, and `Path=/`.

Cross-subdomain cookies are a separate choice. Enable them only when multiple
applications must receive the same credential and set the narrowest domain:

```go
options.Advanced.CrossSubDomainCookies = singleauth.CrossSubDomainCookieOptions{
    Enabled: true,
    Domain:  ".example.com",
}
```

Sharing a parent-domain cookie expands the set of hosts that can influence an
authentication flow. It does not replace `TrustedOrigins` or tenant
authorization.

## Browser origin policy

List application origins, not route URLs:

```go
TrustedOrigins: []string{
    "https://app.example.com",
    "https://admin.example.com",
},
```

Cookie-authenticated unsafe methods require a trusted `Origin` or `Referer`.
Redirect-bearing fields such as `callbackURL`, `errorCallbackURL`, and
`newUserCallbackURL` must also be relative or match a trusted origin.

Do not disable origin or CSRF checks to compensate for a proxy mistake.
`DisableOriginCheck: true` also prevents the current origin-based CSRF
validator from providing effective protection.

## Proxy contract

Verify these facts in the proxy configuration:

| Concern | Required behavior |
| --- | --- |
| TLS | Browser uses HTTPS; HTTP redirects to HTTPS before credentials are sent. |
| Host | Preserve the intended public host or set one trusted forwarded host. |
| Scheme | Preserve HTTPS semantics or set trusted `X-Forwarded-Proto: https`. |
| Client IP | Append to, rather than blindly replace, the controlled forwarding chain. |
| Cookies | Preserve every `Set-Cookie` line separately; never comma-join them. |
| Request body | Preserve JSON/form content type and enforce a reasonable size limit at the edge. |
| Path | Forward the configured `BasePath` exactly once. |
| Redirects | Preserve `Location` without rewriting it to an internal origin. |

## Verification sequence

1. Request the public `/api/auth/ok` URL and confirm status 200.
2. Inspect a sign-in response and confirm every session cookie has `Secure`,
   the expected domain/path, and the public host context.
3. Send a cookie-authenticated POST with the real application `Origin`; it
   should pass. Repeat with an unrelated origin; it must fail.
4. Start a social sign-in and verify the generated provider `redirect_uri`.
5. Confirm session records contain the expected client IP, not the proxy IP or
   an attacker-controlled header.
6. Exercise enough rejected requests to observe a 429 and verify replicas use
   the intended rate-limit store.

Continue with [Security](../core/security.md),
[net/http transport](../transports/net-http.md), and
[Troubleshooting](./troubleshooting.md).
