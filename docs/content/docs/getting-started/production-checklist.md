---
title: "Production checklist"
---

Required storage, secret, proxy, cookie, origin, and operational checks before deployment.

The zero-value configuration is intentionally convenient for development, not production. Complete every applicable item before serving real accounts.

## Required runtime configuration

- Set `Environment: "production"` explicitly. The root runtime does not infer it from `SINGLE_AUTH_ENV`.
- Configure a stable HTTPS `BaseURL` when one public auth origin exists. Use `DynamicBaseURL` only for a real multi-host deployment and always set `AllowedHosts` plus a safe `Fallback`.
- Keep the default `/api/auth` path or mount every transport at the exact configured `BasePath`.
- Supply a durable primary adapter. The implicit memory adapter loses users and sessions on restart and is isolated per process.
- Run schema migrations before accepting traffic. A raw SQLite runtime or an adapter implementing `storage.SchemaEnsurer` can run them; an arbitrary adapter without that capability cannot.

```go
auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
    Environment: "production",
    BaseURL:     "https://accounts.example.com",
    Secret:      os.Getenv("SINGLE_AUTH_SECRET"),
}, db)
if err != nil {
    return err
}
if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

## Secrets and rotation

- Generate at least 32 random characters; a higher-entropy value such as 48 random bytes encoded as base64 is preferable.
- Never use the built-in fallback in production. Construction fails when explicit production mode sees it.
- For rotation, put the new key first and retain older keys while version-tagged encrypted OAuth/account/plugin values still need decryption.
- Expect an active-key change to invalidate session-token signatures, session-cache values, verification-email JWTs, do-not-remember cookies, and OAuth-state cookie bindings. The retained ring does not provide seamless rotation for those active-secret-only formats.
- Store `SINGLE_AUTH_SECRETS` as an ordered ring such as `3:new,2:previous,1:old`. Versions must be valid and unique.
- Treat OAuth tokens, session cookies, verification records, database backups, and logs as secrets even when token encryption is enabled.

```go
import (
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    baCrypto "github.com/pers0na2dev/single-auth/security/crypto"
)

options := singleauth.Options{
    Secrets: []baCrypto.SecretEntry{
        {Version: 3, Value: os.Getenv("AUTH_SECRET_V3")},
        {Version: 2, Value: os.Getenv("AUTH_SECRET_V2")},
    },
}
```

## Cookies and HTTPS

- Terminate browser traffic over HTTPS. Secure mode adds the `__Secure-` prefix and the `Secure` attribute.
- Verify proxy scheme and host forwarding before relying on dynamic base URLs. With dynamic `auto`/empty protocol, cookie `Secure` is not generally recalculated per request: it keeps the production-environment default unless `UseSecureCookies` is explicit. Set `UseSecureCookies: true` in production dynamic deployments.
- Keep `HttpOnly`, `SameSite=Lax`, and `Path=/` unless a reviewed integration requires a change.
- When enabling cross-subdomain cookies, set the narrowest possible domain. Sharing a parent-domain cookie trusts every application that can write cookies for that domain.
- Do not put unbounded user or plugin data in the session cookie cache. Values are chunked at 4,050 bytes per cookie, with at most 100 chunks, and an oversized payload is skipped.
- If `rememberMe=false`, expect a browser-session token cookie and a 24-hour logical session; do not interpret the lack of `Max-Age` as an unlimited session.

## Origins, redirects, and CSRF

- Add every real browser application origin to `TrustedOrigins`; include scheme and host, and include the development origin only in development configuration.
- Cookie-authenticated unsafe requests must send `Origin` or `Referer`. Fix the caller instead of disabling checks.
- Keep redirect targets in trusted origins or use safe relative paths beginning with one `/`.
- Never put a broad wildcard in `TrustedOrigins` or dynamic `AllowedHosts` without understanding which tenants it admits.
- Leave `DisableOriginCheck` and `DisableCSRFCheck` unset. If a protocol endpoint cannot send browser origin headers, scope `SkipOriginCheckPaths` to that exact endpoint subtree and make the endpoint validate its own signed protocol message.
- Remember that `SkipOriginCheckPaths` disables both redirect-origin and CSRF validation for the matched path and slash-boundary children.

## Proxies and client IPs

- Prefer a static `BaseURL`. If proxy headers are enabled, ensure only a trusted ingress can write `X-Forwarded-Host` and `X-Forwarded-Proto`.
- The dynamic URL resolver rejects comma-separated forwarded host/protocol chains; it does not select an attacker-controlled first element.
- Configure `Advanced.IPAddress.Headers` for the header your ingress actually supplies.
- Configure `TrustedProxies` with the exact proxy IPs or CIDRs before accepting a multi-hop `X-Forwarded-For` chain. Without trusted proxies, only a single IP value is accepted.
- IPv6 clients are grouped by `/64` by default. Change `IPv6Subnet` only as an explicit abuse-control decision.

```go
Advanced: singleauth.AdvancedOptions{
    IPAddress: ratelimit.IPOptions{
        Headers:        []string{"x-forwarded-for"},
        TrustedProxies: []string{"10.0.0.0/8", "192.0.2.10"},
    },
},
```

## Rate limiting

- Explicit production mode enables the limiter when `RateLimit.Enabled` is omitted. Set it explicitly if configuration is shared across environments.
- The default is 100 requests per 10 seconds per client IP and route. Sign-in, sign-up, password-change, and email-change routes use 3 per 10 seconds; reset and verification-email send routes use 3 per 60 seconds.
- The default memory backend is per process. Use secondary or database storage when limits must be shared by replicas.
- Strict concurrent enforcement requires `ratelimit.AtomicStorage`. A legacy get/set store is best effort and emits a warning.
- For Redis-like secondary storage, implement `ratelimit.SecondaryIncrementer` to make increments atomic.
- If no trustworthy IP can be resolved, production requests share the `no-trusted-ip` bucket per path. Treat the warning as a proxy configuration problem.

## Sessions and secondary storage

- Decide whether the database or secondary store is authoritative. With secondary storage configured, sessions and verification values use it by default.
- Set `Session.StoreSessionInDatabase` only if you need a database copy in addition to the authoritative secondary entry.
- Set `PreserveSessionInDatabase` only for a deliberate audit-retention policy; revocation still removes the authoritative secondary entry.
- Secondary verification consumption must be atomic across processes. Implement `SecondaryGetAndDeleter` or `SecondaryValueGetAndDeleter` for replay-safe single-use values.
- Increase `CookieCache.Version` when a cached session/user shape or authorization assumption changes, forcing old cache cookies to miss.
- Sensitive endpoints bypass the stateful cache, but ordinary cached session reads can remain valid until `CookieCache.MaxAge`. Choose that duration as an explicit revocation-latency tradeoff.

## Email and provider operations

- Configure real mail callbacks before enabling required email verification, password reset, email change, or verification-based deletion.
- Make mail callbacks retry-safe. Nil `RunBackground` is synchronous; provide a durable job runner if delivery should outlive the request.
- Password-reset and unauthenticated verification-email endpoints intentionally avoid account enumeration. Preserve their generic responses and timing behavior in surrounding application code.
- Use an `http.Client` with bounded timeouts. The default is 30 seconds; provider-specific clients inherit it unless they supply their own.
- Enable `EncryptOAuthTokens` when access and refresh tokens require application-layer encryption, and preserve old secrets during rotation so retained values remain decryptable. Core `idToken` fields are not covered by that option; enforce separate storage encryption or avoid retaining them when required by your threat model.

## Observability and failure handling

- Supply a concurrency-safe logger callback or writers. The default threshold is `warn`, with warnings/errors on stderr.
- Inspect `contract.APIError` on trusted server calls, but do not expose `Cause`. Unknown errors are deliberately serialized as `500 INTERNAL_SERVER_ERROR`.
- Health-check `GET /api/auth/ok` through the same ingress and transport used by clients.
- Alert on storage errors, repeated secret-quality warnings, invalid proxy warnings, rate-limit fallback warnings, and provider callback failures.

## Release verification

Before rollout, exercise the configured real backend and every mounted transport:

1. sign up, sign in, session read, refresh, sign out, and revoked-cookie rejection;
2. password reset replay rejection and optional session revocation;
3. email verification success, expiry, malformed token, and callback validation;
4. social authorization, database-state atomic replay rejection or the selected cookie-state replay model, linking, unlink-last-account protection, and token refresh;
5. CSRF rejection for a cookie-authenticated unsafe request without a valid origin;
6. rate-limit `429`, `X-Retry-After`, and recovery after the window;
7. transaction rollback and post-commit hook behavior;
8. restart and multi-replica behavior for the chosen primary and secondary stores.

Run normal tests, race tests, vet, and the relevant Testcontainers E2E suites against the same database family used in deployment.
