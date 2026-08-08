---
title: "Troubleshooting"
description: "Diagnose mount, cookie, CSRF, OAuth, proxy, migration, and multi-replica failures from stable evidence."
---

Start with the first boundary that fails. Avoid disabling security checks,
clearing all storage, or changing several options at once; those actions erase
the evidence that distinguishes a routing problem from a cookie, state, or
authorization problem.

## Capture a minimal request record

For one failing request, record:

- timestamp and replica/request ID;
- method and public URL, with secrets and query tokens redacted;
- status, stable error `code`, and response content type;
- `Origin`, `Referer`, `Host`, forwarding headers, and the direct peer IP;
- cookie names and attributes, never complete values;
- every `Set-Cookie` header as a separate line;
- relevant runtime mode, base URL/path, adapter IDs, and plugin list;
- storage/provider error class and latency without credentials.

Do not log passwords, session cookies/tokens, OAuth state or authorization
codes, verification values, access/refresh/ID tokens, API keys, private keys, or
provider client secrets.

## Is the auth handler mounted?

```bash
curl --include https://accounts.example.com/api/auth/ok
```

Expected status is 200 with `{"ok":true}`. Interpret failures:

| Result | Likely boundary |
| --- | --- |
| Proxy 404 | Proxy route or path rewrite before single-auth. |
| single-auth 404 | Wrong base path, disabled path, server-only endpoint, or unknown route. |
| 405 | Known route with unsupported method. |
| 502/504 | Listener, upstream health, timeout, or proxy-to-service connection. |
| 200 from `/ok`, auth still fails | Continue; `/ok` does not query storage or providers. |

Check that the proxy forwards the base path exactly once. With default config,
the handler normally receives `/api/auth/...` through its mount and the runtime
matches endpoint-relative paths such as `/get-session`.

## Why is the session `null`?

```bash
curl --include \
  --cookie cookies.txt \
  https://accounts.example.com/api/auth/get-session
```

`null` with status 200 is the normal unauthenticated result. Inspect:

1. Did the sign-in response send a session `Set-Cookie` line?
2. Did the client store it and return it to the same applicable host/path?
3. Was `Secure` used over HTTPS rather than HTTP?
4. Does the cookie domain match the current host?
5. Do all replicas share the active secret and session authority?
6. Does the stored session exist and remain unexpired?
7. Did sign-out, revoke, password reset, account deletion, or a secret rotation
   invalidate it?
8. Is a cookie cache version mismatch causing an expected cache miss?

Never comma-join `Set-Cookie`. Browsers and cookie jars need each header line
separately.

## Why does a POST fail CSRF or origin validation?

Cookie-authenticated unsafe requests must carry a trusted non-null `Origin` or
`Referer`. Reproduce with the actual application origin:

```bash
curl --include \
  --cookie cookies.txt \
  --header 'Origin: https://app.example.com' \
  --header 'Content-Type: application/json' \
  --request POST \
  --data '{}' \
  https://accounts.example.com/api/auth/sign-out
```

Check:

- `TrustedOrigins` contains the origin only, without a route suffix;
- proxy/public scheme and host are correct;
- the browser is not sending `Origin: null`;
- a redirect field is relative-safe or belongs to a trusted origin;
- no wrapper stripped `Origin` or changed the host;
- an external protocol callback uses its documented signature/state bypass
  rather than a broad user-configured skip.

Do not set `DisableOriginCheck` as a diagnostic fix. It also prevents the
current origin-based CSRF validator from providing effective protection.

## Why does OAuth report redirect mismatch?

Compare the generated authorization URL's `redirect_uri` byte-for-byte with
the provider-console entry. It must use:

```text
<public base URL><base path>/callback/<provider ID>
```

Common differences are HTTP versus HTTPS, frontend host versus auth host,
missing/duplicated `/api/auth`, trailing slash, port, or provider map key.

Fix `BaseURL` or constrained dynamic host resolution. Do not rewrite provider
redirects at the proxy after single-auth generated them.

## Why does OAuth state fail?

State errors are security failures. Inspect without logging values:

- state strategy (`database` or `cookie`);
- whether the state record exists, is expired, or was already consumed;
- whether storage is shared by all replicas;
- whether atomic consume is implemented;
- whether the state binding cookie returned to the callback host;
- active secret consistency across replicas and across the flow duration;
- cookie domain/path/secure attributes;
- callback host and protocol;
- whether the browser or test client kept every cookie.

Restart the browser flow after fixing the cause. Do not reuse a state value or
skip the cookie binding check merely to complete an old callback.

## Why do migrations or storage operations fail?

Construction validates configuration but does not mutate a database. Confirm a
controlled deployment/startup ran:

```go
if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

Then inspect the backend-specific page for:

- connection ownership and health;
- required database/schema permissions;
- current namespace/database selection;
- additive migration limitations on populated required fields;
- indexes and foreign keys;
- transaction support/topology;
- driver scalar and time handling;
- context deadline or pool exhaustion.

Migration is additive. It does not rename/drop columns or backfill a new
required field on a populated table. Plan those changes explicitly.

## Why does it work on one replica only?

Compare effective configuration, not just environment variable names:

- ordered secrets and active key;
- base URL, base path, cookie prefix/attributes, cache version;
- primary adapter target and schema namespace;
- Redis target and key prefix;
- plugin list and order;
- trusted origins and proxy policy;
- clock;
- deployed migration state.

Then run cross-replica drills: create on A/read on B, OAuth start on A/callback
on B, revoke on A/read on B, and race a single-use token on both.

## Typed errors versus unknown failures

Normal API errors are JSON:

```json
{"code":"INVALID_EMAIL_OR_PASSWORD","message":"Invalid email or password"}
```

Branch on HTTP status and stable code. The message is user-facing text and may
be localized by the i18n plugin.

Unknown server errors are redacted as `INTERNAL_SERVER_ERROR`. Correlate the
request with server-side structured logs; do not expose the wrapped cause to a
browser. Protocol endpoints may use their standardized response or redirect
format instead of the normal JSON envelope.

## Safe diagnostic sequence

1. Reproduce one request with exact public method/path.
2. Confirm mount with `/ok`.
3. Capture status, stable code, headers, and request correlation.
4. Identify whether failure occurred before routing, in HTTP security, session
   resolution, endpoint authorization, storage, or an external provider.
5. Change one configuration fact.
6. Repeat the same request and a negative-control request.
7. Add a regression test at the narrowest layer and at the public transport
   boundary when behavior changed.

Related references:

- [Errors and logging](../core/errors-and-logging.md)
- [Security](../core/security.md)
- [HTTP routes](../reference/http-routes.md)
- [Production checklist](../getting-started/production-checklist.md)
- [Storage testing](../storage/testing.md)
