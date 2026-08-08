---
title: "single-auth"
description: "Native Go authentication server with browser, React, Next.js, Vue, and Solid clients."
---

A native Go authentication server with an isolated JavaScript client package.

`single-auth` is a Go authentication library modeled after the observable behavior of Better Auth 1.6.26. One immutable authentication runtime exposes the same routes through the standard library, direct `fasthttp`, Fiber v3, and a transport-neutral direct API. Browser, React, Next.js, Vue, and Solid applications call that HTTP surface through `@pers0na2dev/single-auth`.

> **Warning: Pre-1.0 project**
>
> The Go server is close to feature complete, but this repository is still a port in progress. Read [Project status](./getting-started/project-status.md) before choosing it for production.

## What is included

- [**Start with net/http**](./getting-started/quickstart.md) — Create an auth runtime and mount it on a standard `http.ServeMux`.
- [**Use the JavaScript client**](./javascript-client/index.md) — Call the Go server from a browser, React, Next.js, Vue, or Solid.
- [**Follow a production guide**](./guides/index.md) — Configure proxies, replicas, OAuth, secret rotation, tenant auth, and incident diagnosis.
- [**Choose a transport**](./transports/index.md) — Use `net/http`, direct `fasthttp`, Fiber v3, or the direct API.
- [**Configure persistence**](./storage/index.md) — Use memory, SQL, MongoDB, and Redis-backed secondary storage.
- [**Enable plugins**](./plugins/index.md) — Add organizations, OAuth, OIDC, SAML SSO, SCIM, passkeys, 2FA, and more.

| Area | Support |
| --- | --- |
| HTTP servers | `net/http`, `fasthttp`, Fiber v3 |
| JavaScript clients | Browser, React, Next.js, Vue, and Solid entrypoints against the public Go HTTP API |
| Primary storage | Memory, SQLite, PostgreSQL, MySQL, MSSQL, MongoDB |
| Secondary storage | Redis or a custom string/object store |
| Core authentication | Email/password, email verification, password reset, sessions, users, accounts, social OAuth |
| Protocols | OAuth 2.0 authorization server, OIDC provider, OIDC SSO, SAML 2.0 SSO/SLO, SCIM 2.0 |
| Security | CSRF/origin checks, trusted origins, secure cookies, proxy-aware IP resolution, rate limiting, secret rotation |
| Extensibility | Plugin factories, static plugins, endpoint middleware, before/after hooks, database hooks |

## Deliberate exclusions

The current milestone does not include a native Go HTTP client, a CLI, billing integrations such as Stripe or Polar, anonymous product telemetry, Cloudflare Workers, unsupported JavaScript frameworks, or compatibility layers for JavaScript-only ORMs such as Drizzle and Prisma. Go applications use the direct API or documented HTTP routes; JavaScript applications use the separately tested client package.

## Default route

Unless changed with `Options.BasePath`, every HTTP endpoint is mounted below:

```text
/api/auth
```

For example, email sign-up is `POST /api/auth/sign-up/email` and session lookup is `GET /api/auth/get-session`.

## Read next

- [Installation](./getting-started/installation.md)
- [Quickstart](./getting-started/quickstart.md)
- [JavaScript clients](./javascript-client/index.md)
- [Production guides](./guides/index.md)
- [Configuration](./getting-started/configuration.md)
- [Production checklist](./getting-started/production-checklist.md)
