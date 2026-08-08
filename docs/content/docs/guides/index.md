---
title: "Guides"
description: "Task-oriented production recipes that connect single-auth configuration, storage, transports, and protocol behavior."
---

Use these guides after the [quickstart](../getting-started/quickstart.md). They
cover complete deployment and incident paths rather than one package at a time.

## Extend the server

- [Write a server plugin](./write-a-server-plugin.md) — implement the two-phase
  factory lifecycle, authenticated endpoints, schemas, hooks, errors, security,
  and a transport/storage test matrix.

## Deployment

- [Deploy behind a reverse proxy](./deploy-behind-a-proxy.md) — public URL,
  forwarded headers, trusted proxy chains, secure cookies, and origin policy.
- [Run multiple replicas](./multi-replica-sessions.md) — shared session and
  verification authority, Redis, cache staleness, rate limiting, and rollouts.
- [Rotate secrets](./rotate-secrets.md) — what the versioned key ring preserves,
  what it invalidates, and how to stage a rotation.

## Authentication flows

- [Social OAuth end to end](./social-oauth-end-to-end.md) — provider console,
  redirect URI, state/PKCE, callbacks, account linking, and failure diagnosis.
- [Tenant authentication](./tenant-auth.md) — organization plugin ordering,
  roles, API keys, SSO/SCIM boundaries, and tenant-safe authorization.

## Operations

- [Troubleshoot requests](./troubleshooting.md) — cookies, CSRF, callback URLs,
  OAuth state, proxies, migrations, typed errors, and a safe evidence checklist.

The package and route references remain the source of exact declarations. A
guide explains how the parts interact; it does not replace the
[HTTP route contract](../reference/http-routes.md),
[configuration reference](../getting-started/configuration.md), or generated
[Go package reference](../reference/packages/index.md).
