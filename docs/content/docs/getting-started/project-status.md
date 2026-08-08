---
title: "Project status"
description: "Current Go server and JavaScript client status, exclusions, and pre-1.0 expectations."
---

Current server and JavaScript client readiness, exclusions, and pre-1.0 release expectations.

## Current server readiness

The audited Go capability map currently records **38 of 38 server capabilities as passing (100%)**. Core HTTP behavior, all three transports, native storage, social providers, organizations, enterprise SSO, the OIDC provider, and the OAuth authorization server have passing server coverage.

The generated [capability matrix](../reference/capabilities.md) lists all 38
native Go groups, their observable contracts, transports, storage backends,
and evidence kinds. JavaScript client readiness is deliberately separate.

Run the reproducible capability report:

```bash
go run ./internal/conformance/cmd/capability-report
```

To additionally validate frozen references against the preserved source tree:

```bash
go run ./internal/conformance/cmd/capability-report -upstream-root better-auth-main
```

## SSO completion

The enterprise SSO capability is passing. The SSO after-hook now applies the
configured domain-based organization assignment after ordinary social OAuth
callbacks, and unauthenticated SAML GET callbacks honor a custom
`OnAPIError.ErrorURL`. OIDC and SAML provider login, provisioning, domain
verification, metadata, signed/encrypted assertions, replay protection, and
single logout remain covered across the applicable transports.

## Current JavaScript client readiness

The isolated package exports browser, React, Next.js, Vue, and Solid entrypoints.
Its Bun gate covers lint, type checking, unit tests, declarations, ESM build,
packed exports, and a live lifecycle against the native Go server. See
[JavaScript clients](../javascript-client/index.md). These checks do not increase
the native Go capability denominator.

## Not in scope

- a native typed/raw Go HTTP client;
- JavaScript frameworks other than React, Next.js, Vue, and Solid;
- command-line tooling;
- Stripe, Polar, and other billing plugins;
- anonymous product telemetry and its publisher;
- Cloudflare Workers or other JavaScript runtimes;
- Drizzle, Prisma, Kysely, or other JavaScript ORM adapters;

## Versioning expectation

The project is pre-1.0. Treat public types and routes as subject to correction while release hardening and the module publishing path are completed. Pin a commit when evaluating it and rerun your own integration suite before upgrading.

## Canonical-name migration

The canonical project identity is now `single-auth`, with root Go package `singleauth`. This is a source-breaking pre-release rename: consumers must update Go imports and package qualifiers, and CI must use `SINGLE_AUTH_E2E_REQUIRED`.

Native storage also uses the canonical name for generated presence columns, indexes, constraints, temporary SQL identifiers, and test database names. Redis-backed deployments use the canonical cache/key namespace. Rebuild disposable environments and explicitly migrate existing schemas or cached namespaces before upgrading from an earlier pre-release build.
