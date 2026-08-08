---
title: "Capability matrix"
description: "Generated observable-contract status for every native Go server, transport, storage, protocol, and plugin capability."
---

This page is generated from `conformance/capability-map.json`. It measures unique observable Go capabilities, not duplicated upstream test leaves.

The current map contains **38 capability groups: 38 passing and 0 partial**.

## How to read status

- **Passing** means the capability map records production Go implementation and the applicable conformance evidence for its declared dimensions.
- **Partial** means at least one listed observable behavior remains incomplete. Read the capability and its linked narrative page before relying on it.
- Empty transport or storage dimensions mean the capability is a transport-neutral primitive or does not directly own persistence; they do not mean the package is unavailable.

Run `go run ./internal/conformance/cmd/capability-report` from the repository root to validate the map's evidence paths. The explicit upstream audit mode additionally reads the preserved reference tree; ordinary Go tests and documentation builds do not.

## Summary

| Category | Total | Passing | Partial |
| --- | ---: | ---: | ---: |
| Core HTTP | 8 | 8 | 0 |
| Transports | 3 | 3 | 0 |
| Native storage | 9 | 9 | 0 |
| Protocols and plugins | 18 | 18 | 0 |

## Core HTTP

### `core-http.auth-bootstrap-and-dispatch`

**Authentication bootstrap, route registry, and request dispatch**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `bootstrap-dispatch`
  - Configured core and plugin endpoints are registered exactly once.
  - Direct invocation and HTTP dispatch resolve the same endpoint behavior.

### `core-http.email-password`

**Email and password sign-up and sign-in**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `postgres`, `sqlite`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `email-password-flow`
  - A valid email and password can create an account and authenticated session.
  - Invalid credentials and invalid request bodies return stable client errors without creating a session.

### `core-http.sessions`

**Session creation, lookup, refresh, revocation, and middleware**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `redis`, `sqlite`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `session-lifecycle`
  - An authenticated request resolves the current session and user while an unauthenticated request resolves no session.
  - Session refresh and revocation update both persisted state and cookie-visible behavior.

### `core-http.email-verification`

**Email verification token and callback lifecycle**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `verification-lifecycle`
  - A verification request issues a bounded token without consuming the request body twice.
  - A valid token verifies the email and follows only an accepted callback target.

### `core-http.password-reset`

**Password reset request, token consumption, and session revocation**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `password-reset-lifecycle`
  - A reset request does not disclose whether the target account exists.
  - A reset token is expiring and single-use, including under concurrent redemption.

### `core-http.accounts-and-social-linking`

**Account listing, linking, unlinking, and provider token access**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `account-link-lifecycle`
  - Account listing and provider-scoped lookup never cross user or provider boundaries.
  - Link, unlink, and provider-token operations preserve the last usable authentication method and enforce ownership.

### `core-http.origin-and-csrf-security`

**Trusted-origin, CSRF, host, and redirect validation**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `request-origin-policy`
  - State-changing requests reject untrusted Origin and cross-site navigation metadata.
  - Redirect and proxy-host inputs are accepted only when they resolve through configured trust policy.

### `core-http.rate-limiting`

**Memory, database, and secondary-storage request rate limiting**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `redis`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `rate-limit-enforcement`
  - Requests above the configured path-specific window receive 429 and a retry boundary.
  - Concurrent requests consume one atomic counter across memory, database, and secondary storage implementations.

## Transports

### `transports.net-http`

**Standard library net/http handler**

Status: **Passing**.

Coverage dimensions:

- Transports: `net/http`
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `net-http-adapter`
  - net/http requests preserve method, path, query, headers, cookies, body, and cancellation in the transport-neutral dispatcher.
  - Dispatcher status, headers, cookies, and response body are emitted through net/http without semantic loss.

### `transports.fasthttp`

**Direct fasthttp handler**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `fasthttp-adapter`
  - fasthttp requests preserve method, path, query, headers, cookies, body, and cancellation in the transport-neutral dispatcher.
  - Dispatcher status, headers, cookies, and response body are emitted through fasthttp without semantic loss.

### `transports.fiber`

**Fiber adapter**

Status: **Passing**.

Coverage dimensions:

- Transports: `fiber`
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `fiber-adapter`
  - Fiber requests preserve method, path, query, headers, cookies, body, and cancellation in the transport-neutral dispatcher.
  - Dispatcher status, headers, cookies, and response body are emitted through Fiber without semantic loss.

## Native storage

### `native-storage.adapter-contract`

**Native Go storage adapter contract and factory**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `adapter-contract`
  - Create, find, update, delete, count, transaction, join, increment, and consume-one operations use one backend-neutral Go contract.
  - Schema field mappings and capability conversions preserve canonical values at the adapter boundary.

### `native-storage.memory`

**In-memory adapter with transactions, joins, and uniqueness**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `memory`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `memory-adapter`
  - Memory operations preserve uniqueness, singular-mutation, join, and copy isolation semantics.
  - Concurrent writes and failed transactions cannot erase independently committed data.

### `native-storage.sqlite`

**SQLite adapter and schema lifecycle**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `sqlite-adapter`
  - SQLite executes the complete native adapter contract with atomic singular mutations and transactions.
  - SQLite schema creation and repeated migration inspection converge without duplicate changes.

### `native-storage.postgres`

**PostgreSQL adapter against a real service**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `postgres`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `postgres-adapter`
  - PostgreSQL executes the native adapter contract against a real service with backend-native transactions and joins.
  - PostgreSQL values, identifiers, case-insensitive predicates, and returned mutations decode to canonical Go records.

### `native-storage.mysql`

**MySQL adapter against a real service**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `mysql`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `mysql-adapter`
  - MySQL executes the native adapter contract against a real service with atomic guarded mutations.
  - MySQL values, identifiers, case-insensitive predicates, and update-returning emulation decode to canonical Go records.

### `native-storage.mssql`

**Microsoft SQL Server adapter against a real service**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `mssql`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `mssql-adapter`
  - Microsoft SQL Server executes the native adapter contract against a real service with backend-native transactions.
  - SQL Server values, identifiers, predicates, and returned mutations decode to canonical Go records.

### `native-storage.mongodb`

**MongoDB adapter against a real service**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `mongodb`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `mongodb-adapter`
  - MongoDB executes the native adapter contract against a real service using canonical string IDs at the public boundary.
  - ObjectID references, joins, guarded mutations, and case-insensitive filters preserve record ownership and value types.

### `native-storage.redis`

**Redis secondary storage against a real service**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `redis`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `redis-secondary-storage`
  - Redis get, set, delete, consume, increment, expiry, key listing, and clear operations preserve the secondary-storage contract.
  - Consume and increment operations remain atomic under concurrent access and Redis capability fallbacks.

### `native-storage.schema-migrations`

**Cross-backend relational schema inspection and migration planning**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `mssql`, `mysql`, `postgres`, `sqlite`
- Evidence kinds: `e2e`, `integration`, `unit`

Observable contracts:

- `schema-migration-lifecycle`
  - Schema inspection produces deterministic create, alter, index, and reference changes for each supported relational backend.
  - Applying an accepted migration plan and inspecting again yields no pending change for the covered lifecycle.

## Protocols and plugins

### `protocols-plugins.plugin-host`

**Plugin registration, hooks, schemas, and trusted origins**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `plugin-host-lifecycle`
  - Plugin endpoints, middleware, hooks, schema fragments, and error codes merge deterministically into one auth instance.
  - Ordered request hooks pass mutations forward and stop the chain when a hook returns a response.

### `protocols-plugins.oauth2-primitives`

**OAuth 2.0 requests, token refresh, redirect rejection, and token validation**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `oauth2-client-primitives`
  - Authorization, token, userinfo, and refresh requests preserve OAuth parameters and reject unsafe redirects.
  - Token validation and state handling distinguish provider failures, invalid state, and internal failures without trusting malformed tokens.

### `protocols-plugins.social-provider-registry`

**OAuth and OIDC social provider registry**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `social-provider-contract`
  - Each supported provider exposes stable authorization, token, scope, and profile mapping behavior.
  - Provider callbacks enforce state, redirect, account-linking, and email-verification policy before creating a session.

### `protocols-plugins.oauth-authorization-server`

**OAuth authorization-server metadata, consent, userinfo, and revocation**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `oauth-server-surface`
  - Authorization-server metadata advertises only configured endpoints, scopes, claims, and client-registration support.
  - Authorization codes are single-use and token, userinfo, consent, refresh, and revocation operations enforce client and scope policy.

### `protocols-plugins.oidc-provider`

**OpenID Connect provider endpoints and security policy**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `oidc-provider-surface`
  - OIDC discovery, authorization, consent, token, registration, userinfo, and logout endpoints share one issuer and client policy.
  - Redirect URI, prompt, PKCE, nonce, scope, and token redemption checks fail closed before credentials or sessions are issued.

### `protocols-plugins.saml`

**SAML requests, assertions, signatures, metadata, and response validation**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `saml-protocol-validation`
  - SAML requests and metadata encode protocol identifiers, bindings, issuer, destination, and assertion-consumer URLs deterministically.
  - Response validation rejects invalid signatures, audiences, timestamps, replay, and assertion wrapping before exposing an identity.

### `protocols-plugins.sso`

**Enterprise SSO registration, OIDC/SAML lifecycle, and organization assignment**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `enterprise-sso-lifecycle`
  - Registered and default SSO providers resolve by provider ID or normalized domain with explicit default-provider precedence.
  - Provider registration, domain verification, OIDC callbacks, SAML metadata, signed or encrypted assertion callbacks, single logout, and organization assignment enforce trust boundaries, replay protection, session ownership, and verified-domain policy.

### `protocols-plugins.webauthn`

**WebAuthn registration and authentication verification**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `webauthn-verification`
  - Registration verification binds challenge, origin, relying party, credential key, sign count, and user identity.
  - Authentication verification rejects replayed or cross-ceremony challenges and invalid assertions before returning a user.

### `protocols-plugins.passkey`

**Passkey registration, authentication, credential CRUD, and transport adapters**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `passkey-lifecycle`
  - Passkey option and verification endpoints consume one scoped challenge and create at most one credential or session.
  - Credential list, rename, and delete operations are limited to the authenticated owner across supported HTTP transports.

### `protocols-plugins.scim`

**SCIM user management, filtering, pagination, and PATCH**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `scim-user-management`
  - SCIM bearer authentication scopes user CRUD, filtering, pagination, and PATCH to the owning provider and organization.
  - SCIM responses preserve resource schemas, list totals, error status, and patch-operation semantics.

### `protocols-plugins.api-key`

**API key creation, verification, update, listing, rate limits, and organization ownership**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `api-key-lifecycle`
  - API keys are returned in plaintext only at creation and later verified through the configured hash and prefix policy.
  - Update, list, revoke, expiration, rate-limit, and organization operations enforce key and actor ownership atomically.

### `protocols-plugins.organization`

**Organizations, members, roles, permissions, and lifecycle hooks**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `organization-lifecycle`
  - Organization CRUD, membership, role, permission, invitation, and active-organization operations enforce tenant boundaries.
  - Hooks and invitation acceptance preserve atomic membership state under rejection, expiry, replay, and concurrent acceptance.

### `protocols-plugins.admin`

**Administrative users, sessions, permissions, and impersonation**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `redis`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `admin-control-plane`
  - Administrative user, role, ban, session, and impersonation operations require the matching permission and reject self-harm cases.
  - Impersonation and ban transitions issue or revoke only the intended sessions and remain auditable through stable responses.

### `protocols-plugins.two-factor`

**TOTP, OTP, backup codes, trust cookies, and two-factor enrollment**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `two-factor-lifecycle`
  - Two-factor enrollment does not become active until a valid factor is confirmed and recovery material is issued safely.
  - TOTP, OTP, backup-code, trust-cookie, attempt-limit, and recovery flows consume secrets atomically and preserve session policy.

### `protocols-plugins.openapi`

**OpenAPI 3.1 document generation for core and plugin routes**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: transport-neutral or not applicable
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `openapi-document`
  - The generated OpenAPI document describes registered core and plugin paths, methods, parameters, bodies, responses, and security schemes.
  - Model and additional-field schemas preserve required, optional, read-only, nested, enum, and generated-default semantics.

### `protocols-plugins.device-authorization`

**OAuth device authorization and verification flow**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `device-authorization-flow`
  - Device and user codes bind client, scope, interval, expiry, and claiming session before approval or denial.
  - Concurrent polling redeems an approved device code at most once and reports pending, slow-down, denied, expired, and invalid states distinctly.

### `protocols-plugins.jwt`

**JWT issuance, verification, JWKS, and key rotation**

Status: **Passing**.

Coverage dimensions:

- Transports: transport-neutral or not applicable
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `jwt-key-lifecycle`
  - JWT issuance and verification enforce configured issuer, audience, subject, lifetime, algorithm, and claim policy.
  - JWKS publication and rotation keep active verification keys available while rejecting unknown or invalid signatures.

### `protocols-plugins.remaining-server-plugins`

**Remaining Go-native Better Auth server plugins**

Status: **Passing**.

Coverage dimensions:

- Transports: `fasthttp`, `fiber`, `net/http`
- Storage backends: `memory`, `sqlite`
- Evidence kinds: `integration`, `unit`

Observable contracts:

- `remaining-plugin-surface`
  - Each included server plugin exposes its endpoint, schema, middleware, callback, and error behavior through the native plugin host.
  - Bearer, captcha, email OTP, magic link, MCP, phone, SIWE, username, and related flows preserve authentication and single-use-token security boundaries.

## Scope boundary

The matrix intentionally excludes the native Go HTTP client, the deferred CLI, billing/payment plugins, JavaScript-only runtimes and ORMs, and build-tool compatibility. The separately tested browser, React, Next.js, Vue, and Solid package is shipped but does not increase the native Go denominator.

Update the manifest only after applicable production behavior and evidence pass. Then regenerate this page with `go run ./docs/scripts/capabilities` and verify it with `go run ./docs/scripts/capabilities -check`.
