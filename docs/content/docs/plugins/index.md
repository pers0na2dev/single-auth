---
title: "Server plugins"
description: "Choose, order, migrate, secure, test, and deploy native Go server plugins through the single-auth PluginFactory lifecycle."
---

Server plugins extend the native Go runtime with endpoints, middleware, hooks, error definitions, schema fragments, storage behavior, and protocol services. They run inside the same transport-neutral registry as core authentication and can be reached through `net/http`, fasthttp, Fiber, or trusted direct calls where the individual plugin permits it.

## Status and scope

| Surface | Current status | What that means |
| --- | --- | --- |
| Plugin host lifecycle | Passing | Factory schemas, ordered builds, endpoints, middleware, hooks, trusted origins, and rate rules are covered by the capability map |
| Native server plugins | Passing | The overall server matrix reports all 38 capabilities passing; read each plugin's security and deployment boundaries before rollout |
| Enterprise SSO | Passing | OIDC/SAML lifecycle, social-callback domain assignment, configured callback error routing, provisioning, and SLO are covered |

The module is pre-1.0. Pin a commit, review the [current project status](../getting-started/project-status.md), and rerun your integration suite when upgrading.

This section covers native Go server behavior. Browser and framework callers use the shipped JavaScript clients; command-line tooling, billing integrations, and JavaScript ORM adapters are outside this milestone.

## Register factories

Use `Options.PluginFactories` in normal applications:

```go
auth, err := singleauth.New(singleauth.Options{
    BaseURL:       "https://auth.example.com",
    BasePath:      "/api/auth",
    Secret:        os.Getenv("SINGLE_AUTH_SECRET"),
    TrustedOrigins: []string{"https://app.example.com"},
    PluginFactories: []singleauth.PluginFactory{
        jwt.NewFactory(jwt.Options{}),
        multisession.NewFactory(multisession.Options{}),
        openapi.NewFactory(openapi.Options{DisableDefaultReference: true}),
    },
})
if err != nil {
    return err
}
```

Every factory implements the current root contract:

```go
type PluginFactory interface {
    PluginID() string
    Schema() (storage.Schema, error)
    Build(PluginHost) (engine.Plugin, error)
}
```

`Schema` must be deterministic and must declare every model or field used by `Build`. `Build` receives root-owned services rather than constructing parallel auth behavior: final options, the hook-aware adapter, secondary-storage-aware sessions, cookies, secrets and encryption, clock and randomness, trusted origins, password wrappers, verification primitives, serializers, database-hook registration, OAuth state, and user/account lifecycle helpers.

## PluginFactory lifecycle

`singleauth.New` performs plugin initialization in this order:

1. Validate and snapshot root options and static plugin descriptors.
2. Start with the core schema, add the database rate-limit model when selected, then merge `Options.Schema`, static plugin schemas, and every factory's `Schema` result in declaration order.
3. Validate the merged schema and construct the configured adapter with that final schema. If no adapter is configured, construct the memory adapter with it.
4. Wrap storage with database hooks and initialize secondary-storage services.
5. Call each factory's `Build` in declaration order. A blank built plugin ID is filled from `PluginID`; a mismatched ID fails initialization.
6. Freeze password wrappers and database hooks, then combine core endpoints, custom endpoints, static plugins, and built plugins into one registry.
7. Reject route/name collisions, build the shared dispatcher and rate limiter, and expose the transports and direct API.

Factory order does not change which schemas are available: all `Schema` calls happen before any `Build`. It does change build-time dependency discovery, password-wrapper nesting, database-hook order, and hook/middleware execution order. A factory that requires another plugin during `Build` must follow it.

`PluginHost.ListEndpoints` may be captured during `Build`, but the registry is not finalized until all factories finish. It returns the final endpoint snapshot when called later; OpenAPI uses this lazy behavior.

## Factory or static descriptor?

| Registration | Use it when | Tradeoff |
| --- | --- | --- |
| `Options.PluginFactories` | Normal root applications | Recommended: receives the authoritative adapter, schemas, sessions, cookies, security policy, callbacks, and secondary storage |
| `Options.Plugins` with `engine.Plugin` | A descriptor is already completely self-contained | No late binding to root services; the caller must have supplied correct explicit runtime dependencies |
| Package `New` / `MustNew` returning `engine.Plugin` | Manual `engine.Registry` assembly, isolated embedding, or focused tests | `MustNew` panics on invalid setup; easy to diverge from root cookie/session/storage semantics |
| Stateful factory returned by packages such as API keys, organization, or OAuth provider | The package exposes a bound direct service after root construction | Create one factory per `Auth`; rebinding a single-use factory fails |

Prefer error-returning constructors during application startup. Use `MustNew` only for genuinely static configuration where a panic is the desired failure mode.

## Schema and migrations

Factories contribute schema before adapter construction, but `singleauth.New` never applies database DDL automatically. After the final factory list is configured, run migrations in a controlled deployment step:

```go
if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

The memory adapter needs no migration. Native durable adapters implement schema setup; custom adapters must receive the merged schema and provide their own migration workflow. Built-in migrations are additive: they create missing objects and indexes but do not rename or drop fields, change existing types, backfill values, or resolve duplicates before a new unique index.

Changing a physical alias, normalizer, encryption mode, or semantic default may therefore require an application migration even when the Go schema validates. Review [schemas](../storage/schemas.md), [migrations](../storage/migrations.md), and backend-specific behavior before rollout.

## Dependency and ordering matrix

| Put first | Then | Reason |
| --- | --- | --- |
| [JWT](./jwt.md) | [OAuth provider](./oauth-provider.md) | OAuth provider checks for JWT during `Build` unless `DisableJWTPlugin` is deliberate |
| [JWT](./jwt.md) | [Legacy OIDC provider](./oidc-provider.md) with `UseJWTPlugin` | ID-token signing and JWKS endpoints must be available |
| [Organization](./organization.md) | [API keys](./api-keys.md), [SCIM](./scim.md), or [SSO](./sso.md) when organization-aware | Dependent ownership, provisioning, and membership logic must discover organization support |
| [Admin](./admin.md) | [SCIM](./scim.md) when `active:false` should ban users | SCIM maps active-state changes to Admin's ban lifecycle only when Admin is installed |
| [Multi-session](./multi-session.md) | [Custom session](./custom-session.md) with device-list mutation | Custom session replaces/projects the list endpoint produced by multi-session |
| Application/auth plugins | [OpenAPI](./openapi.md) | Recommended for readable configuration; OpenAPI lazily enumerates the finalized registry |
| Earlier password wrappers | [Have I Been Pwned](./have-i-been-pwned.md), or the reverse | Wrapper order is observable; choose intentionally and test every password-writing route |

Some relationships are constraints rather than ordering:

- Install exactly one authorization-server route family from [OAuth provider](./oauth-provider.md), [legacy OIDC provider](./oidc-provider.md), or standalone [MCP](./mcp.md). Their `/oauth2/*`, consent, token, discovery, or registration routes overlap. Use OAuth provider's MCP services when one instance needs general OAuth/OIDC plus MCP.
- SSO and SCIM may be installed in either order, but provider IDs must remain unique; both reserve IDs through the shared runtime.
- Additional fields has no relative factory-order requirement because all schemas are previewed first. Hook order still matters if another plugin mutates the same request fields.
- A plugin not named in this matrix is independent unless its own page says otherwise.

## Catalog

### Identity and authentication

| Plugin | Purpose |
| --- | --- |
| [Additional fields](./additional-fields.md) | Typed fields and validation hooks for core user, session, account, and verification records |
| [Anonymous users](./anonymous.md) | Temporary accounts, account-link transfer, and anonymous-user deletion |
| [Email OTP](./email-otp.md) | Purpose-bound email codes for sign-in, verification, reset, and email change |
| [Magic link](./magic-link.md) | Delivered single-use email authentication links |
| [Google One Tap](./one-tap.md) | Google ID-token sign-in through the root OAuth identity lifecycle |
| [One-time token](./one-time-token.md) | Short-lived single-use session handoff tokens |
| [Passkey](./passkey.md) | Native WebAuthn registration, authentication, and credential management |
| [Phone number](./phone-number.md) | Phone/password sign-in, OTP verification, update, signup, and reset |
| [Sign-In with Ethereum](./siwe.md) | Nonce- and domain-bound wallet signature authentication |
| [Username](./username.md) | Normalized usernames, display names, availability, and password sign-in |

### Sessions, factors, and tokens

| Plugin | Purpose |
| --- | --- |
| [Bearer sessions](./bearer.md) | Resolve root sessions from bearer tokens and expose session tokens safely |
| [Custom session](./custom-session.md) | Replace public session output with an application projection |
| [JWT and JWKS](./jwt.md) | Issue, verify, publish, rotate, and revoke asymmetric JWT keys |
| [Last login method](./last-login-method.md) | Store non-authoritative UI hints about the latest successful method |
| [Multi-session](./multi-session.md) | Retain multiple account sessions in one client and switch or revoke them |
| [Two-factor authentication](./two-factor.md) | TOTP, delivered OTP, backup codes, trusted devices, and lockout |

### Authorization, administration, and tenancy

| Plugin or package | Purpose |
| --- | --- |
| [Access control](./access-control.md) | Pure Go resource/action vocabulary and role evaluation; not itself an `engine.Plugin` |
| [Admin](./admin.md) | RBAC-protected users, bans, sessions, roles, passwords, and impersonation |
| [API keys](./api-keys.md) | Hashed keys with ownership, permissions, quotas, expiry, and rate limits |
| [Organization](./organization.md) | Tenants, memberships, invitations, teams, roles, and active organization state |
| [SCIM](./scim.md) | Organization-scoped SCIM provisioning and deprovisioning |

### OAuth, federation, and enterprise protocols

| Plugin | Purpose |
| --- | --- |
| [Device authorization](./device-authorization.md) | RFC 8628 device/user codes, approval, denial, and polling |
| [Generic OAuth](./generic-oauth.md) | Register application-defined OAuth/OIDC identity providers |
| [MCP authorization server](./mcp.md) | Standalone MCP OAuth discovery, authorization, clients, and bearer resource protection |
| [OAuth popup](./oauth-popup.md) | Signed first-party popup completion around root social OAuth callbacks |
| [OAuth provider](./oauth-provider.md) | Recommended OAuth 2.1/OIDC authorization server, clients, consent, tokens, introspection, and revocation |
| [OAuth proxy](./oauth-proxy.md) | Relay provider callbacks between a stable origin and preview deployments |
| [Legacy OIDC provider](./oidc-provider.md) | Compatibility OIDC provider retained for existing behavior |
| [Enterprise SSO](./sso.md) | Managed OIDC/SAML providers, domains, organization assignment, and SAML logout |

### Request protection and developer tooling

| Plugin | Purpose |
| --- | --- |
| [CAPTCHA](./captcha.md) | HTTP-only human-verification checks before selected routes |
| [Have I Been Pwned](./have-i-been-pwned.md) | K-anonymous compromised-password rejection through the password chain |
| [Error localization](./i18n.md) | Request-local translation of stable error messages without changing codes |
| [OpenAPI](./openapi.md) | OpenAPI 3.1 generation and optional Scalar reference for the finalized registry |

## Shared HTTP and direct-call rules

- Plugin paths are relative to `Options.BasePath`, `/api/auth` by default.
- Endpoint handlers, endpoint middleware, before/after hooks, database hooks, and serializers belong to the shared dispatcher and storage runtime.
- Outer HTTP behavior is not identical to direct dispatch. HTTP rate limiting, transport observers, disabled-path routing, and HTTP-only `OnRequest` plugins such as CAPTCHA are bypassed by `auth.API().Call`.
- Direct endpoint calls still run endpoint middleware and hooks. They do not create a cookie jar; copy `Set-Cookie` values into later `Cookie` headers yourself.
- Server-only endpoints have no public HTTP route even when they are callable by trusted direct code.
- net/http, fasthttp, and Fiber adapters convert the same transport-neutral request/response contract. Test the transports you actually deploy, especially multiple `Set-Cookie`, redirects, streaming, and forwarded-host behavior.

See [Transports](../transports/index.md) and [Direct API](../transports/direct-api.md).

## Client boundary

A native typed or raw Go SDK is intentionally not shipped. Go applications use the direct API or documented HTTP routes. Browser and framework callers use the JavaScript clients. Client coverage is tracked separately from native Go server capabilities.

## Shared security and concurrency rules

- Configure `BaseURL`, `BasePath`, `Secret`, and `TrustedOrigins` before constructing `Auth`. Treat callback URLs, OAuth state, verification codes, backup codes, JWT keys, API keys, and session tokens as credentials.
- Cookie-authenticated mutations remain subject to root origin/CSRF and session-freshness policy. Do not turn a direct call into an unvalidated HTTP proxy.
- Keep plugin-contributed authority fields `input:false`; response filtering is not encryption or authorization.
- Delivery, provider, validator, normalizer, enrichment, and background callbacks may run concurrently. Make them thread-safe, deterministic where required, context-aware, and durably complete before returning when loss is unacceptable.
- A process-local keyed lock does not coordinate replicas. Replay-, quota-, invitation-, counter-, and token-sensitive flows require the selected adapter's transaction, compare-and-set, or atomic-consume guarantees.
- Secondary session storage must be invalidated through root host services. Prefer factories so plugins do not delete only database rows while leaving cached sessions live.
- Route names, paths, provider IDs, physical schema aliases, and model extensions share one namespace. `singleauth.New` fails on registry/schema collisions; resolve them rather than shadowing another plugin.

Read [Security](../core/security.md), [Sessions](../core/sessions.md), and [Transactions](../storage/transactions.md) for the root guarantees.

## Deployment and test checklist

1. Pin a module commit and read the project-status page plus every selected plugin page.
2. Choose one owner for overlapping OAuth/OIDC/MCP routes and order dependencies using the matrix above.
3. Configure production base URL/path, trusted origins, cookie policy, secret rotation, provider credentials, callback URLs, and bounded outbound HTTP clients.
4. Construct `Auth` in CI or a deployment job so schema, factory IDs, hook registration, provider registration, and route collisions fail before traffic.
5. Inspect and apply the merged additive schema with `RunMigrationsContext`; separately backfill, deduplicate, rename, or re-encrypt data when required.
6. Run focused plugin tests, `go test ./...`, `go test -race ./...`, and `go vet ./...`. Run Testcontainers E2E for every durable backend involved in plugin state.
7. Cover success, malformed input, authorization, CSRF/origin, provider/delivery failure, expiry, replay, rollback, and concurrent duplicate requests.
8. Exercise each deployed transport and any direct-call wrapper, preserving redirects, multiple cookies, optional/null fields, cancellation, and stable error codes.
9. Verify secondary-storage invalidation, secret/key rotation, multi-replica atomicity, and post-deploy migration idempotence.
10. Monitor rate-limit exhaustion, delivery queues, provider latency/errors, verification replay, session-revocation failures, and cleanup/reconciliation paths.

Storage test guidance is in [Storage testing](../storage/testing.md). **Status:** the native plugin host and enterprise SSO are passing; package-specific security and deployment boundaries remain authoritative on the linked pages.
