---
title: "Go package reference"
---

Generated reference for every exported symbol in the supported server-side Go packages.

This reference is generated from the current Go source. It includes exported constants, variables, types, functions, and methods. Narrative guides explain lifecycle and policy; these pages provide exact declarations.

> **Info: Server API only**
>
> Browser and framework clients are documented separately in the [JavaScript client guide](../../javascript-client/index.md). Internal implementation packages, conformance machinery, commands, and test fixtures are excluded from this server-package reference.

## Entry point

- [`github.com/pers0na2dev/single-auth`](./root.md) — Package singleauth is the application-facing facade for the native Go authentication runtime.

## Core runtime

- [`github.com/pers0na2dev/single-auth/core`](./core.md) — Package core contains the canonical single-auth server runtime.
- [`github.com/pers0na2dev/single-auth/core/contract`](./core--contract.md) — Package contract defines the transport-neutral request, response, header, and error values shared by the single-auth engine and its HTTP adapters.
- [`github.com/pers0na2dev/single-auth/core/engine`](./core--engine.md) — Package engine implements the immutable endpoint registry, router, and dispatch pipeline used by single-auth transports and direct server calls.
- [`github.com/pers0na2dev/single-auth/core/model`](./core--model.md) — Exported server-side Go API.

## Security

- [`github.com/pers0na2dev/single-auth/security/authorization`](./security--authorization.md) — Package authorization implements reference implementation 1.6.26 role-based access-control statement evaluation.
- [`github.com/pers0na2dev/single-auth/security/cookies`](./security--cookies.md) — Package cookies implements the reference implementation compatible cookie parsing, serialization and mutation helpers.
- [`github.com/pers0na2dev/single-auth/security/crypto`](./security--crypto.md) — Package crypto implements the wire-compatible cryptographic formats used by the reference implementation.
- [`github.com/pers0na2dev/single-auth/security/ratelimit`](./security--ratelimit.md) — Package ratelimit implements reference implementation compatible, per-IP request rate limiting without depending on a concrete HTTP framework.

## Protocols

- [`github.com/pers0na2dev/single-auth/protocol/oauth2`](./protocol--oauth2.md) — Package oauth2 implements the OAuth 2.0/OIDC primitives shared by Better Auth providers.
- [`github.com/pers0na2dev/single-auth/protocol/providers`](./protocol--providers.md) — Package providers ports the built-in the reference implementation 1.6.26 social providers.
- [`github.com/pers0na2dev/single-auth/protocol/saml`](./protocol--saml.md) — Package saml implements transport-independent SAML 2.0 protocol primitives and validation used by single-auth.
- [`github.com/pers0na2dev/single-auth/protocol/webauthn`](./protocol--webauthn.md) — Package webauthn implements the WebAuthn protocol layer used by Better Auth's passkey plugin.

## Storage

- [`github.com/pers0na2dev/single-auth/storage`](./storage.md) — Package storage defines the transport- and database-neutral persistence contract used by single-auth.
- [`github.com/pers0na2dev/single-auth/storage/memory`](./storage--memory.md) — Package memory provides the concurrent in-memory single-auth adapter.
- [`github.com/pers0na2dev/single-auth/storage/migration`](./storage--migration.md) — Package migration plans and executes reference implementation-compatible relational schema migrations against an introspected database catalog.
- [`github.com/pers0na2dev/single-auth/storage/mongodb`](./storage--mongodb.md) — Package mongodb implements the single-auth storage contract on top of the official MongoDB Go driver.
- [`github.com/pers0na2dev/single-auth/storage/mssql`](./storage--mssql.md) — Package mssql implements the single-auth storage contract on top of an already opened SQL Server database/sql handle.
- [`github.com/pers0na2dev/single-auth/storage/mysql`](./storage--mysql.md) — Package mysql implements the single-auth storage contract on top of an already opened database/sql handle for MySQL-compatible servers.
- [`github.com/pers0na2dev/single-auth/storage/postgres`](./storage--postgres.md) — Package postgres implements the single-auth storage contract on top of an already opened PostgreSQL database/sql handle.
- [`github.com/pers0na2dev/single-auth/storage/secondary`](./storage--secondary.md) — Package secondary defines optional key-value storage contracts used for sessions, verification values, and rate-limit counters.
- [`github.com/pers0na2dev/single-auth/storage/secondary/redis`](./storage--secondary--redis.md) — Package redis implements reference implementation-compatible secondary storage on top of a small, driver-neutral Redis command interface.
- [`github.com/pers0na2dev/single-auth/storage/sqlite`](./storage--sqlite.md) — Package sqlite implements the single-auth storage contract on top of an already opened SQLite database/sql handle.

## Transports

- [`github.com/pers0na2dev/single-auth/transport/fasthttp`](./transport--fasthttp.md) — Package fasthttp adapts the transport-neutral authentication dispatcher to github.com/valyala/fasthttp without converting through net/http.
- [`github.com/pers0na2dev/single-auth/transport/fiber`](./transport--fiber.md) — Package fiber adapts the transport-neutral authentication dispatcher to Fiber v3 without converting through net/http.
- [`github.com/pers0na2dev/single-auth/transport/nethttp`](./transport--nethttp.md) — Package nethttp adapts the transport-neutral authentication dispatcher to the standard library's net/http server.

## Observability

- [`github.com/pers0na2dev/single-auth/observability/instrumentation`](./observability--instrumentation.md) — Package instrumentation provides the reference implementation-compatible tracing primitives.
- [`github.com/pers0na2dev/single-auth/observability/logger`](./observability--logger.md) — Package logger provides structured, leveled logging for single-auth.

## Plugins

- [`github.com/pers0na2dev/single-auth/plugins/additionalfields`](./plugins--additionalfields.md) — Package additionalfields ports single-auth 1.6.26's server-side additionalFields contract.
- [`github.com/pers0na2dev/single-auth/plugins/admin`](./plugins--admin.md) — Package admin implements the single-auth 1.6.26 administration plugin.
- [`github.com/pers0na2dev/single-auth/plugins/anonymous`](./plugins--anonymous.md) — Package anonymous implements the single-auth 1.6.26 anonymous server plugin.
- [`github.com/pers0na2dev/single-auth/plugins/apikey`](./plugins--apikey.md) — Package apikey implements the single-auth API-key plugin contract.
- [`github.com/pers0na2dev/single-auth/plugins/bearer`](./plugins--bearer.md) — Package bearer implements the single-auth 1.6.26 bearer server plugin.
- [`github.com/pers0na2dev/single-auth/plugins/captcha`](./plugins--captcha.md) — Package captcha implements the single-auth 1.6.26 CAPTCHA request plugin.
- [`github.com/pers0na2dev/single-auth/plugins/customsession`](./plugins--customsession.md) — Package customsession implements the single-auth 1.6.26 custom-session plugin.
- [`github.com/pers0na2dev/single-auth/plugins/deviceauthorization`](./plugins--deviceauthorization.md) — Package deviceauthorization implements single-auth 1.6.26's RFC 8628 device-authorization plugin for direct calls, net/http, fasthttp, and Fiber.
- [`github.com/pers0na2dev/single-auth/plugins/emailotp`](./plugins--emailotp.md) — Package emailotp implements single-auth 1.6.26's email-otp plugin for the transport-neutral single-auth engine.
- [`github.com/pers0na2dev/single-auth/plugins/genericoauth`](./plugins--genericoauth.md) — Package genericoauth ports single-auth 1.6.26's generic-oauth plugin.
- [`github.com/pers0na2dev/single-auth/plugins/haveibeenpwned`](./plugins--haveibeenpwned.md) — Package haveibeenpwned implements single-auth 1.6.26's Have I Been Pwned password plugin using the Pwned Passwords k-anonymity range API.
- [`github.com/pers0na2dev/single-auth/plugins/i18n`](./plugins--i18n.md) — Package i18n translates typed single-auth API errors according to a request-local locale while leaving successful responses untouched.
- [`github.com/pers0na2dev/single-auth/plugins/jwt`](./plugins--jwt.md) — Package jwt implements single-auth 1.6.26's asymmetric JWT and JWKS plugin.
- [`github.com/pers0na2dev/single-auth/plugins/lastloginmethod`](./plugins--lastloginmethod.md) — Package lastloginmethod implements single-auth 1.6.26's last-login-method plugin.
- [`github.com/pers0na2dev/single-auth/plugins/magiclink`](./plugins--magiclink.md) — Package magiclink implements single-auth 1.6.26's built-in magic-link plugin for the transport-neutral single-auth engine.
- [`github.com/pers0na2dev/single-auth/plugins/mcp`](./plugins--mcp.md) — Package mcp implements the single-auth 1.6.26 MCP OAuth authorization server plugin.
- [`github.com/pers0na2dev/single-auth/plugins/multisession`](./plugins--multisession.md) — Package multisession implements single-auth 1.6.26's multi-session plugin.
- [`github.com/pers0na2dev/single-auth/plugins/oauthpopup`](./plugins--oauthpopup.md) — Package oauthpopup ports single-auth's popup-based OAuth handoff plugin.
- [`github.com/pers0na2dev/single-auth/plugins/oauthprovider`](./plugins--oauthprovider.md) — Package oauthprovider contains the production OAuth 2.0/OIDC provider metadata surface shared by single-auth HTTP hosts.
- [`github.com/pers0na2dev/single-auth/plugins/oauthproxy`](./plugins--oauthproxy.md) — Package oauthproxy ports single-auth 1.6.26's OAuth proxy plugin.
- [`github.com/pers0na2dev/single-auth/plugins/oidcprovider`](./plugins--oidcprovider.md) — Package oidcprovider implements the frozen single-auth 1.6.26 oidc-provider plugin.
- [`github.com/pers0na2dev/single-auth/plugins/onetap`](./plugins--onetap.md) — Package onetap ports single-auth's Google One Tap server plugin.
- [`github.com/pers0na2dev/single-auth/plugins/onetimetoken`](./plugins--onetimetoken.md) — Package onetimetoken implements single-auth 1.6.26's one-time-token plugin.
- [`github.com/pers0na2dev/single-auth/plugins/openapi`](./plugins--openapi.md) — Package openapi exposes the single-auth 1.6.26 OpenAPI 3.1 generator and its Scalar API-reference endpoints.
- [`github.com/pers0na2dev/single-auth/plugins/organization`](./plugins--organization.md) — Package organization implements the single-auth 1.6.26 organization plugin.
- [`github.com/pers0na2dev/single-auth/plugins/passkey`](./plugins--passkey.md) — Package passkey implements the single-auth 1.6.26 passkey server plugin.
- [`github.com/pers0na2dev/single-auth/plugins/phonenumber`](./plugins--phonenumber.md) — Package phonenumber implements the single-auth 1.6.26 phone-number plugin.
- [`github.com/pers0na2dev/single-auth/plugins/scim`](./plugins--scim.md) — Package scim implements the transport-neutral single-auth SCIM plugin.
- [`github.com/pers0na2dev/single-auth/plugins/siwe`](./plugins--siwe.md) — Package siwe implements the single-auth 1.6.26 Sign-In with Ethereum server plugin for single-auth.
- [`github.com/pers0na2dev/single-auth/plugins/sso`](./plugins--sso.md) — Package sso implements single-auth's SSO plugin endpoints on top of the transport-independent SAML protocol package.
- [`github.com/pers0na2dev/single-auth/plugins/twofactor`](./plugins--twofactor.md) — Package twofactor implements the single-auth 1.6.26 two-factor plugin for single-auth.
- [`github.com/pers0na2dev/single-auth/plugins/username`](./plugins--username.md) — Package username ports single-auth 1.6.26's username plugin.

Regenerate after public API changes with `go run ./docs/scripts/go-api-reference` from the repository root. Verify checked-in output with `go run ./docs/scripts/go-api-reference -check`.
