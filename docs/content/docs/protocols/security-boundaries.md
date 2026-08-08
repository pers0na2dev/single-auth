---
title: "Protocol security boundaries"
---

State, redirects, keys, replay stores, clocks, limits, and deployment invariants across protocols.

Protocol correctness depends on state outside the parser or cryptographic primitive. Treat the following boundaries as part of the authentication implementation.

## Input and redirect ownership

- Derive issuer/base URLs from fixed configuration or trusted proxy headers only.
- Validate browser `Origin`, callback URLs, error URLs, relay state, post-logout redirect URIs, OAuth request URIs, and SAML destinations against explicit allow-lists.
- Never let a remote OAuth discovery document redirect a server-side token, user-info, or JWKS request to another host.
- Apply request-body and decoded-payload limits before allocating or parsing large OAuth JSON, SAML XML, CBOR, signatures, certificates, or metadata.

## One-time state

| State | Required property |
| --- | --- |
| OAuth state | Cryptographically random, bound to the flow, expiry, callback, and provider; consumed once. |
| PKCE verifier | High entropy, confidential from the authorization endpoint, bound to the authorization code. |
| Email/reset/OTP token | Expiring and atomically consumed; store a hash when disclosure risk requires it. |
| SAML AuthnRequest ID | Bound to provider and recipient, expiring, atomically consumed. |
| SAML assertion ID | Atomically reserved until assertion expiry to reject replay. |
| WebAuthn challenge | Random, bound to operation/user/origin/RP, expiring, atomically consumed. |
| OAuth authorization code | Short lived, client/redirect/PKCE bound, atomically consumed. |

An in-process mutex is sufficient only for a single-process deployment. Multiple replicas require a shared database or secondary store with atomic take/reserve semantics.

## Keys and secrets

- Use a high-entropy root auth secret and rotate it through the supported secret list instead of abruptly replacing it.
- Store OAuth client secrets, provider client secrets, access/refresh tokens, SAML private keys, and signing keys outside logs and source control.
- Enable OAuth token encryption at rest when the adapter stores provider tokens.
- Publish only public JWKS/certificates. Keep private signing/decryption keys server-side.
- Constrain JWT algorithms, issuer, audience, timestamps, nonce, and key ID; a valid signature alone is not sufficient.
- Reject deprecated SAML algorithms unless a documented interoperability exception is required and monitored.

## Clock policy

JWT, session, OAuth code/token, SAML assertion, and verification-token expiry depend on a reasonably synchronized clock. Use UTC, monitor drift, and keep allowed skew small. Large skew widens replay windows.

## Transactions and hooks

Account creation/linking, credential use counters, authorization-code consumption, refresh-token rotation, session creation, and hook side effects may need one transaction. Use the adapter supplied through the current request context so transaction-aware hooks and plugins do not escape to the root adapter.

## Error handling

Return stable public error codes and generic messages at trust boundaries. Log detailed wrapped causes with request/provider identifiers, never passwords, bearer tokens, cookies, authorization codes, SAML assertions, private keys, or full provider profiles.

## Production verification

Test the complete deployed path through the real proxy/TLS/cookie topology. Unit-level protocol verification does not prove that callback URLs, `Secure`/`SameSite` cookies, proxy-derived scheme/host, trusted origins, database transactions, shared replay state, or key rotation work across replicas.
