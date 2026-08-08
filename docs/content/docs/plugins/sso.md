---
title: "Enterprise SSO"
description: "Configure OIDC and SAML enterprise SSO registration, domain verification, callbacks, and organization assignment."
---

Manage enterprise OIDC and SAML identity providers, verified domains, account provisioning, organization membership, and SAML Single Logout.

## Installation and ordering

Import `github.com/pers0na2dev/single-auth/plugins/sso`. Providers can be application-owned `DefaultSSO` entries or session-managed `ssoProvider` records.

Register `organization` before SSO when a provider can be attached to an organization or automatic membership is enabled. Register SCIM before or after SSO; the two plugins reserve provider IDs against each other at runtime. Keep SSO provider IDs distinct from built-in and social account provider IDs.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/organization"
    "github.com/pers0na2dev/single-auth/plugins/sso"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"https://app.example.com"},
        PluginFactories: []singleauth.PluginFactory{
            organization.NewFactory(organization.Options{}),
            sso.NewFactory(sso.Options{
                DefaultSSO: []sso.DefaultProvider{{
                    ProviderID: "company-oidc",
                    Domain:     "example.com",
                    OIDCConfig: &sso.OIDCConfig{
                        Issuer:            "https://id.example.com",
                        DiscoveryEndpoint: "https://id.example.com/.well-known/openid-configuration",
                        ClientID:          os.Getenv("SSO_CLIENT_ID"),
                        ClientSecret:      os.Getenv("SSO_CLIENT_SECRET"),
                        Scopes:            []string{"openid", "profile", "email"},
                    },
                }},
                DisableImplicitSignUp: true,
                TrustEmailVerified:    true,
                OrganizationProvisioning: sso.OrganizationProvisioningOptions{
                    DefaultRole: "member",
                },
            }),
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

All routes below are relative to `Options.BasePath`, which defaults to `/api/auth`.

## Choose a provider source

### Static providers

Use `DefaultSSO` for providers controlled by deployment configuration. Static providers are checked before database providers and cannot be listed, updated, or deleted through management routes. Restart/redeploy the application to change them.

Each entry requires:

- a unique `ProviderID`;
- a domain used for discovery by email/domain;
- a complete `OIDCConfig`, a complete `SAMLConfig`, or both.

### Managed providers

Managed providers are created by a signed-in user. Personal providers belong to their creator. An organization provider requires membership and, when the organization plugin is installed, an `owner` or `admin` role. The default limit is ten persisted providers per owner.

```http
POST /api/auth/sso/register HTTP/1.1
Content-Type: application/json
Cookie: better-auth.session_token=token.signature

{
  "providerId": "acme-oidc",
  "issuer": "https://id.acme.example",
  "domain": "acme.example",
  "organizationId": "org_acme",
  "oidcConfig": {
    "clientId": "client-id",
    "clientSecret": "client-secret",
    "discoveryEndpoint": "https://id.acme.example/.well-known/openid-configuration",
    "scopes": ["openid", "profile", "email"]
  }
}
```

The response includes the created record and the redirect URI to configure at the identity provider:

```json
{
  "providerId": "acme-oidc",
  "issuer": "https://id.acme.example",
  "domain": "acme.example",
  "organizationId": "org_acme",
  "redirectURI": "https://auth.example.com/api/auth/sso/callback/acme-oidc",
  "oidcConfig": {
    "clientId": "client-id",
    "clientSecret": "client-secret"
  }
}
```

Treat the registration response as sensitive because it contains the supplied provider configuration. List/get responses are sanitized: OIDC client IDs are masked, secrets are omitted, and SAML certificates are represented by metadata such as their SHA-256 fingerprint and validity window.

If domain verification is enabled, registration also returns `domainVerificationToken` and stores `domainVerified: false` until the TXT challenge succeeds.

## Sign-in flow

Call `/sign-in/sso` with a post-login `callbackURL` plus one provider selector. `providerId` wins when supplied; otherwise the plugin can select by `domain`, the domain portion of `email`, or `organizationSlug`. Set `providerType` to `oidc` or `saml` only when a provider has both configurations.

```http
POST /api/auth/sign-in/sso HTTP/1.1
Content-Type: application/json

{
  "email": "ada@acme.example",
  "callbackURL": "https://app.example.com/dashboard",
  "errorCallbackURL": "https://app.example.com/sign-in",
  "providerType": "oidc",
  "loginHint": "ada@acme.example",
  "scopes": ["openid", "profile", "email"]
}
```

```json
{
  "url": "https://id.acme.example/authorize?...",
  "redirect": true
}
```

The browser follows `url`. OIDC returns through `/sso/callback/:providerId` or the shared `/sso/callback`; SAML returns through the configured callback/ACS route. The plugin links or creates the local account, refreshes the root session, runs configured provisioning, and finally redirects to `callbackURL`. `DisableImplicitSignUp` blocks creation of a new local user but still permits an already linked identity.

Optional sign-in fields are `newUserCallbackURL`, `requestSignUp`, and `loginHint` for OIDC. Every callback URL is checked against root trusted-origin policy.

## Endpoints

| Method | Path | Input | Result and authority |
| --- | --- | --- | --- |
| POST | `/sso/register` | `providerId`, absolute `issuer`, `domain`, optional `organizationId`, and an `oidcConfig` or `samlConfig` | Signed-in owner/admin; creates a managed provider and returns its redirect URI. |
| GET | `/sso/providers` | None | Signed-in user; returns accessible personal providers first, then organization providers. |
| GET | `/sso/get-provider` | Exactly one `providerId` query value | Signed-in owner/admin; returns a sanitized provider. |
| POST | `/sso/update-provider` | `providerId` plus `issuer`, `domain`, `oidcConfig`, or `samlConfig` changes | Signed-in owner/admin; partial configuration merge. |
| POST | `/sso/delete-provider` | `providerId` | Signed-in owner/admin; transactionally deletes linked SSO accounts and the provider, then returns `{success:true}`. |
| POST | `/sign-in/sso` | `callbackURL` plus `providerId`, `domain`, `email`, or `organizationSlug` | Public start endpoint; returns `{url,redirect:true}`. |
| GET | `/sso/callback/:providerId` | OIDC `code` and `state` | OIDC callback with single-use state. |
| GET | `/sso/callback` | Shared OIDC `code` and `state` | Provider ID is recovered from state. |
| GET, POST | `/sso/saml2/callback/:providerId` | Redirect or form SAML callback | Compatibility SAML callback. |
| POST | `/sso/saml2/sp/acs/:providerId` | `SAMLResponse`, optional `RelayState` | Assertion Consumer Service. |
| GET | `/sso/saml2/sp/metadata` | Query `providerId`; optional requested representation | Public SP metadata for IdP configuration. |
| GET, POST | `/sso/saml2/sp/slo/:providerId` | SAML logout request/response | Available only with Single Logout enabled. |
| POST | `/sso/saml2/logout/:providerId` | Matching authenticated SAML session | Starts SP-initiated logout when SLO is enabled. |
| POST | `/sso/request-domain-verification` | `providerId` | Owner/admin; creates or returns the active TXT token. |
| POST | `/sso/verify-domain` | `providerId` | Owner/admin; resolves every configured domain and returns 204 on success. |

Management endpoints return normal single-auth error objects such as:

```json
{
  "code": "UNPROCESSABLE_ENTITY",
  "message": "SSO provider with this providerId already exists"
}
```

Callback failures normally redirect to the configured application error URL with protocol error parameters rather than rendering JSON to the browser.

## OIDC configuration and discovery

`OIDCConfig` requires `Issuer`, `ClientID`, and `ClientSecret`. Endpoint values may be discovered or supplied explicitly:

| Field | Purpose |
| --- | --- |
| `DiscoveryEndpoint` | OpenID Provider metadata URL. If omitted, the plugin derives `issuer + /.well-known/openid-configuration`. |
| `AuthorizationEndpoint`, `TokenEndpoint`, `UserInfoEndpoint`, `JWKSEndpoint` | Explicit protocol endpoints. Discovery fills missing values. |
| `Scopes` | Requested scopes; normally `openid`, `profile`, and `email`. |
| `TokenEndpointAuthentication` | Token endpoint client authentication. Default `client_secret_basic`. |
| `PKCE` | Authorization-code PKCE. Defaults to enabled. |
| `Mapping` | Claim names for ID, email, verified email, name, image, and extra user fields. |
| `OverrideUserInfo` | Allows provider data to update the existing local user. |
| `SkipDiscovery` | Registration-only input for fully explicit endpoint configuration; it is not persisted as an ongoing bypass. |

Discovery and all discovered URLs must use absolute HTTP(S) URLs. The native resolver blocks loopback, link-local, private, and otherwise untrusted addresses; validates redirect hops and DNS results; rejects issuer mismatch and incomplete metadata; and bounds response size and time. Use an application-controlled `OIDC.HTTPClient` and `LookupIP` only when a private enterprise IdP is intentional. Do not weaken the policy based on an untrusted registration request.

Common discovery codes include `discovery_untrusted_origin`, `discovery_private_host`, `discovery_timeout`, `discovery_not_found`, `discovery_invalid_json`, `discovery_incomplete`, and `issuer_mismatch`.

## SAML configuration

A SAML registration needs a callback URL and SP metadata. It must also provide either IdP metadata XML or an explicit entry point plus certificate.

```json
{
  "providerId": "acme-saml",
  "issuer": "https://idp.acme.example/entity",
  "domain": "acme.example",
  "samlConfig": {
    "entryPoint": "https://idp.acme.example/sso",
    "cert": "-----BEGIN CERTIFICATE-----...",
    "callbackUrl": "https://auth.example.com/api/auth/sso/saml2/sp/acs/acme-saml",
    "audience": "https://auth.example.com/saml/acme",
    "wantAssertionsSigned": true,
    "authnRequestsSigned": true,
    "privateKey": "-----BEGIN PRIVATE KEY-----...",
    "spMetadata": {
      "entityID": "https://auth.example.com/saml/acme"
    }
  }
}
```

`SAMLMapping` maps assertion attributes to ID, email, email verification, name, first/last name, and extra fields. `IDPMetadata` can carry XML or explicit entity/signing/SSO/SLO material. `SPMetadata` can carry XML or explicit entity, binding, signing, and encryption material. Private keys and provider secrets are sensitive configuration; protect the provider table and backups accordingly.

Get generated metadata with:

```http
GET /api/auth/sso/saml2/sp/metadata?providerId=acme-saml HTTP/1.1
```

Configure the returned entity ID, ACS URL, binding, certificates, and optional SLO endpoint in the IdP. For IdP-initiated login, set `IDPInitiatedCallbackURL` globally or `idpInitiatedCallbackUrl` on the provider and keep `AllowIDPInitiated` enabled. For SP-only deployments, explicitly disable IdP-initiated login.

### SAML defaults

| Behavior | Default |
| --- | --- |
| AuthnRequest lifetime | 5 minutes |
| Relay-state lifetime | 10 minutes |
| Clock skew | 5 minutes |
| Response size limit | 256 KiB |
| Metadata size limit | 100 KiB |
| `InResponseTo` correlation | Enabled when present |
| Assertion replay protection | Enabled |
| IdP-initiated login | Allowed |
| Timestamp requirement | Timestamps validated when present; `RequireTimestamps` is false |
| Single Logout | Disabled |
| SLO request lifetime after enabling | 5 minutes |

Signature requirement and accepted signature/digest/encryption algorithms are configurable through `SAML.SignatureRequirement` and `SAML.Algorithms`. Keep the defaults unless interoperability evidence requires a controlled exception.

## Domain verification

Set `DomainVerification.Enabled` to require ownership before domain-based sign-in or organization assignment. A new token is valid for seven days. With the default prefix and provider ID `acme-oidc`, publish one TXT record for each configured domain:

```text
Name:  _single-auth-token-acme-oidc.acme.example
Value: _single-auth-token-acme-oidc=<domainVerificationToken>
```

The raw token alone is also accepted as the TXT value. `/sso/request-domain-verification` returns the still-active token instead of rotating it. `/sso/verify-domain` rejects identifiers longer than the DNS 63-character label limit, checks every domain, and marks the provider verified only after all lookups match. Changing the provider domain resets `domainVerified` to false.

## Provisioning

`OrganizationProvisioning` creates a missing membership after a successful SSO login when the provider has an `organizationId` and the organization plugin is installed. `DefaultRole` falls back to `member`; `GetRole` can derive a role from the local user, provider data, and tokens. Membership creation is idempotent.

`ProvisionUser` runs after the identity/account transaction and receives the persisted user, normalized user info, tokens, and provider profile. With `ProvisionUserOnEveryLogin: false`, it is intended for initial provisioning; enable the option only when the callback is safe to repeat on every login. Callbacks can be invoked concurrently and should be idempotent, bounded, and free of secret logging.

The package also exports `AssignOrganizationFromProvider` and `AssignOrganizationByDomain` for explicit trusted workflows. They require a transaction adapter and already-authorized inputs; they do not replace session checks on management routes.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `DefaultSSO` | Empty | Application-owned providers, evaluated before persisted providers. |
| `ProvidersLimit` | 10 | Maximum persisted providers owned by a user. |
| `ProvidersLimitForUser` | None | Per-user limit resolver; overrides `ProvidersLimit`. |
| `ModelName` / `Fields` | `ssoProvider` and canonical fields | Physical table/field aliases. |
| `DisableImplicitSignUp` | `false` | Reject creation of a new local identity. |
| `TrustEmailVerified` | `false` | Trust the IdP verification claim for the local email. |
| `DefaultOverrideUserInfo` | `false` | Default OIDC user-info overwrite policy. |
| `RedirectURI` | `/sso/callback/:providerId` under auth base URL | Shared or provider callback path override. |
| `DomainVerification.Enabled` | `false` | Add verification storage/field and gate domain use. |
| `DomainVerification.TokenPrefix` | `single-auth-token` | TXT identifier prefix. |
| `OrganizationProvisioning.Disabled` | `false` | Disable automatic membership assignment. |
| `OrganizationProvisioning.DefaultRole` | `member` | Role for a new membership. |
| `ProvisionUser` | None | Application provisioning callback. |
| `ProvisionUserOnEveryLogin` | `false` | Repeat `ProvisionUser` on linked-user logins. |

OIDC and SAML runtime sub-options control HTTP/DNS resolution, timeouts, correlation, replay, signing, encryption, size limits, timestamps, IdP-initiated login, and SLO. Option slices, maps, and provider configurations are snapshotted when the plugin is built.

## Schema and migrations

The plugin adds `ssoProvider` with:

- `issuer`, unique `providerId`, and `domain`;
- serialized optional `oidcConfig` and `samlConfig`;
- owning `userId` and optional `organizationId`;
- optional `domainVerified` when domain verification is enabled.

OIDC state, SAML relay/correlation/replay records, SLO records, and domain challenges use the root `verification` model. Linked enterprise identities use the core `account` model; organization provisioning uses `member`.

Register every factory before adapter construction, then apply the merged schema. With a root SQL constructor, run `auth.RunMigrationsContext(ctx)`. Enabling domain verification later adds a field and therefore requires a database migration. Changing `ModelName` or `Fields` is also a physical schema migration. See [Migrations](../storage/migrations.md) and [Schemas](../storage/schemas.md).

## Direct APIs

`NewFactory` does not expose a bound server-side SSO service. Trusted code can invoke registered operations through `auth.API().Call`; direct dispatch bypasses HTTP origin checks and rate limits, so preserve the same actor, callback, and tenant policy.

`New` supports explicit-runtime embedding. `ComputeDiscoveryURL` is a pure URL helper. The organization-assignment helpers described above operate on explicit storage/runtime inputs.

## Security, replay, and concurrency

- OIDC state is signed, correlated to the provider, and consumed once. Authorization codes are exchanged only after trusted callback validation.
- Discovery defends against SSRF, unsafe redirects, private DNS answers, DNS rebinding, issuer mismatch, oversized responses, and malformed JSON.
- SAML validates configured signature policy, audience, destination, timestamps, correlation, and algorithms; assertion IDs are reserved to prevent replay.
- SAML replay and correlation records must live in shared primary storage for multi-replica deployments. In-memory storage gives only process-local guarantees.
- Provider identity-boundary fields cannot change while linked accounts exist. This prevents an update from silently reinterpreting existing identities.
- Provider deletion removes linked SSO accounts and the provider in one transaction when the adapter supports transactions.
- `TrustEmailVerified` is safe only when the IdP is authoritative for that address. Domain verification proves DNS control; it does not by itself prove the IdP's user claim.
- SLO is opt-in because it adds cross-party session deletion. Require the authenticated session to match the SAML session and keep signing checks enabled.

## Troubleshooting

- `No provider found for the issuer`: verify the exact provider ID, email/domain, or organization slug and confirm the managed provider is accessible.
- `Provider domain has not been verified`: publish the TXT challenge and call `/sso/verify-domain` before starting sign-in.
- Discovery rejects a private IdP: use a controlled HTTP client/resolver only if private network discovery is an intentional deployment requirement.
- `Cannot change SSO provider identity fields while linked accounts exist`: create a replacement provider or unlink/migrate accounts through an explicit application workflow.
- SAML `invalid_response`, audience, destination, or signature errors: compare IdP entity ID, ACS URL, binding, certificate, audience, clock, and algorithm policy with generated SP metadata.
- Replay/correlation failures only on some replicas: confirm every instance shares the same verification storage and clock source.
- Organization membership is not created: register `organization` first, attach `organizationId`, and inspect `OrganizationProvisioning.Disabled` and `GetRole`.

## Completed lifecycle compatibility

The two previously tracked SSO lifecycle differences are fixed:

1. Ordinary social OAuth callbacks run the domain-based organization-assignment after-hook after the new session is established. Assignment uses persisted SSO domain policy, enforces configured domain verification, and remains idempotent.
2. An unauthenticated SAML GET callback honors a configured root `OnAPIError.ErrorURL`, including an existing query string, and falls back to the application `/error` route when none is configured.

OIDC lifecycle/discovery/JWKS/SSRF handling and signed/encrypted SAML callback coverage are implemented across the supported transports.

## Related pages

- [Organizations](./organization.md)
- [SCIM](./scim.md)
- [SAML protocol](../protocols/saml.md)
- [Protocol security boundaries](../protocols/security-boundaries.md)
- [Multi-replica sessions](../guides/multi-replica-sessions.md)
- [Go package reference](../reference/packages/plugins--sso.md)

**Status:** passing, including the complete OIDC and SAML server lifecycle.
