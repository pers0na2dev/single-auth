---
title: "SCIM 2.0"
---

Provision users through the native SCIM server plugin and its management API.

SCIM support is implemented by `plugins/scim`. It exposes SCIM User resources for identity-provider provisioning and separate authenticated management routes for configuring providers and bearer tokens.

## Setup order

Register the Organization factory before SCIM when provisioned users must be attached to organizations or teams. Social providers referenced by SCIM configuration must already be present in the root `SocialProviders` map.

```go
auth, err := singleauth.New(singleauth.Options{
    PluginFactories: []singleauth.PluginFactory{
        organization.NewFactory(organization.Options{}),
        scim.NewFactory(scim.Options{}),
    },
})
```

The factory participates in schema composition, so initialize the complete factory list before creating or migrating the adapter. See [Schemas and migrations](../storage/schemas.md).

## Protocol behavior

The plugin implements this route set under the root auth base path:

| Method | Path | Authorization | Behavior |
| --- | --- | --- | --- |
| `POST` | `/scim/generate-token` | Root session | Create or replace one provider connection and return its bearer token once. |
| `GET` | `/scim/list-provider-connections` | Root session | List connections visible through organization role/ownership policy. |
| `GET` | `/scim/get-provider-connection` | Root session | Read one visible connection. |
| `POST` | `/scim/delete-provider-connection` | Root session | Delete one visible connection. |
| `POST` | `/scim/v2/Users` | SCIM bearer token | Provision a user or explicitly permitted existing-user link. |
| `GET` | `/scim/v2/Users` | SCIM bearer token | List provider-scoped users; optional `userName eq <value>` filter only. |
| `GET` | `/scim/v2/Users/:userId` | SCIM bearer token | Read one provider-scoped user. |
| `PUT` | `/scim/v2/Users/:userId` | SCIM bearer token | Replace supported user/account fields. |
| `PATCH` | `/scim/v2/Users/:userId` | SCIM bearer token | Apply the supported PatchOp subset. |
| `DELETE` | `/scim/v2/Users/:userId` | SCIM bearer token | Deprovision according to organization scope and installed plugins. |

SCIM resource requests accept `application/scim+json` and `application/json` and use bearer-token authorization. SCIM errors use protocol-shaped status, detail, and `schemas` fields rather than the core auth JSON error envelope; management endpoints use the core API error envelope.

Generating a token for an existing provider ID first verifies access, removes the old connection, and creates its replacement. There is no separate provider update endpoint or independent credential-rotation endpoint.

> **Warning: Implemented SCIM surface**
>
> This port implements User resources only. It does not expose Groups, `ServiceProviderConfig`, `ResourceTypes`, or `Schemas` discovery endpoints. Confirm that your identity provider can be configured without those endpoints before deployment.

## Token persistence and ownership

`StoreSCIMToken.Mode` defaults to `plain`, and a nil `VerifyToken` uses constant-time plaintext comparison. Prefer `TokenStorageHashed` with a `Hash` callback when tokens need only verification. Use `TokenStorageEncrypted` only with both encryption/decryption support when reversible storage is required. `DefaultSCIM` entries are configuration-owned and use plaintext comparison.

Bearer values encode the random secret together with provider and optional organization identifiers. Never log the generated token; replacing a provider connection invalidates the previous stored secret.

`ProviderOwnership.Enabled` adds a `userId` owner to non-organization provider records. Without it, an unscoped provider record has no personal owner and can be visible/manageable to other authenticated management users. Organization-scoped connections are filtered by membership and role. When `RequiredRoles` is nil, the default is `admin` plus the organization creator role (`owner` by default; only `admin` when the creator role is `admin`).

## User and PATCH limits

`LinkExistingUsers` defaults to disabled. Enabling it without trusted domains, organization-membership requirements, or `ShouldLinkUser` permits any matching email user to be linked, so treat the bare enabled state as a high-trust migration option. Newly created SCIM users start with `emailVerified=false`.

PATCH supports `add` and `replace` for `active`, `name.formatted`, `name.givenName`, `name.familyName`, `externalId`, and `userName`. Dot and slash path forms are normalized. `remove`, unknown operations, and unknown paths are ignored; a request that produces no recognized update is rejected. Setting `active:false` requires the Admin plugin and revokes sessions; without Admin it returns a SCIM bad-request error.

The list filter parser accepts only case-sensitive attribute name `userName` with the `eq` operator; other SCIM operators/attributes return `invalidFilter`. Pagination and sorting parameters are not implemented.

## Identity mapping

Treat the SCIM `userName`, external ID, active state, names, emails, and provider/organization references as identity data rather than arbitrary profile metadata. Decide which upstream system is authoritative before enabling bidirectional edits in your application.

- Use a stable upstream external ID for idempotent reconciliation.
- Normalize email casing consistently with core single-auth behavior.
- Do not infer verified email ownership from a SCIM attribute; this implementation persists newly provisioned email addresses as unverified.
- Scope every token to the intended provider/organization and rotate it after exposure.
- Make delete/deactivate semantics explicit in your identity-provider mapping.

## Deployment

SCIM bearer tokens and provider records require shared primary storage. Multi-instance deployments must use the same database and schema. Keep provisioning endpoints behind HTTPS, rate limits, request-size limits, and logs that omit bearer tokens and sensitive user attributes.
