---
title: "Tenant authentication"
description: "Compose organizations, roles, API keys, SSO, and SCIM without confusing authentication with tenant authorization."
---

Tenant authentication has two distinct decisions:

1. **Who is the user or service?** Sessions, social/credential sign-in, SSO, or
   API-key verification establish an identity.
2. **What may that identity do in this tenant?** Organization membership,
   active organization, role permissions, and resource ownership establish
   authorization.

Never authorize a request only because it contains an organization ID or a
valid global session.

## Plugin order is a dependency order

Register the organization factory before plugins that consume organization
services or permissions:

```go
organizations := organization.NewFactory(organization.Options{
    OrganizationLimit: 10,
    MembershipLimit:   250,
    Teams: organization.TeamsOptions{
        Enabled: true,
    },
})

keys := apikey.NewFactory(apikey.Options{
    Configurations: []apikey.Configuration{{
        ConfigID:       "tenant-service",
        References:     apikey.ReferenceOrganization,
        DefaultPrefix:  "sa",
        DefaultKeyLength: 32,
    }},
})

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://accounts.example.com",
    Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
    PluginFactories: []singleauth.PluginFactory{
        organizations,
        keys,
        // Add organization-aware SSO and SCIM factories after organization.
    },
})
```

The root runtime collects every factory schema before constructing storage, so
order is not a migration substitute. Order controls build-time dependencies,
hook/middleware order, and which previously registered services a later plugin
can use.

Run migrations after composing the final factory set. Adding teams, dynamic
roles, API keys, SSO, or SCIM can add models or fields.

## Organization authority

The organization plugin models:

- organization;
- member with one or more roles;
- invitation;
- optional teams and team membership;
- optional dynamic organization roles;
- active organization/team fields on the session.

An active organization is a convenience selection, not proof of membership.
Tenant endpoints must resolve the current authenticated user, load membership
for the requested or active organization, and check the required permission.

HTTP callers cannot create an organization on behalf of an arbitrary `userId`.
Trusted direct service methods may accept explicit actor or user IDs; validate
the calling application service before exposing them.

## Define roles around resources

Use small resource/action statements such as:

```text
document: read, create, update, delete
member: read, create, update, delete
apiKey: create, read, update, delete
```

Avoid role names as the only authorization contract. A named `manager` role is
hard to audit when each application interprets it differently; permissions can
be checked and evolved explicitly.

The organization plugin protects last-owner operations. Keep those invariants
in place when adding application-owned role or membership APIs. A database row
update outside the plugin can bypass lifecycle hooks, permission checks, team
cleanup, and last-owner protection.

## Tenant selection

Prefer an explicit organization ID in the application resource route and
recheck membership on the server. Use the session's active organization only
when the UI intentionally operates on one selected tenant.

Safe request handling:

1. resolve an authoritative/fresh session according to operation risk;
2. parse the resource's tenant ID from trusted routing/data, not a display
   label;
3. load current membership for that tenant;
4. check the exact permission;
5. constrain the storage query by both resource ID and tenant ID;
6. perform the mutation transactionally where invariants span multiple rows.

The final tenant predicate prevents a confused-deputy bug even when a resource
ID from another tenant is guessed or leaked.

## Organization API keys

Organization-owned API keys establish a service credential scoped to an
organization configuration. Their validity does not imply every action is
allowed. Verification applies enabled/expiry state, permission requirements,
quotas, refill, and rate limits atomically.

Plaintext is returned only at creation. Store a digest, never log creation
responses, and provide a deliberate one-time display/download flow.

An organization API key cannot be projected into a user session. If an
application endpoint accepts either user sessions or service keys, normalize
them into an application-owned principal shape and keep user-only actions
separate.

## SSO organization assignment

SSO proves an identity through a configured OIDC or SAML provider. Domain-based
assignment is an authorization/provisioning policy layered on top.

Validate:

- exact configured domain/provider relationship;
- issuer, audience, signature, state/replay, and callback constraints;
- whether a user should be created, linked, invited, or denied;
- which initial organization role is safe;
- what happens when the user's domain or provider assignment changes.

Do not grant a privileged organization role based solely on an email suffix
supplied by an untrusted identity provider.

The SSO domain-assignment policy also runs after ordinary social OAuth
callbacks. It uses the newly established session user and the persisted SSO
provider/domain policy, honors domain-verification requirements, and keeps
membership creation idempotent. An unauthenticated SAML GET callback honors
the root `OnAPIError.ErrorURL` when configured. Keep both behaviors covered in
your deployment tests when organization enrollment or centralized error
routing is security-sensitive.

## SCIM provisioning

SCIM is a provisioning authority, not an interactive session. Scope every SCIM
token to the intended provider/organization and keep it out of browser code.

Provisioned users must still pass the application's authentication flow. When
linking existing users, define how email collisions, suspended accounts,
membership removal, and identity-provider deprovisioning map to local state.

SCIM mutations and organization membership changes may involve multiple rows.
Use the plugin's service path so transaction, hook, and concurrency behavior is
preserved.

## Invitation safety

Invitation IDs are credentials. Enforce expiry and bind acceptance to the
intended recipient email. Listing user invitations exposes IDs and therefore
requires verified email state.

Decide whether new users may create organizations, which roles an inviter may
assign, and maximum membership/team counts. A role assignment must never allow
the inviter to grant permissions they do not possess.

## Tenant test matrix

For every tenant mutation, test:

- member with required permission succeeds;
- member without permission fails;
- authenticated non-member fails;
- another tenant's resource ID fails;
- missing/expired/revoked session or API key fails;
- stale cookie cache cannot satisfy an authoritative operation;
- concurrent invitation acceptance or key quota consumption has one atomic
  outcome where required;
- last-owner leave/removal is rejected;
- direct server helpers cannot be reached through an untrusted HTTP wrapper;
- all three supported transports return the same logical result.

Read [Organization](../plugins/organization.md),
[API keys](../plugins/api-keys.md), [SSO](../plugins/sso.md), and
[SCIM](../plugins/scim.md) for exact endpoint and option contracts.
