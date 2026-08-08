---
title: "SCIM"
description: "Provision and manage users through SCIM 2.0 with organization scope, bearer tokens, PATCH behavior, filtering, and concurrency controls."
---

Provision and deprovision organization users through RFC 7644-style SCIM endpoints.

## Installation and ordering

Import `github.com/pers0na2dev/single-auth/plugins/scim`. Register `organization` before SCIM when tokens or provisioning are organization-scoped. Register `admin` before SCIM if directory updates should map `active: false` to the root ban state; without Admin, active-state mutations return a SCIM error instead of silently diverging.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/organization"
    "github.com/pers0na2dev/single-auth/plugins/scim"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        PluginFactories: []singleauth.PluginFactory{
            organization.NewFactory(organization.Options{}),
            scim.NewFactory(scim.Options{
                RequiredRoles: []string{"owner"},
                StoreSCIMToken: scim.TokenStorage{Mode: scim.TokenStorageEncrypted},
                LinkExistingUsers: scim.LinkExistingUsersOptions{
                    Enabled: true,
                    TrustedDomains: []string{"example.com"},
                    RequireExistingOrgMembership: true,
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

## Create a provider connection

An authenticated owner creates a bearer credential for one unique `providerId` and an optional organization. The plaintext token is returned only by the generation response.

```http
POST /api/auth/scim/generate-token HTTP/1.1
Content-Type: application/json
Cookie: better-auth.session_token=token.signature

{
  "providerId": "acme-directory",
  "organizationId": "org_123"
}
```

```json
{"scimToken":"secret:acme-directory:org_123"}
```

Generating another token for the same accessible provider replaces the provider connection. Store the returned token immediately; list/get operations never return its secret.

## Endpoints

| Method | Path | Input | Result and authority |
| --- | --- | --- | --- |
| POST | `/scim/generate-token` | `providerId`, optional `organizationId` | Session plus configured organization role and application policy; returns one plaintext token. |
| GET | `/scim/list-provider-connections` | None | Accessible `{providers:[...]}` without secrets. |
| GET | `/scim/get-provider-connection` | Query `providerId` | One accessible provider view. |
| POST | `/scim/delete-provider-connection` | `providerId` | Deletes an accessible connection; returns `{success:true}`. |
| POST | `/scim/v2/Users` | SCIM User resource | Bearer token; creates or explicitly links one user and returns status 201. |
| GET | `/scim/v2/Users` | Optional `filter=userName eq "..."` | Bearer token; SCIM ListResponse scoped to provider and organization. |
| GET | `/scim/v2/Users/:userId` | Path user ID | Scoped SCIM User or 404. |
| PUT | `/scim/v2/Users/:userId` | Complete supported User representation | Updates name, email, external ID, and supported active state. |
| PATCH | `/scim/v2/Users/:userId` | RFC PatchOp document | Applies supported add/replace/remove operations; returns 204. |
| DELETE | `/scim/v2/Users/:userId` | Path user ID | Deprovisions the SCIM identity; returns 204. |

This Go implementation currently exposes the User resource and provider-management routes above. It does not register SCIM Groups, ServiceProviderConfig, Schemas, or ResourceTypes endpoints; do not advertise those URLs to an identity provider.

### Create a user

```http
POST /api/auth/scim/v2/Users HTTP/1.1
Authorization: Bearer SCIM_TOKEN
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "ada@example.com",
  "externalId": "directory-user-42",
  "name": {"givenName":"Ada","familyName":"Lovelace"},
  "emails": [{"value":"ada@example.com","primary":true}],
  "active": true
}
```

The plugin creates a core user and an account whose provider ID matches the SCIM connection. An organization-scoped token also creates/maintains membership in that organization.

### Patch a user

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [
    {"op":"replace","path":"name.givenName","value":"Augusta"},
    {"op":"replace","path":"active","value":false}
  ]
}
```

Paths accept leading slashes or dot notation. Unsupported operations, attributes, and invalid values fail with a SCIM error rather than being ignored.

## SCIM errors

Protocol routes return `application/scim+json` error bodies:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "detail": "Email already in use",
  "scimType": "uniqueness"
}
```

Common `scimType` values are `invalidFilter`, `invalidValue`, and `uniqueness`. Missing/invalid bearer tokens return 401. Cross-provider or cross-organization lookups return 404 so tenant existence is not disclosed. Management endpoints use normal single-auth `{code,message}` errors.

Only `userName eq "value"` filtering is currently supported. Other attributes or operators return `invalidFilter`. List responses report `totalResults`, `startIndex: 1`, `itemsPerPage`, and `Resources`; they are not a claim that arbitrary SCIM pagination parameters are implemented.

## Options and defaults

| Option | Default | Behavior |
| --- | --- | --- |
| `ProviderOwnership.Enabled` | `false` | Adds a user owner to non-organization provider connections. |
| `DefaultSCIM` | Empty | Preconfigured provider/token records available without self-service generation. |
| `RequiredRoles` | `owner`, `admin` | Organization roles allowed to manage scoped providers. |
| `CreatorRole` | `owner` | Role assigned when provisioning creates organization membership. |
| `ReservedProviderIDs` | Built-in auth provider IDs | Extends collision protection. SSO provider IDs are also rejected when SSO is installed. |
| `StoreSCIMToken` | Plain compatibility storage | `plain`, `hashed`, `encrypted`, or custom transforms. |
| `CanGenerateToken` | Allow after built-in checks | Application-specific authorization gate. |
| Before/after token hooks | None | Observe or reject token creation. |
| `LinkExistingUsers.Enabled` | `false` | Opt into linking by email. |
| `VerifyToken` | Constant-time comparison for plain storage | Custom verification for application storage policy. |

`LinkExistingUsers` can additionally require trusted domains, existing organization membership, or an application callback. Enabling only the boolean permits any matching email to link, so production deployments should add at least one explicit trust constraint.

## Schema and migrations

The plugin adds `scimProvider` with `providerId`, persisted token representation, optional `organizationId`, and optional `userId` when provider ownership is enabled. Provisioned identities use the core `user` and `account` models. Organization-scoped provisioning also uses `member`, `team`, and related organization models when installed.

Register all factories before adapter construction so the merged schema contains every required model and field. Run `auth.RunMigrationsContext(ctx)` for root SQL constructors or merge `scim.Schema(options)` yourself before creating an explicit adapter. Changing `ProviderOwnership.Enabled` or token storage mode is a data migration, not only a documentation/configuration change.

## Direct API

There is no separately bound SCIM server service. Trusted management code may
use `auth.API().Call` with the registered operation names, but direct dispatch
bypasses HTTP origin checks and rate limiting; preserve the same actor and
tenant checks.

`EncodeBearerToken` is a formatting helper, not authorization. `BuildUserPatch` converts validated patch operations into storage updates; it does not authenticate or scope a request.

## Security, replay, and concurrency

- Tokens are scoped to exactly one provider and optional organization. A token cannot read or mutate another provider's accounts.
- Plaintext is returned only at generation. Prefer hashed storage when only comparison is needed, or encrypted storage when recovery is a deliberate requirement.
- Deactivation revokes sessions. Deletion removes only the SCIM account when other login identities remain; otherwise it deletes/deprovisions the user. Organization deletion also removes membership/team state transactionally.
- User creation/linking and email changes enforce account and email uniqueness. Concurrent identity-provider retries must handle 409 responses idempotently.
- Token and hook callbacks may run concurrently. Hooks must be idempotent and must not log `SCIMToken`.

## Troubleshooting

- 401 `SCIM token is required`: send exactly `Authorization: Bearer <token>`.
- 401 `Invalid SCIM token`: verify token storage/verification mode and the full provider-scoped token string.
- 403 during token generation: check organization membership, `RequiredRoles`, and `CanGenerateToken`.
- 409 uniqueness: search for an existing user/account and decide whether constrained `LinkExistingUsers` is appropriate.
- Active-state updates mention Admin: install `admin` before SCIM or stop sending `active` mutations.
- Organization deprovisioning fails: register `organization` first and confirm all instances share transactional primary storage.

## Related pages

- [Organizations](./organization.md)
- [Enterprise SSO](./sso.md)
- [SCIM protocol](../protocols/scim.md)
- [Storage transactions](../storage/transactions.md)
- [Go package reference](../reference/packages/plugins--scim.md)

**Status:** implemented for SCIM User CRUD/PATCH and provider-connection management across all three HTTP transports.
