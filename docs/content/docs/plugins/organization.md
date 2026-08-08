---
title: "Organization"
description: "Configure tenants, memberships, invitations, teams, dynamic roles, storage, and authorization in the native Go organization plugin."
---

Model tenants, members, invitations, teams, roles, and active organization state.

All paths below are relative to the auth `BasePath` (`/api/auth` by default). The plugin is implemented for the direct API, `net/http`, direct `fasthttp`, and Fiber.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/organization`. `NewFactory` returns a stateful `*organization.Plugin`; keep that value when trusted server code also needs the direct organization service.

```go
package main

import (
    "log"
    "net/http"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/organization"
)

func main() {
    organizations := organization.NewFactory(organization.Options{
        OrganizationLimit: 10,
        MembershipLimit:   250,
        Teams: organization.TeamsOptions{
            Enabled:              true,
            MaximumTeams:         20,
            AllowRemovingAllTeams: false,
        },
    })
    auth, err := singleauth.New(singleauth.Options{
        AppName:       "Example Account",
        BaseURL:       "http://localhost:8080",
        BasePath:      "/api/auth",
        Secret:        os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"http://localhost:3000"},
        PluginFactories: []singleauth.PluginFactory{organizations},
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

Register this factory before organization-aware API keys, SCIM, or SSO provisioning so dependent plugins can discover its schema and authorization service. Compose and apply the plugin schema before serving traffic; see [Schemas](../storage/schemas.md) and [Migrations](../storage/migrations.md).

## First organization flow

The following requests assume that `cookies.txt` already contains a signed-in user's session cookie. Mutating cookie-authenticated requests include `Origin` because the root runtime applies its normal CSRF policy.

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --cookie-jar cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"name":"Acme","slug":"acme","metadata":{"plan":"pro"}}' \
  http://localhost:8080/api/auth/organization/create
```

A successful create returns the organization and its initial creator membership. Unless `keepCurrentActiveOrganization` is `true`, the same session is updated to make this organization active. When teams and the default team are enabled, that team also becomes active.

```json
{
  "id": "<organization-id>",
  "name": "Acme",
  "slug": "acme",
  "logo": null,
  "metadata": {"plan": "pro"},
  "createdAt": "<timestamp>",
  "members": [
    {
      "id": "<member-id>",
      "organizationId": "<organization-id>",
      "userId": "<user-id>",
      "role": "owner",
      "createdAt": "<timestamp>"
    }
  ]
}
```

Read the selected tenant through the active session:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  http://localhost:8080/api/auth/organization/get-full-organization
```

Pass `organizationId` or `organizationSlug` in the query to select explicitly. With no selector and no active organization, this endpoint returns JSON `null`.

## Organization endpoints

HTTP bodies cannot select another actor with `userId`. The session is the actor boundary; fields accepted by server-only direct operations are rejected or ignored on public routes.

| Method | Path | Input | Result | Authority |
| --- | --- | --- | --- |
| POST | `/organization/check-slug` | `slug` | `{"status":true}`; a collision is an error | Session |
| POST | `/organization/create` | `name`, `slug`; optional `logo`, `metadata`, `keepCurrentActiveOrganization`, and configured organization input fields | Organization with initial `members` and public custom fields | Session, creation policy, and per-user organization limit |
| GET | `/organization/list` | No query | Organizations joined by the current user | Session |
| GET | `/organization/get-full-organization` | Optional `organizationId`, `organizationSlug`, `membersLimit`; otherwise active organization | Organization, members with public user projections, invitations, and optional teams; or `null` | Session and membership in the selected organization |
| POST | `/organization/set-active` | `organizationId`, `organizationSlug`, or explicit `organizationId:null` to clear | Selected organization or `null` | Session and membership when selecting a value |
| POST | `/organization/update` | Optional `organizationId`, otherwise active; `data` with optional `name`, `slug`, nullable `logo`, `metadata`, and configured organization input fields | Updated organization with public custom fields | Session, membership, `organization:update` |
| POST | `/organization/delete` | `organizationId` | Deleted organization | Session, membership, `organization:delete`; route returns 404 when deletion is disabled |

`membersLimit` must be non-negative. `list` returns only organizations reached through the current user's membership rows; it is not an administrative tenant listing.

Schema-defined fields stay flat on the wire. Create enforces required fields;
create and update validate field types before writing. Unknown and `Input:false`
fields are ignored, `Returned:false` fields remain private, and custom values
cannot override canonical organization fields. Returned custom values remain
flat in wire responses, including nested members.

## Invitations

Configure `SendInvitationEmail` to deliver the application-specific acceptance URL. The callback receives the persisted invitation, including its opaque ID. A callback error is returned to the caller after the invitation row has been created; delivery retries must therefore reuse/reconcile that row instead of blindly creating another invitation.

```go
organizations := organization.NewFactory(organization.Options{
    SendInvitationEmail: func(ctx context.Context, invitation organization.Invitation) error {
        return mailer.SendOrganizationInvitation(ctx, invitation.Email, invitation.ID)
    },
})
```

Invite a member to the active organization:

```bash
curl --fail-with-body \
  --cookie owner-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"email":"grace@example.com","role":"member"}' \
  http://localhost:8080/api/auth/organization/invite-member
```

After the recipient signs in with the same email, accept the opaque invitation ID with the recipient's cookie jar:

```bash
curl --fail-with-body \
  --cookie recipient-cookies.txt \
  --cookie-jar recipient-cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"invitationId":"<invitation-id>"}' \
  http://localhost:8080/api/auth/organization/accept-invitation
```

Acceptance returns `{"invitation":{...},"member":{...}}`, atomically claims a still-pending, unexpired invitation, creates the membership, and updates the accepting session's active organization. A second acceptance loses the conditional claim and receives `INVITATION_NOT_FOUND`.

| Method | Path | Input | Result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/organization/invite-member` | `email`, `role`; optional `organizationId`; optional `teamId` string or string array when teams are enabled | Pending invitation | Session, membership, `invitation:create`; non-creators cannot assign the creator role |
| POST | `/organization/accept-invitation` | `invitationId` | Invitation and created member | Signed-in recipient; matching email, expiry, pending status, verification policy, membership limit |
| POST | `/organization/reject-invitation` | `invitationId` | Rejected invitation and `member:null` | Signed-in recipient under the same email policy |
| POST | `/organization/cancel-invitation` | `invitationId` | Canceled invitation | Session, membership, `invitation:cancel` |
| GET | `/organization/get-invitation` | Query `id` | Invitation plus organization name/slug and inviter email | Signed-in recipient under the email policy |
| GET | `/organization/list-invitations` | Optional `organizationId`, otherwise active | Organization invitations | Session and membership |
| GET | `/organization/list-user-invitations` | No email query; email comes from the session | Invitations addressed to the verified session email | Session with verified email |

`RequireEmailVerificationOnInvitation` controls invitation-by-ID actions. Explicit `true` requires a verified matching session email. Explicit `false` requires only a matching session email. When nil, the compatibility behavior requires verification when the root has a custom `GenerateID`; otherwise a matching email is sufficient. Listing a user's invitations always requires a verified email because it exposes invitation IDs.

## Members and permissions

Built-in permissions are resource/action statements:

| Role | Permissions |
| --- | --- |
| `owner` | Organization update/delete; member, invitation, team, and dynamic access-control actions |
| `admin` | Organization update; member, invitation, team, and dynamic access-control actions; no organization delete |
| `member` | Dynamic-role read only |

Multiple assigned roles are persisted as a comma-separated value and are evaluated as alternatives. `Roles` replaces the built-in permission-role map when non-nil; `AccessControl` defines the allowed resource/action vocabulary for custom and dynamic roles.

| Method | Path | Input | Result | Authority |
| --- | --- | --- | --- | --- |
| GET | `/organization/get-active-member` | No query | Current user's member with public user projection, or `null` | Session; uses active organization |
| GET | `/organization/get-active-member-role` | Optional `organizationId`/`organizationSlug`, optional target `userId` | `{"role":"..."}` | Session and membership in the selected organization |
| GET | `/organization/list-members` | Optional org selector, `limit`, `offset`, `sortBy`, `sortDirection`, `filterField`, `filterOperator`, `filterValue` | `{"members":[...],"total":N}` | Session and membership |
| POST | `/organization/update-member-role` | `memberId`, `role` string or array; optional `organizationId` | Updated member | Session, `member:update`, valid role assignment, last-owner protection |
| POST | `/organization/remove-member` | `memberIdOrEmail`; optional `organizationId` | `{"member":{...}}` | Session, `member:delete`, target and last-owner protections |
| POST | `/organization/leave` | `organizationId` | Removed member | Session; the only creator-role member cannot leave |
| POST | `/organization/has-permission` | Optional `organizationId`; exactly one of `permissions` or legacy `permission` | `{"error":null,"success":true|false}` | Session and membership |

Supported member filter operators are `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`, `contains`, `starts_with`, and `ends_with`. The selected field is interpreted through the configured member schema. Treat filter field names as an application-level allowlist before forwarding untrusted arbitrary queries.

`addMember` is intentionally server-only. Use the bound service or the direct endpoint API for trusted provisioning; it is not registered as an HTTP path.

## Teams

Set `Teams.Enabled` to register team routes and add team storage. A default team named after the organization is created unless `DefaultTeamEnabled` is explicitly false.

| Method | Path | Input | Result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/organization/create-team` | `name`; optional `organizationId`; configured additional fields are flattened | Team | Session, membership, `team:create`, team limit |
| GET | `/organization/list-teams` | Optional `organizationId`, otherwise active | Organization teams | Session and membership |
| POST | `/organization/update-team` | `teamId`, `data` with optional `name`, `organizationId`, additional fields | Updated team | Session, membership, `team:update` |
| POST | `/organization/remove-team` | `teamId`; optional `organizationId` | `{"message":"Team removed successfully."}` | Session, membership, `team:delete`; last-team policy |
| POST | `/organization/set-active-team` | `teamId` or `teamId:null` | Team or `null` | Session, organization membership, and team membership when selecting |
| GET | `/organization/list-user-teams` | No query | Teams joined by the current user | Session |
| GET | `/organization/list-team-members` | `teamId` | Team-member rows | Session and organization membership |
| POST | `/organization/add-team-member` | `teamId`, `userId`; optional `organizationId` | Team-member row | Session, `member:update`, target must be an organization member, team-member limit |
| POST | `/organization/remove-team-member` | `teamId`, `userId`; optional `organizationId` | Success message | Session, `member:delete`, organization/team membership checks |

Deleting a team also clears affected active-team state and removes or rewrites pending invitation team references. With the default `AllowRemovingAllTeams:false`, the last team cannot be removed.

## Dynamic access control

Dynamic roles require both `DynamicAccessControl.Enabled:true` and an `AccessControl` vocabulary. They are scoped to an organization and merged with configured role statements during authorization.

| Method | Path | Input | Result | Authority |
| --- | --- | --- | --- | --- |
| POST | `/organization/create-role` | `organizationId`, `role`, `permission`, optional `additionalFields` | `success`, public `roleData`, normalized `statements` | Session, membership, `ac:create`, configured resource/action validation, role limit |
| GET | `/organization/list-roles` | `organizationId` | Dynamic roles | Session, membership, `ac:read` |
| GET | `/organization/get-role` | `organizationId` and `roleId` or `roleName` | Dynamic role | Session, membership, `ac:read` |
| POST | `/organization/update-role` | `organizationId`, role selector, `data.roleName`, `data.permission`, additional fields | Updated role mutation result | Session, membership, `ac:update` |
| POST | `/organization/delete-role` | `organizationId`, role selector | `{"success":true}` | Session, membership, `ac:delete`; cannot delete predefined or assigned roles |

The dynamic routes do not exist when the feature is disabled. A nil maximum is unlimited; a non-nil zero maximum intentionally prevents creating dynamic roles.

## Options and defaults

| Option | Default and behavior |
| --- | --- |
| `CreatorRole` | `owner` |
| `AllowUserToCreateOrganization` | nil means `true`; direct trusted `CreateOrganization` can bypass the public creation switch |
| `OrganizationLimit` | `0` means unlimited; otherwise creation is blocked once the user belongs to that many organizations |
| `DisableOrganizationDeletion` | `false` |
| `MembershipLimit` | `100`; also the default member read limit and invitation-acceptance ceiling |
| `InvitationExpiresIn` | 48 hours |
| `RequireEmailVerificationOnInvitation` | nil compatibility behavior described above |
| `AccessControl` / `Roles` | Built-in statement vocabulary and `owner`, `admin`, `member` roles |
| `DynamicAccessControl.Enabled` | `false` |
| `DynamicAccessControl.MaximumRolesPerOrganization` | nil means unlimited; callback takes precedence |
| `Teams.Enabled` | `false` |
| `Teams.DefaultTeamEnabled` | nil means `true` when teams are enabled |
| `Teams.MaximumTeams` | `0` means unlimited; callback takes precedence |
| `Teams.MaximumMembersPerTeam` | nil means unlimited; pointer to zero means no additions; callback takes precedence |
| `Teams.AllowRemovingAllTeams` | `false` |
| Hooks, `SendInvitationEmail`, custom default-team creator | nil / disabled |
| `Schema` | Canonical model and field names |

All numeric limits reject negative values at construction. Limit callbacks run for the specific create/add operation and may return tenant-specific ceilings.

## Storage and migrations

The factory contributes these canonical models and fields:

| Model | Important fields |
| --- | --- |
| `organization` | Unique indexed `slug`, `name`, optional `logo`, JSON-encoded `metadata`, `createdAt` |
| `member` | Indexed `organizationId` and `userId`, `role`, `createdAt`; both references cascade on parent deletion |
| `invitation` | Organization, normalized email, role, pending/accepted/rejected/canceled status, expiry, inviter, optional team linkage |
| `session` extension | Optional, server-managed `activeOrganizationId` |
| `organizationRole` | Organization, role name, JSON permission statements, timestamps; only with dynamic access control |
| `team` / `teamMember` | Organization-scoped teams and user membership; only when teams are enabled |
| `session` team extension | Optional, server-managed `activeTeamId`; only when teams are enabled |

Changing `Schema`, enabling teams, or enabling dynamic roles changes the composed schema and requires a migration. Do not point production at the read-only upstream snapshot or use it at runtime.

## Direct service

Keep the `*organization.Plugin` returned by `NewFactory` for trusted server calls. After `singleauth.New` binds it, it exposes `CreateOrganization`, server-only `AddMember`, `RemoveMember`, `GetFullOrganization`, `SetActiveOrganization`, `UpdateOrganization`, `CreateInvitation`, `ListOrganizationTeams`, `GetActiveMember`, and `RequireOrgRole`. Direct input types carry explicit actor/user IDs and bypass HTTP body trust boundaries; validate any user-controlled values before calling them. A plugin instance is single-runtime and cannot be rebound.

For lower-level trusted calls, read [Direct API](../transports/direct-api.md). Exported declarations are listed in the [organization package reference](../reference/packages/plugins--organization.md).

## Errors, replay, and concurrency

Errors use the normal JSON API error shape. Common codes include `ORGANIZATION_SLUG_ALREADY_TAKEN`, `YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS`, `USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION`, `ORGANIZATION_MEMBERSHIP_LIMIT_REACHED`, `YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER`, and the resource-specific permission errors. Authorization failures are not all the same status: validation and state conflicts are generally 400, absent sessions are 401, and permission failures are generally 403. Match on `code`, not only status or message.

Organization creation uses `Adapter.Transaction` for the organization, creator membership, optional default team, and lifecycle hooks. If an adapter reports `ErrTransactionsUnsupported`, this implementation executes the sequence without rollback; use a transactional production adapter when atomic creation matters. Invitation acceptance conditionally claims the pending row and compensates partial work on non-transactional adapters. Membership and team cleanup use transactions where available.

Invitation acceptance is single-use under concurrent requests because the status/expiry claim uses an atomic conditional increment. Last-owner and organization-delete checks also use process-local keyed locks and reread state. Those locks do not coordinate separate service processes; multi-replica safety therefore depends on the selected adapter's transactional and atomic mutation guarantees. See [Transactions](../storage/transactions.md) and [Storage testing](../storage/testing.md).

Keep the root CSRF/origin policy enabled, do not expose direct inputs as an unvalidated HTTP proxy, and restrict invitation IDs to the intended recipient. See [Security](../core/security.md) and [Sessions](../core/sessions.md). **Status:** implemented.
