---
title: "Access control"
description: "Define and evaluate deterministic resource/action policies for server-side authorization."
---

Access control defines deterministic resource/action policies that can be shared by admin, organization, API-key, or application authorization. It is a pure Go package: it does not authenticate a request, choose a tenant, register middleware, or add an HTTP route.

## Define a vocabulary and roles

Import `github.com/pers0na2dev/single-auth/security/authorization`. `CreateAccessControl` snapshots the declared vocabulary, and `NewRole` snapshots the statements assigned to one role.

```go
package permissions

import "github.com/pers0na2dev/single-auth/security/authorization"

var Control = authorization.CreateAccessControl(authorization.Statements{
    "project": {"read", "create", "update", "delete"},
    "audit":   {"read"},
})

var Editor = Control.NewRole(authorization.Statements{
    "project": {"read", "create", "update"},
    "audit":   {"read"},
})

var Viewer = Control.NewRole(authorization.Statements{
    "project": {"read"},
})
```

The runtime deliberately does not reject role statements outside the vocabulary. Better Auth enforced that relationship through TypeScript types; Go callers must validate application-owned or database-backed role definitions themselves.

This package is not an `engine.Plugin`, so there is no `NewFactory`, registration order, HTTP endpoint, hook, schema, or migration. Pass roles to the plugin or application layer that authenticates the actor and owns the authorization decision.

## Evaluate permissions

The default connector is `AND` at both levels:

- the outer connector combines requested resources;
- the inner connector combines actions requested for one resource.

```go
result, err := Editor.Authorize(authorization.AuthorizeRequest{
    {
        Resource: "project",
        Actions:  []string{"read", "update"},
    },
    {
        Resource: "audit",
        Actions:  []string{"read"},
    },
})
if err != nil {
    return err
}
if !result.Success {
    return fmt.Errorf("permission denied: %s", result.Error)
}
```

Use an inner `OR` when any one action is sufficient:

```go
result, err := Editor.Authorize(authorization.AuthorizeRequest{
    {
        Resource: "project",
        Actions: authorization.ActionRequest{
            Actions:   []string{"update", "delete"},
            Connector: authorization.OR,
        },
    },
})
```

Use an outer `OR` when any one resource request may authorize the operation:

```go
result, err := Editor.Authorize(
    authorization.AuthorizeRequest{
        {Resource: "organization", Actions: []string{"admin"}},
        {Resource: "project", Actions: []string{"update"}},
    },
    authorization.OR,
)
```

With outer `OR`, unknown or denied resources are skipped until one request succeeds. If none succeeds, the response is `{Success:false, Error:"Not authorized"}`.

## Request forms

`ResourceRequest.Actions` accepts either a slice or array directly, or an `ActionRequest` object:

```go
authorization.AuthorizeRequest{
    {Resource: "project", Actions: []string{"read", "update"}},
    {
        Resource: "audit",
        Actions: authorization.ActionRequest{
            Actions:   []string{"read"},
            Connector: authorization.AND,
        },
    },
}
```

`map[string]any` is also accepted as an object-shaped action request when it has `actions` and optional `connector` keys. Prefer the typed form in new Go code.

An ordered `AuthorizeRequest` makes the first failing resource deterministic. `AuthorizeMap` is a convenience for ordinary Go maps; because maps have no insertion order, it sorts resource keys before evaluation.

```go
result, err := Viewer.AuthorizeMap(map[string]any{
    "project": []string{"read"},
})
```

## API reference

| Function or type | Purpose |
| --- | --- |
| `CreateAccessControl(Statements)` | Snapshot the known resource/action vocabulary and return a role factory |
| `NewRole(Statements)` | Create a standalone role without a vocabulary object |
| `(*AccessControl).Statements()` | Return an independent copy of the declared vocabulary |
| `(*AccessControl).NewRole(Statements)` | Create a role with independently copied statements |
| `(*Role).Statements()` | Return an independent copy of the role statements |
| `(*Role).Authorize(AuthorizeRequest, connector...)` | Evaluate resources in insertion order |
| `(*Role).AuthorizeMap(map[string]any, connector...)` | Sort resource names, then evaluate the request |
| `AND`, `OR` | Combine outer resources or inner actions |
| `ErrInvalidAccessControlRequest` | Identifies a scalar or nil action request that cannot be normalized |

`Authorize` returns two channels of failure. A valid but denied policy normally returns `err == nil` and `response.Success == false`; malformed scalar input returns `ErrInvalidAccessControlRequest`. Always inspect both.

## Denial and malformed-input behavior

| Condition | Result |
| --- | --- |
| Known resource, one or more disallowed actions under inner `AND` | `unauthorized to access resource "resource"` |
| Unknown resource under outer `AND` | `You are not allowed to access resource: resource` |
| All resources denied or unknown under outer `OR` | `Not authorized` |
| Empty request or empty action list | Denied |
| Non-string value inside an action slice | That action is not allowed, so the enclosing request is denied |
| Scalar or nil `Actions` value | `ErrInvalidAccessControlRequest` |
| Object-shaped request whose `actions` is absent or not an array | Normalized to an empty list and denied |

An inner connector other than `OR` normalizes to `AND`. Do not pass an unknown outer connector: compatibility behavior falls through differently from either explicit policy and can authorize a request containing a later successful resource. Restrict configuration to the exported `AND` and `OR` constants.

## Concurrency, persistence, and security

Statement maps and slices are deep-copied at construction and when returned by `Statements`. Authorization is read-only and safe to call concurrently. If callbacks or surrounding tenant/role lookups use mutable state, that state remains the application's responsibility.

The package does not persist policies or enforce referential integrity. When roles come from a database:

1. validate every resource and action against `Control.Statements()` before saving;
2. resolve the authenticated user and tenant before selecting a role;
3. treat a policy denial as an authorization failure even though the Go `error` is nil;
4. fail closed when a role is missing, corrupt, or belongs to another tenant.

Do not use this utility as route middleware by itself. The caller must authenticate the request, prevent tenant confusion, and map a denial to the appropriate HTTP or direct-API response.

## Troubleshooting

- A request that unexpectedly fails under `AND` usually contains one extra action; switch the inner connector to `OR` only when either action truly grants the operation.
- A role created successfully with a misspelled resource is expected runtime behavior. Add validation at the role-management boundary.
- Different first-error text between `Authorize` and `AuthorizeMap` comes from insertion order versus sorted map keys.
- `err == nil` does not mean access was granted. Check `response.Success`.

## Related pages

- [Admin](./admin.md)
- [Organizations](./organization.md)
- [API keys](./api-keys.md)
- [Security](../core/security.md)

**Status:** implemented with deterministic connector, malformed-input, snapshot, and race coverage.
