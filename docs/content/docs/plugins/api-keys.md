---
title: "API keys"
description: "Issue, verify, scope, rate-limit, expire, and project user or organization API keys with the native Go plugin."
---

Issue hashed user or organization credentials with permissions, quotas, expiry, and optional session projection.

All paths below are relative to the auth `BasePath` (`/api/auth` by default). API-key verification is server-only; there is deliberately no public `/api-key/verify` route.

## Install and register

Import `github.com/pers0na2dev/single-auth/plugins/apikey`. `NewFactory` returns a stateful `*apikey.Plugin` that is both the root factory and the bound direct service API.

```go
package main

import (
    "log"
    "net/http"
    "os"
    "time"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/apikey"
)

func main() {
    keys := apikey.NewFactory(apikey.Options{
        Configurations: []apikey.Configuration{{
            ConfigID:             "service",
            References:           apikey.ReferenceUser,
            DefaultPrefix:        "sa",
            DefaultKeyLength:     32,
            EnableMetadata:       true,
            RateLimitEnabled:     apikey.Bool(true),
            RateLimitTimeWindow:  time.Minute,
            RateLimitMax:         120,
            DefaultExpiresIn:     90 * 24 * time.Hour,
            DefaultPermissions:   map[string][]string{"documents": {"read"}},
            EnableSessionForAPIKeys: true,
            APIKeyHeaders:        []string{"x-api-key"},
        }},
    })

    auth, err := singleauth.New(singleauth.Options{
        BaseURL:       "http://localhost:8080",
        BasePath:      "/api/auth",
        Secret:        os.Getenv("SINGLE_AUTH_SECRET"),
        TrustedOrigins: []string{"http://localhost:3000"},
        PluginFactories: []singleauth.PluginFactory{keys},
    })
    if err != nil {
        log.Fatal(err)
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

`DefaultKeyLength` is the random suffix length; a configured prefix is prepended. In this example, new keys default to 90 days, start with `sa`, allow 120 successful verifications per minute, and initially grant only `documents:read`.

Compose and migrate the `apikey` model before serving traffic. See [Schemas](../storage/schemas.md) and [Migrations](../storage/migrations.md).

## Create and retain the credential

The following request assumes `cookies.txt` contains a normal signed-in user session. A session-enabled user API key can also be projected into root session state, including authoritative resolution. Decide explicitly whether management routes may be reached with that credential and use distinct headers/configurations when self-management would be unsafe.

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{
    "configId":"service",
    "name":"reporting worker",
    "expiresIn":7776000,
    "metadata":{"environment":"production"}
  }' \
  http://localhost:8080/api/auth/api-key/create
```

`expiresIn` is seconds on the HTTP create/update contract. The plaintext `key` appears only in this creation response:

```json
{
  "id": "<key-id>",
  "configId": "service",
  "name": "reporting worker",
  "start": "sa<first-characters>",
  "prefix": "sa",
  "key": "sa<plaintext-random-suffix>",
  "referenceId": "<session-user-id>",
  "enabled": true,
  "rateLimitEnabled": true,
  "rateLimitTimeWindow": 60000,
  "rateLimitMax": 120,
  "requestCount": 0,
  "expiresAt": "<timestamp>",
  "permissions": {"documents":["read"]},
  "metadata": {"environment":"production"},
  "createdAt": "<timestamp>",
  "updatedAt": "<timestamp>"
}
```

Persist the plaintext in a secret manager immediately. `get`, `list`, `update`, and `verify` omit it; it cannot be recovered from the stored digest.

## Public HTTP endpoints

| Method | Path | Input | Authority |
| --- | --- | --- | --- |
| POST | `/api-key/create` | `configId`; optional `name`, `prefix`, `expiresIn` seconds, `metadata`, `organizationId` | Authoritative user session; organization `apiKey:create` for organization-owned configurations |
| GET | `/api-key/get` | Query `id`, optional `configId` | Owning user, or organization member with `apiKey:read` |
| GET | `/api-key/list` | Optional `configId`, `organizationId`, `limit`, `offset` | Session owner, or organization member with `apiKey:read` |
| POST | `/api-key/update` | `keyId`; optional `configId`, `name`, `enabled`, `expiresIn` seconds or null, `metadata` | Authoritative owner session, or organization `apiKey:update` |
| POST | `/api-key/delete` | `keyId`, optional `configId` | Owner, or organization `apiKey:delete` |

All successful calls return status 200. `create`, `get`, and `update` return an API-key object; `delete` returns `{"success":true}`. `list` returns this stable envelope:

```json
{
  "apiKeys": [{"id":"<key-id>","referenceId":"<owner-id>"}],
  "total": 1,
  "limit": 20,
  "offset": 0
}
```

`total` is calculated before pagination. Reads of a user-owned key by another user return `KEY_NOT_FOUND` rather than revealing that the key exists. Passing the wrong `configId` has the same not-found behavior.

Update a label, disable a credential, or reset its expiry relative to the update time:

```bash
curl --fail-with-body \
  --cookie cookies.txt \
  --header 'Content-Type: application/json' \
  --header 'Origin: http://localhost:3000' \
  --request POST \
  --data '{"keyId":"<key-id>","configId":"service","enabled":false}' \
  http://localhost:8080/api/auth/api-key/update
```

An explicit JSON `null` for `expiresIn` clears expiry when custom expiry is enabled. An empty update returns `NO_VALUES_TO_UPDATE`. Prefix, ownership, configuration, counters, and permissions cannot be changed through the public update route.

HTTP callers cannot supply `userId`. The following fields are server-only on create/update and cause `SERVER_ONLY_PROPERTY` when supplied publicly: `remaining`, `refillAmount`, `refillInterval`, `rateLimitMax`, `rateLimitTimeWindow`, `rateLimitEnabled`, and `permissions` (`remaining:null` is tolerated on create for compatibility).

## Verify in trusted Go code

Use the bound plugin after `singleauth.New` has returned. `Verify` is reusable credential authentication, not a one-time-token check: every valid call claims quota and rate-limit state before returning.

```go
result, err := keys.Verify(ctx, apikey.VerifyInput{
    ConfigID: "service",
    Key:       presentedKey,
    Permissions: map[string][]string{
        "documents": {"read"},
    },
})
if err != nil {
    return err // plugin was nil or not bound
}
if !result.Valid {
    return fmt.Errorf("api key rejected: %s", result.Error.Code)
}

ownerID := result.Key.ReferenceID
```

Invalid credentials are represented in `VerifyResult` as `Valid:false` plus `Error`; they are not returned as the Go `error` value. A successful result includes the public key record with `Key` omitted. When `ConfigID` is empty, verification checks configured entries in declaration order.

Required permissions are conjunctive across requested resources/actions. A missing permission returns the deliberately non-enumerating `KEY_NOT_FOUND` result. Quota and rate counters are not charged when required-permission validation fails.

Direct server code can also call `Create`, `Get`, `List`, `Update`, and `Delete`. Those inputs include trusted actor and ownership fields plus quota, refill, rate-limit, and permission controls. Do not expose these structs through an application HTTP proxy without reconstructing authentication and authorization. See [Direct API](../transports/direct-api.md).

## Optional session projection

`EnableSessionForAPIKeys` is false by default. When true for a user-owned configuration, the plugin checks its configured headers before normal session resolution:

```bash
curl --fail-with-body \
  --header 'x-api-key: sa<plaintext-random-suffix>' \
  http://localhost:8080/api/auth/get-session
```

A valid key produces the normal `{session,user}` response and can authenticate endpoints that accept an ordinary plugin-projected session. Each request verifies and charges the key. The synthetic session uses the key ID as its session ID and expires with the key, or after seven days when the key has no expiry; it is not a newly persisted core session.

Organization-owned keys cannot become user sessions. Invalid/disabled/expired keys return 401; quota and per-key rate-limit exhaustion return 429. With multiple session-enabled configurations, header/configuration search follows declaration order, so prefer distinct header names where ambiguity would be unsafe.

## Configurations and defaults

With no explicit configuration, the plugin creates one user-owned configuration named `default`.

| `Configuration` field | Default and behavior |
| --- | --- |
| `References` | `ReferenceUser` |
| `ConfigID` | Normalized to `default` when omitted in a single configuration |
| `DefaultPrefix` | Empty |
| `DefaultKeyLength` | 64-character random suffix |
| `MinimumPrefixLength` / `MaximumPrefixLength` | 1 / 32 for a caller-supplied prefix; allowed characters are ASCII letters, digits, `_`, `-` |
| `MinimumNameLength` / `MaximumNameLength` | 1 / 32 |
| `RequireName` | `false` |
| `EnableMetadata` | `false`; create rejects supplied metadata when disabled |
| `DisableKeyHashing` | `false`; SHA-256 base64url digest storage is enabled |
| `StoreStartingCharacters` / `StartingCharactersLength` | `true` / 6 characters of the full plaintext |
| `RateLimitEnabled` / `RateLimitTimeWindow` / `RateLimitMax` | `true` / 24 hours / 10 successful claims |
| `DefaultExpiresIn` | zero means no automatic expiry |
| `DisableCustomExpiresTime` | `false` |
| `MinimumExpiresIn` / `MaximumExpiresIn` | 24 hours / 365 days |
| `DefaultPermissions` | nil / no permissions |
| `EnableSessionForAPIKeys` | `false` |
| `APIKeyHeaders` | `x-api-key` |

`Remaining`, refill amount/interval, permission overrides, and per-key rate overrides are direct-service inputs rather than configuration fields. Refill amount and interval must be supplied together. Refill intervals and rate windows are durations in Go and milliseconds in stored/API-key response fields.

A `ConfigID` is required for every entry when multiple configurations exist. Only a configuration literally named `default` is selected when a caller omits `configId`; otherwise the operation returns `NO_DEFAULT_API_KEY_CONFIGURATION_FOUND`. IDs must be unique.

Disabling hashing stores bearer credentials as plaintext and should be reserved for a deliberately compatible custom storage boundary. `start`, prefix, metadata, and labels are also sensitive enough to exclude from broad logs or analytics.

## Organization-owned keys

Register the organization plugin before this plugin, configure an entry with `References: apikey.ReferenceOrganization`, and provide the role statements the API-key plugin should honor:

```go
import "github.com/pers0na2dev/single-auth/security/authorization"

organizations := organization.NewFactory(organization.Options{})
organizationKeys := apikey.NewFactory(apikey.Options{
    Configurations: []apikey.Configuration{{
        ConfigID:   "organization",
        References: apikey.ReferenceOrganization,
    }},
    Organization: apikey.OrganizationAuthorization{
        CreatorRole: "owner",
        Roles: map[string]authorization.Statements{
            "admin": {
                "apiKey": {"create", "read", "update", "delete"},
            },
        },
    },
})

factories := []singleauth.PluginFactory{organizations, organizationKeys}
```

Create with `organizationId` and `configId:"organization"`. The configured creator role always receives all four actions. Other organization roles need explicit `apiKey:create`, `read`, `update`, and/or `delete` statements in `Options.Organization.Roles`. Mere organization membership is not sufficient. Missing organization integration returns `ORGANIZATION_PLUGIN_REQUIRED`; a non-member receives `USER_NOT_MEMBER_OF_ORGANIZATION`.

The ownership discriminator is the configuration: user listing ignores organization configurations, while an `organizationId` listing ignores user configurations. A key cannot move between owners or configurations.

## Storage schema

The plugin contributes one `apikey` model:

| Field group | Fields |
| --- | --- |
| Identity and ownership | `id`, indexed `configId`, indexed `referenceId` |
| Credential material | unique indexed `key` digest/plaintext, optional `prefix`, optional `start`, optional `name` |
| Expiry and enabled state | `enabled`, `expiresAt`, timestamps |
| Usage quota | `remaining`, `refillAmount`, `refillInterval`, `lastRefillAt` |
| Per-key rate limit | `rateLimitEnabled`, `rateLimitTimeWindow`, `rateLimitMax`, `requestCount`, `lastRequest` |
| Policy data | JSON-transformed `permissions` and optional `metadata` |

`referenceId` intentionally has no database foreign key because it can refer to either a user or an organization according to `configId`. Ownership is enforced by the service. Schema aliases and extra fields can be supplied through `Options.Schema`; migrate after changing them.

## Errors, concurrency, and security

Public endpoint errors use the normal JSON API error shape. Important codes are `UNAUTHORIZED_SESSION`, `KEY_NOT_FOUND`, `KEY_DISABLED`, `KEY_EXPIRED`, `USAGE_EXCEEDED`, `RATE_LIMITED`, `SERVER_ONLY_PROPERTY`, `INVALID_PREFIX_LENGTH`, `INVALID_NAME_LENGTH`, the custom-expiry errors, and the organization authorization errors. Match on `code` rather than message text.

Verification deletes an expired key when encountered. A no-refill key already at zero remaining is also deleted and returns `USAGE_EXCEEDED`. Refillable quotas use a conditional refill claim followed by a conditional decrement. Rate-window start/reset/increment and remaining-use decrement use `Adapter.IncrementOne`, so concurrent requests cannot all spend the same final use or exceed the configured counter on an adapter that honors the atomic storage contract.

Verification decrements the remaining-use quota before it applies the per-key
rate-limit check. A request that returns `RATE_LIMITED` may therefore still
spend one remaining use. Size quotas and rate limits with that ordering in mind
and test the exact policy under contention.

API keys are reusable bearer credentials, not replay-proof messages. TLS, log redaction, narrow permissions, short expiries, rotation, and prompt disable/delete operations remain required. Hashing protects credentials at rest but does not protect a plaintext key copied from the one-time creation response or request header.

Exported declarations are listed in the [API-key package reference](../reference/packages/plugins--apikey.md). See also [Security](../core/security.md), [Sessions](../core/sessions.md), and [Transactions](../storage/transactions.md). **Status:** implemented with atomic quota and rate-limit coverage.
