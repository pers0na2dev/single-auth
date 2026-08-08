---
title: "Additional fields"
description: "Extend core records with native Go storage fields, validation, defaults, and output filtering."
---

Additional fields extends the root `user`, `session`, `account`, and `verification` models. The same declarations contribute adapter schema, parse writable user/session input, apply storage defaults and transforms, and filter fields marked `returned:false` from public output.

## Install and configure

Import `github.com/pers0na2dev/single-auth/plugins/additionalfields` and `github.com/pers0na2dev/single-auth/storage`. Register `NewFactory` while constructing `Auth`; the factory contributes its schema before the root adapter is initialized.

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/plugins/additionalfields"
    "github.com/pers0na2dev/single-auth/storage"
)

func main() {
    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:8080",
        Secret:  os.Getenv("SINGLE_AUTH_SECRET"),
        EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
        PluginFactories: []singleauth.PluginFactory{
            additionalfields.NewFactory(additionalfields.Options{
                User: additionalfields.Fields{
                    {
                        Name: "displayName",
                        Attribute: storage.FieldAttribute{
                            Type:     storage.FieldString,
                            Required: storage.Bool(true),
                        },
                        Validators: additionalfields.FieldValidators{
                            Input: func(value any) (additionalfields.ValidationResult, error) {
                                text, ok := value.(string)
                                if !ok || strings.TrimSpace(text) == "" {
                                    return additionalfields.ValidationResult{
                                        Issues: []additionalfields.Issue{{
                                            Message: "displayName must not be empty",
                                        }},
                                    }, nil
                                }
                                return additionalfields.ValidationResult{
                                    Value: strings.TrimSpace(text),
                                }, nil
                            },
                        },
                    },
                    {
                        Name: "role",
                        Attribute: storage.FieldAttribute{
                            Type:         storage.FieldString,
                            Input:        storage.Bool(false),
                            DefaultValue: storage.StaticValue("member"),
                        },
                    },
                },
                Session: additionalfields.Fields{
                    {
                        Name: "workspace",
                        Attribute: storage.FieldAttribute{
                            Type:     storage.FieldString,
                            Required: storage.Bool(false),
                        },
                    },
                    {
                        Name: "internalNote",
                        Attribute: storage.FieldAttribute{
                            Type:         storage.FieldString,
                            Input:        storage.Bool(false),
                            Returned:     storage.Bool(false),
                            DefaultValue: storage.StaticValue("server"),
                        },
                    },
                },
            }),
        },
    })
    if err != nil {
        log.Fatal(fmt.Errorf("create auth: %w", err))
    }
    log.Fatal(http.ListenAndServe(":8080", auth))
}
```

No plugin ordering is required relative to ordinary endpoint plugins. The important boundary is initialization: fields cannot be added after `singleauth.New` has already built the adapter schema.

## Field declarations

`Options.User`, `Session`, `Account`, and `Verification` are ordered `Fields` slices. Each entry has a logical `Name`, one `storage.FieldAttribute`, and optional input/output validators.

| Attribute | Default | Behavior |
| --- | --- | --- |
| `Type` | required by schema validation | `string`, `number`, `boolean`, `date`, `json`, `string[]`, `number[]`, or `enum` |
| `Enum` | none | Permitted values for an enum field at the storage-schema layer |
| `Required` | adapter-required when omitted | Explicit `true` also makes the create-time input parser reject a missing value |
| `Input` | `true` | `false` makes the field server-controlled |
| `Returned` | `true` | `false` removes the field from public serialized output |
| `DefaultValue` | none | Evaluated on create and for session defaults; receives a deterministic `ValueContext` clock |
| `OnUpdate` | none | Storage-layer value factory applied by adapters that support the schema contract |
| `Transform.Input` / `Output` | none | Storage transformations for values crossing the adapter boundary |
| `FieldName` | logical name | Physical database-column alias |
| `References` | none | Model/field reference with optional delete behavior and relation name |
| `Unique`, `Index`, `Sortable`, `BigInt` | `false` | Native storage capabilities |

Use `storage.Bool(false)` when omission and explicit false differ. Use `storage.StaticValue(value)` for a constant default.

`Compile` rejects empty or duplicate logical names and validates types, aliases, and core references by merging the extension with `storage.CoreSchema`. Options are snapshotted, so mutating the original slices after factory construction does not alter the running contract.

## Endpoint behavior

There are no standalone HTTP routes. The before hook parses applicable fields on `POST /sign-up/email`, `POST /update-user`, and `POST /update-session`. `input:false` fields remain server-controlled. `Compile` returns an immutable `Processor` for trusted code that creates records outside built-in endpoints.

| Root operation | Model/action | Additional input |
| --- | --- | --- |
| `POST /sign-up/email` / `signUpEmail` | user create | Declared user fields beside `name`, `email`, and `password` |
| `POST /update-user` / `updateUser` | user update | Declared user fields beside core `name` and `image` |
| `POST /update-session` / `updateSession` | session update | Declared session fields |

The hook accepts JSON and `application/x-www-form-urlencoded` bodies. Malformed bodies are left for the root endpoint so its normal validation order remains authoritative.

```http
POST /api/auth/sign-up/email
Content-Type: application/json
Origin: https://app.example.com

{
  "name": "Ada",
  "email": "ada@example.com",
  "password": "correct horse battery staple",
  "displayName": "  Ada Lovelace  "
}
```

The input validator above trims `displayName`. The client cannot set `role`; its default is applied during record creation.

For typed direct root methods, place extra values in `model.Fields`:

```go
fields := model.Fields{}
fields.Set("displayName", "Grace Hopper")

updated, err := auth.API().UpdateUser(ctx, singleauth.UpdateUserInput{
    AdditionalFields: fields,
    Headers: contract.NewHeaders(contract.HeaderField{
        Name: "Cookie", Value: sessionCookie,
    }),
})
```

Direct dispatch still runs the installed before hook. Supply the same authenticated cookie/header context that the HTTP route requires.

### Create versus update

Create parsing applies defaults, then checks fields explicitly marked `Required: storage.Bool(true)`. Update parsing applies neither missing-field defaults nor create-only required checks.

For a supplied writable field, the input validator runs before `Transform.Input`. When a validator exists, its returned `ValidationResult.Value` is used and the input transform is not run by the parser. Storage adapters can still apply their schema transformations at persistence boundaries.

For `Input: storage.Bool(false)`:

- a missing create value allows the configured default to run;
- a truthy client-supplied value returns `FIELD_NOT_ALLOWED`;
- a falsey supplied value is omitted for compatibility and does not make the field writable;
- updates do not apply a default.

Do not rely on the falsey compatibility case as authorization. The root parser independently excludes `input:false` fields from persistence.

The built-in endpoint hook parses user and session fields only. Account and verification declarations still extend schema, but trusted provider/plugin code must call the `Processor` methods described below when it needs the same parsing contract.

## Validators and output filtering

`FieldValidators.Input` is synchronous. Return a transformed `Value` on success, or a non-nil `Issues` slice on failure. Only the first issue message is exposed. A non-nil empty issues slice still means failure.

```go
Validators: additionalfields.FieldValidators{
    Input: func(value any) (additionalfields.ValidationResult, error) {
        text, ok := value.(string)
        if !ok {
            return additionalfields.ValidationResult{
                Issues: []additionalfields.Issue{{Message: "must be a string"}},
            }, nil
        }
        return additionalfields.ValidationResult{Value: strings.TrimSpace(text)}, nil
    },
},
```

`ValidationResult.Async` models an upstream asynchronous validator and is rejected with a 500 error; Go callbacks must finish synchronously before returning.

`FieldValidators.Output` is retained but is not automatically invoked by endpoint serialization or adapter reads. Call `Processor.ValidateOutput` explicitly if trusted application code needs it. `FilterOutput` and the model-specific output helpers remove `Returned: false` fields and deep-copy the record; they do not run output validators.

`returned:false` is disclosure filtering, not encryption or erasure. The value remains in primary storage and can remain in session cookie caches or secondary storage before public serialization.

## Processor API

Use `additionalfields.Compile` when application or plugin code creates records outside the three hooked root endpoints:

```go
processor, err := additionalfields.Compile(options)
if err != nil {
    return err
}

accountFields, err := processor.ParseAccountInput(storage.Record{
    "tenantId": tenantID,
})
```

| Method | Purpose |
| --- | --- |
| `ParseInput(model, data, action)` | General create/update parser; empty action defaults to create |
| `ParseUserInput` / `ParseAdditionalUserInput` | User parser and create convenience |
| `ParseSessionInput` | Session create/update parser |
| `ParseAccountInput` | Account create parser |
| `ParseProviderUserInput` | Keep only declared writable profile fields, then parse them |
| `ParseAdditionalUserInputFromProviderProfile` | Compatibility alias of the preceding method |
| `SessionDefaults` / `GetSessionDefaultFields` | Evaluate every session default on each call |
| `FilterOutput` | Deep-copy a record and remove core/custom `returned:false` fields |
| `ParseUserOutput`, `ParseSessionOutput`, `ParseAccountOutput` | Model-specific output helpers |
| `ValidateOutput` | Explicitly execute configured output validators |
| `BuildSyntheticUserOutput` | Build the enumeration-resistant public user shape used by sign-up |
| `Schema` | Return an independent schema snapshot |
| `Plugin` | Return an endpoint-hook descriptor backed by the processor |

`Processor` is immutable and safe for concurrent use when all configured validators, transforms, defaults, and clock functions are themselves concurrency-safe.

## Errors

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `FIELD_NOT_ALLOWED` | A truthy value attempted to set an `input:false` field |
| 400 | `VALIDATION_ERROR` | The input validator returned issues; the first message becomes the API message |
| 400 | `MISSING_FIELD` | A create request omitted a field explicitly marked required |
| 500 | `ASYNC_VALIDATION_NOT_SUPPORTED` | A validator reported an asynchronous result |

A validator or transform may return its own error. Preserve intentional `contract.APIError` values; unexpected callback errors should be logged internally without exposing sensitive values.

## Schema and migrations

The factory extends existing models and creates no separate table. Adding, renaming, removing, or changing the type, physical `FieldName`, index, uniqueness, or reference of a field requires a database migration. Generate and apply the migration through the repository's normal storage workflow before deploying code that reads or writes the new shape.

Session defaults participate in normal session creation, cookie-cache serialization, and secondary-storage serialization. Public reads filter hidden fields, but internal caches retain the complete record so later server operations do not lose data.

## Security and troubleshooting

- Set `Input: storage.Bool(false)` on roles, billing state, tenant authority, verification decisions, and every other server-owned field.
- Set `Returned: storage.Bool(false)` on data that should not appear in public API output, but do not use it as a substitute for encryption or secret storage.
- If a required field fails only at the adapter, check whether `Required` was omitted. Runtime create parsing checks explicit `true`; the storage schema treats omission as required.
- If an input transform appears not to run, check for an input validator. The validator's returned value is the parser result for that field.
- If an output validator appears not to run, call `ValidateOutput` explicitly; automatic output paths only filter `returned:false` and use storage transforms.
- If one replica sees an old shape, apply the same migration and application configuration to every replica before accepting writes.
- Field order controls which validation failure is returned first. Keep declaration order stable when clients depend on deterministic error messages.

## Related pages

- [Storage schemas](../storage/schemas.md)
- [Migrations](../storage/migrations.md)
- [Typed models](../core/typed-models.md)
- [Direct API](../transports/direct-api.md)
- [Sessions](../core/sessions.md)
- [Security](../core/security.md)

**Status:** implemented across HTTP transports, direct root methods, primary adapters, session cookie cache, and secondary storage.
