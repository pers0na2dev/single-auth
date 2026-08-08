---
title: "Schemas"
---

Define models, fields, aliases, IDs, defaults, transforms, references, and plugin storage.

`storage.Schema` is the canonical description used by primary adapters, migrations, joins, field transformations, plugins, and request/response validation.

```go
type Schema struct {
    Models    map[string]ModelSchema
    UsePlural bool
}

type ModelSchema struct {
    ModelName         string
    Fields            map[string]FieldAttribute
    DisableMigrations bool
    Order             int
}
```

Schema keys are canonical names used by Go code. `ModelName` and `FieldName` are optional physical database aliases.

## Core schema

`storage.CoreSchema()` declares five models:

| Model | Important fields |
| --- | --- |
| `user` | `name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt` |
| `session` | `expiresAt`, `token`, `ipAddress`, `userAgent`, `userId`, timestamps |
| `account` | provider/account IDs, `userId`, OAuth tokens, password, timestamps |
| `verification` | `identifier`, `value`, `expiresAt`, timestamps |
| `rateLimit` | `key`, `count`, `lastRequest` |

The root runtime only materializes the built-in `rateLimit` model when `RateLimit.Storage` is `database`. Plugins and additional options can extend the other models or add new ones.

Every model has an implicit `id` field. Never declare `id` in `ModelSchema.Fields`.

## Add fields to a core model

```go
package authschema

import "github.com/pers0na2dev/single-auth/storage"

func UserProfileSchema() (storage.Schema, error) {
    extension := storage.Schema{
        Models: map[string]storage.ModelSchema{
            "user": {
                Fields: map[string]storage.FieldAttribute{
                    "role": {
                        Type:         storage.FieldEnum,
                        Enum:         []string{"user", "admin"},
                        Required:     storage.Bool(true),
                        DefaultValue: storage.StaticValue("user"),
                        Index:        true,
                    },
                    "bio": {
                        Type:      storage.FieldString,
                        Required:  storage.Bool(false),
                        FieldName: "profile_bio",
                    },
                    "metadata": {
                        Type:     storage.FieldJSON,
                        Required: storage.Bool(false),
                    },
                },
            },
        },
    }

    return storage.CoreSchema().Merge(extension)
}
```

Later fields replace earlier fields with the same canonical name. All other metadata is accumulated. `Merge` clones both inputs and validates the result.

## Add a new model

```go
auditSchema := storage.Schema{
    Models: map[string]storage.ModelSchema{
        "auditEvent": {
            ModelName: "auth_audit_events",
            Order:     20,
            Fields: map[string]storage.FieldAttribute{
                "userId": {
                    Type:     storage.FieldString,
                    Required: storage.Bool(false),
                    Index:    true,
                    References: &storage.Reference{
                        Model:    "user",
                        Field:    "id",
                        OnDelete: storage.SetNull,
                    },
                },
                "action": {
                    Type:     storage.FieldString,
                    Required: storage.Bool(true),
                    Index:    true,
                },
                "payload": {
                    Type:     storage.FieldJSON,
                    Required: storage.Bool(false),
                },
                "createdAt": {
                    Type: storage.FieldDate,
                    DefaultValue: func(ctx storage.ValueContext) (any, error) {
                        if ctx.Now != nil {
                            return ctx.Now().UTC(), nil
                        }
                        return time.Now().UTC(), nil
                    },
                },
            },
        },
    },
}
```

The `SetNull` reference is optional because the database must be able to set it to null.

## Field types

```go
const (
    FieldString      FieldType = "string"
    FieldNumber      FieldType = "number"
    FieldBoolean     FieldType = "boolean"
    FieldDate        FieldType = "date"
    FieldJSON        FieldType = "json"
    FieldStringArray FieldType = "string[]"
    FieldNumberArray FieldType = "number[]"
    FieldEnum        FieldType = "enum"
)
```

| Type | Canonical Go values |
| --- | --- |
| `FieldString` | `string` |
| `FieldNumber` | Finite integer or floating-point numeric values accepted by the adapter |
| `FieldBoolean` | `bool` |
| `FieldDate` | `time.Time`; valid RFC 3339 input may be normalized by adapter boundaries |
| `FieldJSON` | Any JSON-encodable Go value |
| `FieldStringArray` | A string slice or array |
| `FieldNumberArray` | A numeric slice or array |
| `FieldEnum` | A string present in the non-empty `Enum` list |

For portable relational schemas, use `FieldNumber` for integer-like values. PostgreSQL, MySQL, and SQL Server map it to `INTEGER`; set `BigInt` for `BIGINT`.

## Field attributes

```go
type FieldAttribute struct {
    Type         FieldType
    Enum         []string
    Required     *bool
    Returned     *bool
    Input        *bool
    DefaultValue ValueFactory
    OnUpdate     ValueFactory
    Transform    FieldTransform
    References   *Reference
    Unique       bool
    BigInt       bool
    FieldName    string
    Sortable     bool
    Index        bool
}
```

### Required, input, and returned flags

These flags use pointers so omitted and explicit false remain distinct:

```go
Required: storage.Bool(false),
Returned: storage.Bool(false),
Input:    storage.Bool(false),
```

For all three flags, `nil` means true.

- `Required` controls defaulting and schema validation.
- `Input` controls which fields request-side create/update payloads may write.
- `Returned` controls output record schemas.

Direct adapter reads are a trusted server API and can still expose stored fields. `Returned: false` is not an authorization or encryption boundary.

### Defaults

`DefaultValue` runs during create when the field is absent, or when a required field is supplied as null:

```go
DefaultValue: storage.StaticValue(false),
```

Dynamic default:

```go
DefaultValue: func(ctx storage.ValueContext) (any, error) {
    if ctx.Now != nil {
        return ctx.Now().UTC(), nil
    }
    return time.Now().UTC(), nil
},
```

Use `ctx.Now` so the adapter's configured clock remains authoritative.

### On-update values

`OnUpdate` runs when an update omits the field:

```go
OnUpdate: func(ctx storage.ValueContext) (any, error) {
    return ctx.Now().UTC(), nil
},
```

An explicitly supplied value wins.

### Input and output transforms

```go
Transform: storage.FieldTransform{
    Input: func(value any) (any, error) {
        text, ok := value.(string)
        if !ok {
            return nil, fmt.Errorf("expected string")
        }
        return strings.TrimSpace(text), nil
    },
    Output: func(value any) (any, error) {
        return value, nil
    },
},
```

The input transform runs before backend encoding. The output transform runs after backend decoding. Errors abort the operation.

Transforms should be deterministic and should not perform unbounded external work while a database transaction is open.

### Unique, index, and sortable

- `Unique` asks adapters and migration planners to enforce uniqueness.
- `Index` asks migration planners to create a non-unique index.
- `Sortable` marks a field intended for sorting and influences safe indexed string widths on MySQL and SQL Server.

The adapter validates fields referenced by queries, but direct sort calls are not an authorization boundary. Validate user-controlled sort choices in your API layer.

### BigInt

`BigInt` changes relational number storage to a wider integer type. It does not change the public field type.

### Physical field names

`FieldName` maps a canonical field to a database column or BSON key:

```go
"displayName": {
    Type:      storage.FieldString,
    FieldName: "display_name",
},
```

Callers continue to use `displayName` in records, predicates, sorting, and selection.

## References

```go
type Reference struct {
    Model        string
    Field        string
    OnDelete     DeleteAction
    RelationName string
}
```

Supported actions:

```text
NoAction, Restrict, Cascade, SetNull, SetDefault
```

Always set `OnDelete` explicitly. Backend defaults differ, and some backends reject unsupported combinations:

- MySQL rejects `SetDefault`.
- `SetNull` requires an optional field.
- SQL Server emits `NO ACTION` for `Restrict`.
- MongoDB uses references for ID encoding and joins but does not enforce foreign keys or delete actions.

`RelationName` disambiguates multiple references between the same model pair and can be selected through `storage.JoinOption`.

## Model aliases and plural names

```go
schema := storage.Schema{
    UsePlural: true,
    Models: map[string]storage.ModelSchema{
        "user": {
            ModelName: "auth_user",
            Fields:    userFields,
        },
    },
}
```

With `UsePlural`, the physical name becomes `auth_users`. The implementation appends a literal `s`; it does not perform language-aware pluralization.

`Schema.ResolveModel` accepts canonical or physical names. Exact canonical matches take precedence over aliases. `Schema.ResolveField` behaves the same way for fields. Duplicate physical names are rejected by `Validate`.

## Disable migrations and ordering

```go
"externalIdentity": {
    ModelName:         "external_identity",
    DisableMigrations: true,
    Order:             30,
    Fields:            externalFields,
},
```

- `DisableMigrations` excludes the model from generated schema changes. Adapter queries still expect the model to exist externally.
- `Order` controls table/collection creation order. Equal-order models are sorted deterministically by physical name.

Foreign-key-capable planners also defer constraints where needed to support cyclic references.

## SQL presence columns

SQLite, PostgreSQL, MySQL, and SQL Server create an internal column for every non-ID field:

```text
__single_present__<canonical-field-name>
```

This allows a relational row to distinguish:

- field absent from the original record;
- field explicitly present with null;
- field present with a non-null value.

Do not define a physical field whose name begins with `__single_present__`. MongoDB and memory storage preserve this distinction natively.

## Compose plugin schemas

Plugin factories expose deterministic schemas before they are bound to a runtime:

```go
func BuildWithPlugins(
    factories []singleauth.PluginFactory,
) (storage.Schema, error) {
    schema := storage.CoreSchema()
    for _, factory := range factories {
        extension, err := factory.Schema()
        if err != nil {
            return storage.Schema{}, err
        }
        schema, err = schema.Merge(extension)
        if err != nil {
            return storage.Schema{}, err
        }
    }
    return schema, nil
}
```

Use the resulting schema for the explicit adapter, then pass the same factories to `Options.PluginFactories`.

## Database-backed rate-limit schema

When rate limits use database storage, merge the exported model before constructing an explicit adapter:

```go
rateSchema := ratelimit.SchemaWithModelName("auth_rate_limit")

model := rateSchema.Models["rateLimit"]
model.Fields["key"] = storage.FieldAttribute{
    Type:      storage.FieldString,
    Unique:    true,
    FieldName: "rate_key",
}
rateSchema.Models["rateLimit"] = model

schema, err = schema.Merge(rateSchema)
```

Keep those physical aliases synchronized with `RateLimit.Fields`.

## ID generation

The root option has this signature:

```go
type IDGenerator func(
    model string,
    size int,
) (value string, generated bool, err error)
```

Returning `generated=false` asks a database-backed initializer to let the database generate the ID. The built-in memory adapter and `NewWithSQLiteDatabase` require generated string IDs.

Explicit adapters have their own `IDGenerator` option with signature `func(model string) (any, error)`. Root `Options.GenerateID` does not reconfigure an adapter that was constructed earlier; pass the generator to both places when consistent custom IDs are required.

`CreateParams.ForceAllowID` controls caller-supplied IDs:

```go
record, err := adapter.Create(ctx, storage.CreateParams{
    Model:        "user",
    ForceAllowID: true,
    Data: storage.Record{
        "id":    "imported-user-1",
        "name":  "Ada",
        "email": "ada@example.com",
    },
})
```

Without `ForceAllowID`, the adapter discards the supplied `id` and generates one according to its configuration. Serial and UUID modes also validate forced IDs and can fall back to backend generation when an invalid value is supplied.

## Record schemas

`storage.ToRecordSchema` builds an input or output validator from field metadata:

```go
inputSchema := storage.ToRecordSchema(model.Fields, true)
outputSchema := storage.ToRecordSchema(model.Fields, false)

parsed, err := inputSchema.Parse(storage.Record{
    "role": "admin",
})
```

Unknown fields are stripped. Required fields must be present and non-null; optional fields may be absent or null. `FieldNames` returns deterministic sorted names, and `HasField` checks selection.

## Low-level effective table builder

`storage.GetAuthTables` exposes the storage-relevant table merge model through `storage.AuthTablesOptions`. It can omit session and verification tables when secondary storage is authoritative, merge physical core-field aliases, merge plugin table metadata, and add the rate-limit table only for database storage.

Most applications should use `storage.CoreSchema().Merge(...)` with plugin factory schemas because that matches the actual explicit adapter being constructed. `GetAuthTables` is useful for tooling that already represents configuration through its `AuthTablesOptions` types.
