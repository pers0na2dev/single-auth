---
title: "Typed models"
---

Lossless optional values, additional fields, generic model views, and typed direct endpoint bindings.

The production models remain compatible with dynamic schemas while Go callers can recover static types through generic wrappers and explicit decoders.

## Base models

`github.com/pers0na2dev/single-auth/core/model` defines:

- `model.User`: core identity fields plus `AdditionalFields`;
- `model.Session`: ownership, expiry, token, IP/user-agent, plus additional fields;
- `model.Account`: provider identity, credential/OAuth values, plus additional fields;
- `model.Verification`: identifier, value, expiry, plus additional fields;
- `model.RateLimit`: key, count, last-request milliseconds, plus additional fields;
- `model.Record`: canonical `map[string]any` storage row;
- `model.Fields`: additional-field map preserving three-state values.

The root package aliases the five base model types as `singleauth.User`, `Session`, `Account`, `Verification`, and `RateLimit`.

## Absent, null, and present

`model.Value[T]` preserves distinctions that a pointer alone cannot:

```go
absent := model.Absent[string]()       // field not supplied
cleared := model.Null[string]()        // explicit JSON null
name := model.Present("Ada")           // present, even if value is T's zero

if name.IsSet() && !name.IsNull() {
    value, ok := name.Get()
    _ = value
    _ = ok
}
```

Methods are `IsSet`, `IsNull`, `IsZero`, `Get`, `Or`, and `Interface`. The zero value is absent. JSON null decodes as explicit null; a concrete JSON value decodes as present. `Interface` returns `(nil,false)` only for absent and `(nil,true)` for explicit null.

`model.Fields` provides `Set`, `SetNull`, `Unset`, `Lookup`, and `Apply`. Map membership and the nested `Value` state are both respected. `FieldsFromRecord` extracts all non-core fields from a dynamic record.

Base model JSON encoding flattens additional fields into the object. Decoding separates known core fields and preserves unknown fields in `AdditionalFields`.

## Typed users

Define a concrete additional-field shape and decoder:

```go
type UserAdditional struct {
    Role     model.Value[string]
    TenantID string
}

func decodeUserAdditional(fields model.Fields) (UserAdditional, error) {
    role, err := singleauth.DecodeUserField[string](fields, "role")
    if err != nil {
        return UserAdditional{}, err
    }
    tenantID, err := singleauth.RequireDBField[string](fields, "tenantId")
    if err != nil {
        return UserAdditional{}, err
    }
    return UserAdditional{Role: role, TenantID: tenantID}, nil
}

typedAuth, err := singleauth.NewTypedUserAuth(auth, decodeUserAdditional)
if err != nil {
    return err
}

session, err := typedAuth.API().GetSession(ctx, singleauth.GetSessionInput{
    Headers: sessionHeaders,
})
if err != nil {
    return err
}
if session != nil {
    fmt.Println(session.User.Additional.TenantID)
}
```

`TypedUser[Additional]` retains exact base fields and stores the custom shape in `Additional`. `DecodeUserField[T]` returns absent/null/present and rejects a present field of the wrong Go type. `NewTypedAuth` instead accepts a `UserDecoder[Output]` and can return an entirely application-defined user type.

`TypedAuth` embeds `*Auth`, so it remains an `http.Handler` and retains runtime methods. Its typed `API()` currently covers `Call`, `SignUpEmail`, `SignInEmail`, `GetSession`, and `SignOut`. Use the embedded runtime's full untyped direct API for other methods:

```go
accounts, err := typedAuth.Auth.API().ListUserAccounts(ctx, input)
```

## Typed database models

`TypedSession[Additional]`, `TypedAccount[Additional]`, and `TypedVerification[Additional]` keep their base fields and a concrete `Additional` slot. Convert production models with `DecodeSession`, `DecodeAccount`, and `DecodeVerification` using a `DBFieldsDecoder`.

`DecodeDBField[T]` is the model-generic tri-state reader. `RequireDBField[T]` rejects absent, null, and wrong-typed values instead of silently producing a zero value.

```go
type SessionAdditional struct {
    ActiveOrganizationID model.Value[string]
}

typedSession, err := singleauth.DecodeSession(rawSession, func(
    fields model.Fields,
) (SessionAdditional, error) {
    organizationID, err := singleauth.DecodeDBField[string](
        fields,
        "activeOrganizationId",
    )
    return SessionAdditional{ActiveOrganizationID: organizationID}, err
})
```

Use `NoAdditionalFields` as the explicit zero-sized additional type when a model has no configured/plugin fields. `TypedSessionInference[UserAdditional, SessionAdditional]` groups typed user and session values without erasing either shape.

## Typed custom and overridden endpoints

`BindTypedDirectEndpoint` gives a core or plugin direct endpoint a statically selected input and output:

```go
type ExportInput struct {
    Headers contract.Headers
}

type ExportResult struct {
    URL string `json:"url"`
}

endpoint, err := singleauth.BindTypedDirectEndpoint(
    auth,
    "profileExport",
    http.MethodPost,
    func(input ExportInput) singleauth.DirectCallInput {
        return singleauth.DirectCallInput{
            Method:  http.MethodPost,
            Headers: input.Headers,
            Body:    map[string]any{},
        }
    },
    singleauth.DecodeDirectJSON[ExportResult],
)
if err != nil {
    return err
}

result, err := endpoint.Call(ctx, ExportInput{Headers: sessionHeaders})
```

The encoder and decoder are required; construction also requires an initialized auth, endpoint name, and method. `DecodeDirectJSON[T]` decodes the response body into `T` and rejects malformed JSON; normal `encoding/json` rules still apply, including ignoring unknown object fields. A custom `DirectResultDecoder[T]` can also inspect status and headers.

`NoBody` represents an endpoint override that intentionally removes the base body. `BindTypedSignInEmailOverrideAPI` demonstrates a typed override of `signInEmail` while embedding the remaining untyped `DirectAPI` methods.

## Type-contract utilities

The root package also provides explicit Go counterparts for compile-time Better Auth inference:

| Symbol | Purpose |
| --- | --- |
| `TypedRequestContext[Body,Query]` | Keeps body and query types independent with method, path, and params. |
| `AnyKeyShape` | Marks a shape with no statically known required keys. |
| `RequiredKeyShape[T]` / `OptionalKeyShape[T]` | Explicitly mark whether a shape has required keys. |
| `RequiredKeysOf` | Returns `RequiredKeysPresent` or `RequiredKeysAbsent` without reflection. |
| `TypedPluginContext2[A,B]` | Stores two concrete plugin API/configuration types and performs dynamic registry lookup by ID. |
| `KnownPluginPresence` | Compile-time-known true marker returned by `HasFirst` and `HasSecond`. |
| `TypedContext[T]` | Pairs the initialized `AuthContext` with a concrete init extension. |
| `PluginAPIs2[A,B]` / `ComposePluginAPIs2` | Compose differently shaped plugin APIs without flattening collisions. |
| `TypedErrorCodes[T]` / `NewTypedErrorCodes` | Pair the typed base error subset with plugin codes. |
| `PreserveInferenceWithUntypedPlugins` | Retain a typed inference value while also accepting dynamic plugin values. |
| `PreserveErrorCodesWithUntypedPlugins` | Equivalent preservation for typed error codes. |

These utilities do not synthesize fields at runtime. They retain application-selected compile-time shapes while the production runtime continues using validated schemas and lossless dynamic records.

## Decoder rules

- Decode at a trusted boundary and return errors for unexpected types.
- Use `model.Value[T]` for optional nullable fields; use `RequireDBField` only for schema-required data.
- JSON-decoded numbers in dynamic `any` values follow Go JSON number semantics unless a specific direct API decoder retains `json.Number`.
- Do not type-assert additional data without checking null and presence.
- Keep the schema, database migration, field input/output flags, and decoder shape in the same release change.
