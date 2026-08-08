---
title: "Queries and mutations"
---

Use every primary adapter operation, predicate, selection, sort, join, and atomic mutation.

All primary adapters expose the same canonical API through `storage.Adapter`. The concrete backend translates model names, field aliases, values, and ID representations.

Every operation accepts a `context.Context`. Pass a non-nil request or job context so cancellation and deadlines reach the backend.

## Records

```go
type Record = map[string]any
```

Use canonical schema field names:

```go
storage.Record{
    "name":          "Ada",
    "email":         "ada@example.com",
    "emailVerified": false,
}
```

Unknown fields are discarded by native adapters. Inputs and outputs are copied, including nested maps and slices.

## Create

```go
created, err := adapter.Create(ctx, storage.CreateParams{
    Model: "user",
    Data: storage.Record{
        "name":  "Ada",
        "email": "ada@example.com",
    },
})
```

Parameters:

- `Model`: canonical or configured physical model name.
- `Data`: canonical record values.
- `Select`: optional fields returned from the created row.
- `ForceAllowID`: permits an explicitly supplied ID.

Without `ForceAllowID`, an input `id` is stripped before generation.

```go
created, err := adapter.Create(ctx, storage.CreateParams{
    Model:        "user",
    ForceAllowID: true,
    Select:       []string{"id", "email"},
    Data: storage.Record{
        "id":    "imported-user-1",
        "name":  "Ada",
        "email": "ada@example.com",
    },
})
```

Unique violations return an error matching `storage.ErrUniqueConstraint`.

## Find one

```go
user, err := adapter.FindOne(ctx, storage.FindOneParams{
    Model: "user",
    Where: []storage.Where{
        {Field: "email", Value: "ada@example.com"},
    },
    Select: []string{"id", "name", "email"},
})
if err != nil {
    return err
}
if user == nil {
    return nil
}
```

No match is `nil, nil`; it is not `storage.ErrModelNotFound`. `ErrModelNotFound` means the schema does not contain the requested model.

## Find many

```go
users, err := adapter.FindMany(ctx, storage.FindManyParams{
    Model: "user",
    Where: []storage.Where{
        {
            Field:    "name",
            Operator: storage.OpStartsWith,
            Value:    "a",
            Mode:     storage.Insensitive,
        },
    },
    Select: []string{"id", "name", "email"},
    SortBy: &storage.Sort{
        Field:     "name",
        Direction: storage.Ascending,
    },
    Limit:  storage.Int(25),
    Offset: storage.Int(50),
})
```

An omitted limit selects the adapter's configured default, normally 100. `storage.Int(0)` requests zero records. Negative limit or offset is rejected with `storage.ErrInvalidQuery`.

For deterministic pagination, sort by a stable field and add your own tie-breaking strategy when values can be equal.

## Count

```go
count, err := adapter.Count(ctx, storage.CountParams{
    Model: "session",
    Where: []storage.Where{
        {Field: "userId", Value: userID},
        {
            Field:    "expiresAt",
            Operator: storage.OpGt,
            Value:    time.Now().UTC(),
        },
    },
})
```

The result is `int64`.

## Predicates

```go
type Where struct {
    Field     string
    Value     any
    Operator  Operator
    Connector Connector
    Mode      ComparisonMode
}
```

Zero values normalize to:

- `Operator: storage.OpEq`
- `Connector: storage.And`
- `Mode: storage.Sensitive`

### Operators

| Constant | Meaning |
| --- | --- |
| `OpEq` | Equal |
| `OpNe` | Not equal |
| `OpLt` | Less than |
| `OpLTE` | Less than or equal |
| `OpGt` | Greater than |
| `OpGTE` | Greater than or equal |
| `OpIn` | Equal to one item in an array or slice |
| `OpNotIn` | Not equal to every item in an array or slice |
| `OpContains` | String/collection contains |
| `OpStartsWith` | String prefix |
| `OpEndsWith` | String suffix |

`OpIn` and `OpNotIn` require an array or slice value:

```go
Where: []storage.Where{
    {
        Field:    "id",
        Operator: storage.OpIn,
        Value:    []string{"user-1", "user-2"},
    },
},
```

Case-insensitive matching is intended for string operands:

```go
storage.Where{
    Field: "email",
    Value: "ADA@EXAMPLE.COM",
    Mode:  storage.Insensitive,
}
```

Null behavior is portable:

- `OpEq` with `nil` matches missing and explicit null.
- `OpNe` with `nil` matches only present non-null values.

### AND and OR

Database-backed adapters group all `AND` clauses and all `OR` clauses, then require both non-empty groups to match. The memory adapter preserves its flat left-to-right evaluation behavior.

For behavior that remains identical across every backend:

- use only `AND` clauses in one query; or
- use only `OR` clauses in one query; or
- split a complex Boolean expression into explicit application-level queries.

`storage.GroupWhere` normalizes and partitions a flat list using the database-backed grouping rules.

## Sort

```go
SortBy: &storage.Sort{
    Field:     "createdAt",
    Direction: storage.Descending,
},
```

The zero direction behaves as ascending in native adapters. Prefer the explicit `storage.Ascending` or `storage.Descending` constants.

## Selection

`Select` contains canonical field names:

```go
Select: []string{"id", "email"},
```

Duplicate selections are removed. Unknown fields return `storage.ErrFieldNotFound`. An empty selection returns the complete stored record, including trusted server-side fields; use a higher-level response schema before exposing records to clients.

## Joins

Joins are inferred from `FieldAttribute.References`:

```go
user, err := adapter.FindOne(ctx, storage.FindOneParams{
    Model: "user",
    Where: []storage.Where{{Field: "id", Value: userID}},
    Join: map[string]storage.JoinOption{
        "session": {},
    },
})
```

A one-to-many result is stored as `[]storage.Record` under the requested map key. A one-to-one result is a `storage.Record`.

Use `Model` when the output key is only an alias:

```go
Join: map[string]storage.JoinOption{
    "activeSessions": {
        Model: "session",
        Limit: storage.Int(10),
    },
},
```

Use `RelationName` when multiple references connect the same model pair:

```go
Join: map[string]storage.JoinOption{
    "owner": {
        Model:        "user",
        RelationName: "owner",
    },
},
```

An omitted join limit uses the adapter default. `storage.Int(0)` produces an empty joined collection.

`JoinOption.On` and `JoinOption.Relation` are populated for low-level custom adapters that advertise native joins. Normal callers should leave them unset.

## Update one

```go
updated, err := adapter.Update(ctx, storage.UpdateParams{
    Model: "user",
    Where: []storage.Where{
        {Field: "id", Value: userID},
        {Field: "email", Value: expectedEmail},
    },
    Update: storage.Record{
        "name": "Ada Lovelace",
    },
})
```

The full predicate is a guard. A miss returns `nil, nil`. An empty `Where` intentionally updates nothing. `OnUpdate` schema callbacks run for fields omitted from the update.

## Update many

```go
affected, err := adapter.UpdateMany(ctx, storage.UpdateManyParams{
    Model: "session",
    Where: []storage.Where{
        {Field: "userId", Value: userID},
    },
    Update: storage.Record{
        "userAgent": "revoked-client",
    },
})
```

An empty `Where` updates every row in the model. Treat filters derived from user input carefully.

## Delete one

```go
err := adapter.Delete(ctx, storage.DeleteParams{
    Model: "session",
    Where: []storage.Where{
        {Field: "token", Value: token},
    },
})
```

Deleting a missing row succeeds. An empty `Where` deletes nothing.

## Delete many

```go
affected, err := adapter.DeleteMany(ctx, storage.DeleteManyParams{
    Model: "session",
    Where: []storage.Where{
        {Field: "userId", Value: userID},
    },
})
```

An empty `Where` deletes every row in the model. The count is `int64`.

## Atomic consume one

Use `ConsumeOne` for verification codes, state, and other one-time records:

```go
verification, err := adapter.ConsumeOne(ctx, storage.ConsumeOneParams{
    Model: "verification",
    Where: []storage.Where{
        {Field: "identifier", Value: identifier},
        {
            Field:    "expiresAt",
            Operator: storage.OpGt,
            Value:    time.Now().UTC(),
        },
    },
})
```

Exactly one concurrent caller can receive a particular matching row from native adapters. A miss returns `nil, nil`. When a non-unique predicate matches several rows, exactly one row is removed.

## Atomic increment one

```go
updated, err := adapter.IncrementOne(ctx, storage.IncrementOneParams{
    Model: "rateLimit",
    Where: []storage.Where{
        {Field: "key", Value: rateLimitKey},
        {
            Field:    "count",
            Operator: storage.OpLt,
            Value:    100,
        },
    },
    Increment: map[string]float64{
        "count": 1,
    },
    Set: storage.Record{
        "lastRequest": time.Now().UnixMilli(),
    },
})
```

`Increment` accepts positive or negative deltas. Every incremented field must currently contain a numeric value. `Set` values are applied in the same guarded mutation. Both maps cannot be empty.

The guard is evaluated atomically by native adapters. A failed guard returns `nil, nil` and changes nothing.

## Errors

Use `errors.Is` for stable storage categories:

```go
switch {
case errors.Is(err, storage.ErrModelNotFound):
    // The model is absent from the configured schema.
case errors.Is(err, storage.ErrFieldNotFound):
    // A predicate, selection, mutation, or sort named an unknown field.
case errors.Is(err, storage.ErrInvalidQuery):
    // Invalid operator, connector, mode, limit, offset, or value shape.
case errors.Is(err, storage.ErrInvalidIncrement):
    // Invalid or empty increment operation.
case errors.Is(err, storage.ErrUniqueConstraint):
    // Duplicate ID or unique field.
case errors.Is(err, storage.ErrTransactionsUnsupported):
    // Strict transaction behavior is unavailable.
}
```

A missing row is normally represented by a nil record, not an error.
