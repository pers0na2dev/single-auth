---
title: "Custom adapters"
---

Implement a primary backend through the adapter factory, transformations, capabilities, atomic methods, and contract tests.

Use `storage.NewAdapterFactory` to expose a custom backend through the canonical single-auth storage contract. The factory handles schema aliases, scalar conversions, IDs, selections, joins, defaults, transforms, and output normalization around a low-level driver.

Prefer a built-in native adapter when one exists. A custom adapter must preserve authorization-sensitive guard, transaction, and atomic-consumption behavior.

## Constructor boundary

The low-level driver is `storage.CustomAdapter`:

```go
type CustomAdapter struct {
    Create     func(context.Context, CreateParams) (Record, error)
    FindOne    func(context.Context, FindOneParams) (Record, error)
    FindMany   func(context.Context, FindManyParams) ([]Record, error)
    Count      func(context.Context, CountParams) (int64, error)
    Update     func(context.Context, UpdateParams) (Record, error)
    UpdateMany func(context.Context, UpdateManyParams) (int64, error)
    Delete     func(context.Context, DeleteParams) error
    DeleteMany func(context.Context, DeleteManyParams) (any, error)

    ConsumeOne   func(context.Context, ConsumeOneParams) (Record, error)
    IncrementOne func(context.Context, IncrementOneParams) (Record, error)
}
```

The first eight callbacks are required. `ConsumeOne` and `IncrementOne` are optional but strongly recommended for a distributed authentication service.

The factory forwards physical model/field names and backend-native scalar values to these callbacks. It translates their results back to canonical records.

## Complete factory wrapper

The following helper is complete and accepts a fully implemented driver plus an optional transaction runner:

```go
package customstore

import (
    "context"
    "time"

    "github.com/pers0na2dev/single-auth/storage"
)

type TransactionRunner func(
    context.Context,
    func(storage.TransactionAdapter) error,
) error

type Options struct {
    Schema       storage.Schema
    Driver       storage.CustomAdapter
    Capabilities storage.Capabilities
    Transaction  TransactionRunner
    GenerateID   func(model string) (any, error)
}

func New(options Options) (storage.Adapter, error) {
    capabilities := options.Capabilities

    return storage.NewAdapterFactory(
        storage.AdapterFactoryConfig{
            AdapterID:           "custom-primary",
            AdapterName:         "Custom Primary Adapter",
            Schema:              options.Schema,
            Capabilities:        &capabilities,
            DefaultFindManyLimit: 100,
            Clock:                time.Now,
            GenerateID:           options.GenerateID,
            Transaction:          options.Transaction,
        },
        options.Driver,
    )
}
```

The transaction callback must execute the factory callback with an adapter whose operations participate in the same backend transaction. Do not pass the ordinary non-transactional driver by mistake.

## Required callback behavior

### Create

- Insert one physical record.
- Respect transformed `Data` values.
- Return the inserted physical record.
- Surface unique conflicts as an error; wrapping `storage.ErrUniqueConstraint` is recommended.

### FindOne

- Apply every predicate.
- Return `(nil, nil)` when nothing matches.
- Apply projection when the backend handles it.
- Support native joins only when advertised.

### FindMany

- Apply predicates, limit, offset, sort, selection, and advertised native joins.
- Return records in deterministic backend order when `SortBy` is supplied.
- Return an empty slice for explicit zero limit.

### Count

- Count all records matching the complete predicate.
- Return `int64`.

### Update

- Guard the mutation with the complete `Where` list.
- Update at most one record.
- Return the updated physical record.
- Return `(nil, nil)` on guard miss.
- Never interpret empty singular predicates as update-all.

### UpdateMany

- Update every matching record.
- Return an exact non-negative affected-row count.
- Empty predicates mean all rows.

### Delete

- Delete at most one matching record.
- Missing rows succeed.
- Empty singular predicates delete nothing.

### DeleteMany

- Delete every matching record.
- Return an exact non-negative integer in any Go integer type accepted by the factory.
- Empty predicates mean all rows.

The low-level return type is `any` because the factory validates third-party driver results. A malformed, negative, fractional, NaN, infinite, or overflowing result becomes `*storage.InvalidDeleteManyResultError`.

## Atomic callbacks

### ConsumeOne

`ConsumeOne` must atomically select and delete exactly one matching record. The
same backend can expose both atomic primitives through this complete callback
builder:

```go
type AtomicBackend interface {
    AtomicFindAndDelete(
        context.Context,
        string,
        []storage.Where,
    ) (storage.Record, error)
    AtomicIncrementAndReturn(
        context.Context,
        string,
        []storage.Where,
        map[string]float64,
        storage.Record,
    ) (storage.Record, error)
}

func AtomicCallbacks(backend AtomicBackend) (
    func(context.Context, storage.ConsumeOneParams) (storage.Record, error),
    func(context.Context, storage.IncrementOneParams) (storage.Record, error),
) {
    consume := func(
        ctx context.Context,
        params storage.ConsumeOneParams,
    ) (storage.Record, error) {
        return backend.AtomicFindAndDelete(ctx, params.Model, params.Where)
    }

    increment := func(
        ctx context.Context,
        params storage.IncrementOneParams,
    ) (storage.Record, error) {
        return backend.AtomicIncrementAndReturn(
            ctx,
            params.Model,
            params.Where,
            params.Increment,
            params.Set,
        )
    }

    return consume, increment
}
```

Only one concurrent caller may receive a particular record. Return `(nil, nil)` when no row matches.

When omitted, the factory uses `FindMany(limit=1)` followed by guarded `DeleteMany`. That compatibility fallback is safely atomic only when the underlying transaction and delete guard provide the necessary isolation.

### IncrementOne

`IncrementOne` must evaluate all predicates and atomically apply numeric deltas and `Set` values. Assign the callbacks returned above to the low-level driver:

```go
func AttachAtomicCallbacks(
    driver *storage.CustomAdapter,
    backend AtomicBackend,
) {
    consume, increment := AtomicCallbacks(backend)
    driver.ConsumeOne = consume
    driver.IncrementOne = increment
}
```

Return `(nil, nil)` on guard miss. Negative increments are valid. The factory rejects requests where both update maps are empty.

When omitted, the factory uses a read followed by guarded `UpdateMany`. The same transaction/isolation warning applies.

## Factory configuration

```go
type AdapterFactoryConfig struct {
    AdapterID   string
    AdapterName string
    Schema      storage.Schema

    Capabilities         *storage.Capabilities
    DefaultFindManyLimit int
    IDGeneration         storage.IDGenerationMode
    UseNumericIDs        bool
    DisableIDGeneration bool
    Clock                func() time.Time
    GenerateID           func(model string) (any, error)
    CustomIDGenerator    storage.IDGenerator
    Random               io.Reader
    Warn                 func(message string)

    MapKeysTransformInput  map[string]string
    MapKeysTransformOutput map[string]string
    DisableTransformInput  bool
    DisableTransformOutput bool
    DisableTransformJoin   bool

    TransformInput  func(storage.AdapterTransformContext) (any, error)
    TransformOutput func(storage.AdapterOutputTransformContext) (any, error)
    Transaction     func(context.Context, func(storage.TransactionAdapter) error) error
}
```

### Identity

`AdapterID` is required and should be stable. `AdapterName` defaults to the ID.

### Schema and default limit

An empty schema selects `storage.CoreSchema()`. The schema is cloned and validated. The zero default limit selects 100; negative values are rejected.

### Capabilities

A nil capability set uses factory defaults: native numbers, dates, and booleans; encoded JSON and arrays; and no native joins.

When supplied, describe the low-level driver's physical behavior, not the desired public behavior:

```go
Capabilities: &storage.Capabilities{
    NumericIDs:       false,
    UUIDs:            true,
    JSON:             true,
    Dates:            true,
    Booleans:         true,
    Arrays:           true,
    Transactions:     true,
    Joins:            true,
    AtomicConsumeOne: true,
    AtomicIncrement:  true,
},
```

The factory sets `Transactions` from the presence of the transaction callback, and atomic flags from native callback presence.

### ID generation modes

```text
IDGenerationDefault
IDGenerationNone
IDGenerationSerial
IDGenerationUUID
```

- Default uses the end-user generator, custom generator, or built-in random 32-character ID according to precedence.
- None disables generated IDs.
- Serial expects database-generated numeric IDs unless `ForceAllowID` is used.
- UUID applies UUID validation and generation rules.

`UseNumericIDs` is a compatibility alias for serial generation. Prefer `IDGeneration` in new custom adapters.

`GenerateID` has priority over `CustomIDGenerator`. `Random` defaults to `crypto/rand.Reader`.

### Key maps

`MapKeysTransformInput` and `MapKeysTransformOutput` provide transformations beyond `FieldAttribute.FieldName`. Keep the maps reversible and test every predicate, mutation, selection, and join path.

### Disable-transform flags

- `DisableTransformInput` passes records through without scalar/input transforms, but unapproved caller IDs are still stripped.
- `DisableTransformOutput` returns low-level records without canonical output transforms.
- `DisableTransformJoin` prevents join transformation.

These switches are advanced escape hatches. Enabling them shifts responsibility for canonical behavior to the low-level driver.

### Custom transforms

`TransformInput` receives:

- action;
- current data value;
- physical field;
- field metadata;
- physical model;
- an isolated schema copy.

`TransformOutput` receives canonical output-field context plus the selection list. Return transformation errors instead of silently discarding invalid values.

## Native joins

When `Capabilities.Joins` is true, the factory derives physical join descriptions:

```go
type JoinOn struct {
    From string
    To   string
}

type Relation string
```

Relations can be `OneToOne`, `OneToMany`, or `ManyToMany`. The public schema currently infers common one-to-one and one-to-many reference paths. A relation name disambiguates multiple foreign keys.

When native joins are false, the factory can perform compatible follow-up queries unless `DisableTransformJoin` is enabled.

## Transactions

Set a transaction callback only when the backend actually provides rollback semantics. Keep the transaction runner explicit at the constructor boundary:

```go
func WithTransactionRunner(options Options, run TransactionRunner) Options {
    options.Transaction = run
    return options
}
```

A custom factory without a transaction callback can execute the callback against itself non-transactionally while reporting `Capabilities().Transactions == false`. Applications requiring rollback must check the capability before calling.

`storage.RunWithTransaction` reuses a transaction bound in its context, which prevents custom atomic fallbacks from starting a nested transaction.

## Contract testing

Run the public adapter suite against a factory that creates a fresh isolated database for every subtest:

```go
func RunContract(t *testing.T, factory adaptertest.Factory) {
    t.Helper()
    adaptertest.Run(t, factory)
}
```

The supplied factory owns provisioning. It receives the schema required by the
current subtest, constructs the adapter, calls `EnsureSchema` when supported,
and registers cleanup with `t.Cleanup`. The suite checks CRUD, aliases,
selections, predicate operators, null/missing semantics, pagination, joins,
uniqueness, atomic consumption, atomic guarded increments, rollback,
cancellation, and concurrency.

Back the suite with a real service through Testcontainers; mocks alone cannot prove transaction, locking, driver conversion, index, or constraint behavior.
