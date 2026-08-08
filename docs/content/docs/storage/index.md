---
title: "Storage overview"
---

Choose and configure primary and secondary storage for single-auth.

single-auth separates durable authentication records from optional cache-like data:

- A **primary adapter** stores users, accounts, sessions, verification records, plugin models, and database-backed rate limits.
- A **secondary store** can make sessions, verification values, and rate-limit counters available through Redis or another low-latency key-value service.

If `Options.Database` is omitted, single-auth creates a concurrent in-memory primary adapter. That is useful for tests and ephemeral processes, but it is not durable.

## Supported backends

| Backend | Package | Primary or secondary | Transactions | Runtime schema setup |
| --- | --- | --- | --- | --- |
| Memory | `github.com/pers0na2dev/single-auth/storage/memory` | Primary | Yes | Not required |
| SQLite | `github.com/pers0na2dev/single-auth/storage/sqlite` | Primary | Yes | `EnsureSchema` |
| PostgreSQL | `github.com/pers0na2dev/single-auth/storage/postgres` | Primary | Yes | `EnsureSchema` |
| MySQL | `github.com/pers0na2dev/single-auth/storage/mysql` | Primary | Yes | `EnsureSchema` |
| SQL Server | `github.com/pers0na2dev/single-auth/storage/mssql` | Primary | Yes | `EnsureSchema` |
| MongoDB | `github.com/pers0na2dev/single-auth/storage/mongodb` | Primary | Replica set or supported sharded deployment | `EnsureSchema` |
| Redis | `github.com/pers0na2dev/single-auth/storage/secondary/redis` | Secondary only | Atomic key primitives | No relational schema |

Every database constructor accepts a connection handle that your application owns. The adapter does not close that handle, and constructing an adapter does not connect, ping, or modify the database.

## Minimal setup

The smallest configuration uses the built-in memory adapter:

```go
package main

import (
    "log"
    "os"

    singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
    secret := os.Getenv("SINGLE_AUTH_SECRET")
    if len(secret) < 32 {
        log.Fatal("SINGLE_AUTH_SECRET must contain at least 32 characters")
    }

    auth, err := singleauth.New(singleauth.Options{
        BaseURL: "http://localhost:3000",
        Secret:  secret,
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("using %s storage", auth.Adapter().ID())
}
```

For a durable backend, open the driver connection, build the matching adapter, pass it through `Options.Database`, and run migrations explicitly:

```go
adapter, err := postgresstore.New(database, postgresstore.Options{
    Schema: storage.CoreSchema(),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL:  "https://example.com",
    Secret:   secret,
    Database: adapter,
})
if err != nil {
    return err
}

if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

`singleauth.New` never runs migrations automatically.

## Build the final schema first

An explicit adapter snapshots its schema when its constructor runs. single-auth cannot add plugin models to an adapter that has already been created.

Before constructing an explicit memory, SQLite, PostgreSQL, MySQL, SQL Server, or MongoDB adapter, merge:

1. `storage.CoreSchema()`;
2. your additional models and fields;
3. every plugin factory schema;
4. the rate-limit schema when rate limits use database storage.

```go
package authschema

import (
    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/storage"
)

func Build(
    additional storage.Schema,
    factories ...singleauth.PluginFactory,
) (storage.Schema, error) {
    schema := storage.CoreSchema()

    var err error
    if len(additional.Models) != 0 {
        schema, err = schema.Merge(additional)
        if err != nil {
            return storage.Schema{}, err
        }
    }

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

Pass the same factories to `Options.PluginFactories` after using their schemas to configure the adapter.

`NewWithSQLiteDatabase` is the exception: it creates its native SQLite adapter only after single-auth has composed the final schema, so manual plugin-schema merging is unnecessary for that constructor.

## Primary adapter contract

All primary adapters implement `storage.Adapter`. The transaction-scoped operation set is `storage.TransactionAdapter`:

```go
type TransactionAdapter interface {
    Create(context.Context, CreateParams) (Record, error)
    FindOne(context.Context, FindOneParams) (Record, error)
    FindMany(context.Context, FindManyParams) ([]Record, error)
    Count(context.Context, CountParams) (int64, error)
    Update(context.Context, UpdateParams) (Record, error)
    UpdateMany(context.Context, UpdateManyParams) (int64, error)
    Delete(context.Context, DeleteParams) error
    DeleteMany(context.Context, DeleteManyParams) (int64, error)
    ConsumeOne(context.Context, ConsumeOneParams) (Record, error)
    IncrementOne(context.Context, IncrementOneParams) (Record, error)
}
```

`storage.Record` is a `map[string]any`. Model and field names in public calls are canonical schema names; adapters translate configured physical aliases internally.

Important return conventions:

- `FindOne`, `Update`, `ConsumeOne`, and `IncrementOne` return `nil, nil` when nothing matches.
- `FindMany` returns a slice and defaults to at most 100 records when `Limit` is omitted.
- `Count`, `UpdateMany`, and `DeleteMany` return affected-row counts as `int64`.
- Public IDs and ID references are decoded to strings, including serial IDs and MongoDB ObjectIDs.
- Inputs and outputs are copied. Mutating a retained `storage.Record` does not mutate stored state.

See [Queries and mutations](/docs/storage/queries-and-mutations) for every operation and query operator.

## Adapter capabilities

`adapter.Capabilities()` describes physical scalar representations and optional native behavior:

```go
type Capabilities struct {
    NumericIDs       bool
    UUIDs            bool
    JSON             bool
    Dates            bool
    Booleans         bool
    Arrays           bool
    Transactions     bool
    Joins            bool
    SchemaCreation   bool
    AtomicConsumeOne bool
    AtomicIncrement  bool
}
```

A scalar flag set to `false` does not necessarily mean the public feature is unavailable. It can mean the adapter encodes that value into a driver-compatible representation. For example, SQLite exposes JSON values through the public API while storing them as text.

Check `Transactions` before relying on rollback semantics. Check `SchemaCreation` before asserting `storage.SchemaCreator`.

## Migrations are explicit and additive

Native `EnsureSchema` implementations:

- create missing tables or MongoDB collections;
- add missing relational columns;
- create missing indexes;
- create missing relational foreign keys where the backend permits it;
- do nothing when the schema is already current.

They do not drop tables or columns, rename objects, rewrite incompatible types, or backfill application data. Read [Migrations](/docs/storage/migrations) before using them on an existing production database.

## Secondary storage

Configure Redis or a custom key-value implementation through `Options.SecondaryStorage`, never through `Options.Database`.

When secondary storage is configured:

- sessions are secondary-only unless `Session.StoreSessionInDatabase` is true;
- verification records are secondary-only unless `Verification.StoreInDatabase` is true;
- rate limiting defaults to secondary storage unless another mode is selected explicitly.

Single-use verification data needs an atomic get-and-delete primitive across processes. The Redis implementation provides it. A custom store without that optional interface is protected only within one Go process.

See [Redis secondary storage](/docs/storage/redis-secondary-storage).

## Connection ownership

Your application is responsible for:

- importing and configuring a database driver;
- opening and pinging the connection;
- pool sizing and timeouts;
- TLS and credentials;
- running migrations at the appropriate deployment stage;
- closing `*sql.DB`, `*mongo.Client`, and Redis clients during shutdown.

The canonical module path is `github.com/pers0na2dev/single-auth`. Local development checkouts may use a `replace` directive while keeping that canonical requirement and import path.
