---
title: "SQLite"
---

Use the native SQLite adapter with database/sql and explicit additive migrations.

The SQLite adapter works with an already opened `*sql.DB`. It does not import a concrete driver, does not close the handle, and does not modify the database during construction.

The selected SQLite build must support `RETURNING` and JSON functions. Configure connection-wide settings such as foreign-key enforcement and busy timeout through your driver.

## Recommended setup

`NewWithSQLiteDatabase` is the easiest full-runtime constructor. It creates the adapter after single-auth has composed all additional and plugin schemas.

```go
package main

import (
    "context"
    "database/sql"
    "log"
    "os"

    _ "modernc.org/sqlite"

    singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
    secret := os.Getenv("SINGLE_AUTH_SECRET")
    if len(secret) < 32 {
        log.Fatal("SINGLE_AUTH_SECRET must contain at least 32 characters")
    }

    database, err := sql.Open(
        "sqlite",
        "file:auth.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)",
    )
    if err != nil {
        log.Fatal(err)
    }
    defer database.Close()

    if err := database.PingContext(context.Background()); err != nil {
        log.Fatal(err)
    }

    auth, err := singleauth.NewWithSQLiteDatabase(singleauth.Options{
        BaseURL: "http://localhost:3000",
        Secret:  secret,
    }, database)
    if err != nil {
        log.Fatal(err)
    }

    if err := auth.RunMigrationsContext(context.Background()); err != nil {
        log.Fatal(err)
    }

    contextSnapshot, err := auth.Context()
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("adapter=%s database=%s", contextSnapshot.Adapter.ID(), contextSnapshot.DatabaseType)
}
```

`NewWithSQLiteDatabase` rejects a nil handle and rejects configurations that also set `Options.Database`.

## Explicit adapter

Use the package constructor when you need adapter-specific options or want to call it directly:

```go
package authsetup

import (
    "database/sql"
    "fmt"
    "sync/atomic"
    "time"

    "github.com/pers0na2dev/single-auth/storage"
    sqlitestore "github.com/pers0na2dev/single-auth/storage/sqlite"
)

func NewSQLiteAdapter(
    database *sql.DB,
    schema storage.Schema,
) (*sqlitestore.Adapter, error) {
    var sequence atomic.Uint64

    return sqlitestore.New(database, sqlitestore.Options{
        Schema: schema,
        IDGenerator: func(model string) (any, error) {
            return fmt.Sprintf("%s-%d", model, sequence.Add(1)), nil
        },
        Clock:                time.Now,
        DefaultFindManyLimit: 250,
    })
}
```

When no schema is supplied, `storage.CoreSchema()` is used. When `DefaultFindManyLimit` is zero, the default is 100; negative values are rejected. The default ID generator creates a random 32-character hexadecimal string.

An explicit adapter must be built with the [final merged schema](/docs/storage/schemas) before it is passed to `singleauth.New`.

## Connection configuration

SQLite pragmas are often connection-local. Set them through a DSN mechanism that applies to every pooled connection. With `modernc.org/sqlite`:

```go
database, err := sql.Open(
    "sqlite",
    "file:auth.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)",
)
```

For a shared in-memory database, keep the pool on one connection unless the selected driver documents another safe setup:

```go
database, err := sql.Open(
    "sqlite",
    "file:auth-tests?mode=memory&cache=shared&_pragma=foreign_keys(1)",
)
if err != nil {
    return err
}
database.SetMaxOpenConns(1)
```

For a file-backed database, choose pool limits according to your workload. The adapter serializes mutations through an internal write gate while allowing reads to use the database pool.

## Scalar storage

The public API continues to use Go values while SQLite stores:

| single-auth type | SQLite representation |
| --- | --- |
| ID | `TEXT` |
| String and enum | `TEXT` |
| Date | RFC 3339 text |
| JSON and arrays | JSON text |
| Number | `NUMERIC`, or `INTEGER` for `BigInt` |
| Boolean | `INTEGER` with a `0/1` check |

The adapter creates hidden `__single_present__<field>` columns so missing values remain distinguishable from fields explicitly set to null. Do not create schema fields with that prefix.

## Schema setup

Run the configured adapter's additive migration:

```go
if err := adapter.EnsureSchema(ctx); err != nil {
    return err
}
```

Or, after creating `Auth`:

```go
if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

`EnsureSchema`:

- introspects existing tables and columns;
- creates missing tables;
- adds missing columns and presence columns;
- creates missing indexes;
- executes the plan transactionally;
- is a no-op when the schema is current.

SQLite cannot attach a foreign key to an already existing column with a metadata-only `ALTER TABLE`. The adapter includes the reference when a new table or new column is created, but converting a pre-existing unreferenced column requires a deliberate table rebuild outside the additive migrator.

Required fields added to a populated table may also need a staged nullable-field, backfill, and constraint migration.

## Offline SQL plan

Generate deterministic SQL without modifying the database:

```go
plan, err := sqlitestore.PlanSchema(schema)
if err != nil {
    return err
}

sqlText := plan.SQL()
```

`adapter.CreateSchema(ctx, schema, path)` returns the same SQL through `storage.SchemaCreation`. It returns `Append: true` and echoes `path`; it does not write a file.

## Transactions

SQLite transactions use `database/sql`. The write gate remains held for the whole callback, so writes outside the transaction cannot interleave with it:

```go
err := adapter.Transaction(ctx, func(tx storage.TransactionAdapter) error {
    _, err := tx.Create(ctx, storage.CreateParams{
        Model: "user",
        Data: storage.Record{
            "name":  "Ada",
            "email": "ada@example.com",
        },
    })
    return err
})
```

A callback error, context cancellation before commit, or commit failure rolls the transaction back.
