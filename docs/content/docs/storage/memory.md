---
title: "Memory"
---

Configure the concurrent in-memory primary adapter for tests and ephemeral processes.

The memory adapter implements the complete primary storage contract without an external service. It is concurrent, copies inputs and outputs, supports joins, atomic consume and increment operations, and provides rollback-capable transactions.

Its contents disappear when the process exits. Do not use it as durable production storage.

## Automatic memory adapter

Omit `Options.Database` and single-auth creates the adapter after composing core, additional, rate-limit, and plugin schemas:

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

    log.Printf("adapter=%s", auth.Adapter().ID())
}
```

This is the recommended memory setup when plugins are enabled because the final plugin schema is applied automatically.

## Explicit adapter

Use an explicit adapter when you need deterministic data, IDs, or time:

```go
package authsetup

import (
    "fmt"
    "sync/atomic"
    "time"

    "github.com/pers0na2dev/single-auth/storage"
    "github.com/pers0na2dev/single-auth/storage/memory"
)

func NewMemoryAdapter() (*memory.Adapter, error) {
    var sequence atomic.Uint64
    fixedTime := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

    return memory.New(
        memory.WithSchema(storage.CoreSchema()),
        memory.WithClock(func() time.Time { return fixedTime }),
        memory.WithIDGenerator(func(model string) (any, error) {
            return fmt.Sprintf("%s-%d", model, sequence.Add(1)), nil
        }),
        memory.WithDefaultFindManyLimit(250),
    )
}
```

Pass the result through `singleauth.Options.Database`. When plugins or custom fields are present, construct it with the [fully merged schema](/docs/storage/schemas).

## Options

### `WithSchema`

Replaces the default `storage.CoreSchema()`:

```go
adapter, err := memory.New(memory.WithSchema(schema))
```

The schema is cloned during construction.

### `WithInitialData`

Seeds canonical records through the same transforms and validation used by `Create`:

```go
adapter, err := memory.New(
    memory.WithInitialData(map[string][]storage.Record{
        "user": {
            {
                "id":            "user-1",
                "name":          "Ada",
                "email":         "ada@example.com",
                "emailVerified": true,
            },
        },
    }),
)
```

Initial records are deep-copied. Their explicit IDs are preserved.

### `WithDatabase`

Uses a caller-owned `memory.Database` as the backing object:

```go
database := memory.Database{
    "user": {},
}

adapter, err := memory.New(memory.WithDatabase(database))
```

Existing keys and records must use adapter-native physical model and field names. Successful mutations and transaction commits retain the map identity, so the caller can inspect the same object after operations.

The adapter synchronizes its own operations, but the caller must not read or mutate the map concurrently with adapter calls. Use adapter methods for concurrent access.

### `WithIDGenerator`

Overrides the default random 32-character hexadecimal identifier:

```go
memory.WithIDGenerator(func(model string) (any, error) {
    return "fixed-" + model, nil
})
```

Public IDs are returned as strings even if the generator returns another scalar.

### `WithClock`

Controls schema defaults and `OnUpdate` values:

```go
memory.WithClock(func() time.Time {
    return time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
})
```

### `WithDefaultFindManyLimit`

Changes the default limit of 100. Unlike struct-based adapter options, an explicit zero here is accepted and makes an omitted `FindMany` limit return no records.

### `WithScalarCapabilities`

Overrides scalar representation flags while retaining memory transactions, joins, atomic consume, and atomic increment. This is primarily useful when testing a custom adapter's conversion model.

## Copy isolation

Records, nested maps, and slices are copied on input and output:

```go
created, err := adapter.Create(ctx, storage.CreateParams{
    Model: "user",
    Data: storage.Record{
        "name":  "Ada",
        "email": "ada@example.com",
        "metadata": map[string]any{
            "roles": []any{"admin"},
        },
    },
})
if err != nil {
    return err
}

created["name"] = "changed locally"
```

The stored row remains unchanged.

## Transactions

The adapter starts from an isolated snapshot. A callback error or context cancellation discards the snapshot. A successful callback merges only its base-to-working delta into current live data, preserving unrelated writes that completed concurrently.

Unique constraints are checked again at commit. A conflicting concurrent write can therefore make commit fail with `storage.ErrUniqueConstraint`.

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

This provides rollback behavior for application logic, but it is not a substitute for the isolation guarantees of a durable database.

## Migrations

Memory storage does not implement `storage.SchemaEnsurer` or `storage.SchemaCreator`. It materializes the configured tables immediately, so migrations are neither required nor supported.
