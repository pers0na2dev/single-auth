---
title: "Transactions"
---

Require rollback semantics, reuse nested transaction contexts, and understand backend-specific behavior.

Every primary adapter exposes a transaction method:

```go
Transaction(
    context.Context,
    func(storage.TransactionAdapter) error,
) error
```

`storage.TransactionAdapter` exposes all storage operations except another `Transaction` method. Use the callback adapter for every operation that must participate in the transaction.

## Strict transaction

Check capabilities before making rollback a correctness requirement:

```go
package accountservice

import (
    "context"
    "fmt"

    "github.com/pers0na2dev/single-auth/storage"
)

func CreateCredentialAccount(
    ctx context.Context,
    adapter storage.Adapter,
    name string,
    email string,
    passwordHash string,
) error {
    if !adapter.Capabilities().Transactions {
        return fmt.Errorf("%w: account creation requires rollback", storage.ErrTransactionsUnsupported)
    }

    return adapter.Transaction(ctx, func(tx storage.TransactionAdapter) error {
        user, err := tx.Create(ctx, storage.CreateParams{
            Model: "user",
            Data: storage.Record{
                "name":  name,
                "email": email,
            },
        })
        if err != nil {
            return err
        }

        _, err = tx.Create(ctx, storage.CreateParams{
            Model: "account",
            Data: storage.Record{
                "accountId":  email,
                "providerId": "credential",
                "userId":     user["id"],
                "password":   passwordHash,
            },
        })
        return err
    })
}
```

If account creation fails, neither record is committed by adapters that report transaction support.

## Callback rules

- Use the supplied `tx`, not the outer adapter.
- Return the first error that should abort the unit of work.
- Do not start unbounded background work inside the callback.
- Keep external network calls outside the transaction where possible.
- Propagate the same context to transaction operations.
- Treat commit errors as operation failures even when the callback returned nil.

For SQL adapters, a callback error or context cancellation before commit triggers rollback. A successful commit completes before `Transaction` returns.

## Nested-aware helper

`storage.RunWithTransaction` binds the active transaction adapter to a derived context:

```go
err := storage.RunWithTransaction(
    ctx,
    adapter,
    func(txCtx context.Context, tx storage.TransactionAdapter) error {
        _, err := tx.Create(txCtx, storage.CreateParams{
            Model: "verification",
            Data: storage.Record{
                "identifier": "email-change:user-1",
                "value":      "signed-value",
                "expiresAt":  time.Now().UTC().Add(time.Hour),
            },
        })
        if err != nil {
            return err
        }

        return storage.RunWithTransaction(
            txCtx,
            adapter,
            func(nestedCtx context.Context, nested storage.TransactionAdapter) error {
                _, err := nested.Update(nestedCtx, storage.UpdateParams{
                    Model: "user",
                    Where: []storage.Where{{Field: "id", Value: "user-1"}},
                    Update: storage.Record{
                        "email": "new@example.com",
                    },
                })
                return err
            },
        )
    },
)
```

The nested call reuses the active transaction. It does not create a savepoint and cannot independently commit or roll back.

`storage.CurrentTransactionAdapter(ctx, fallback)` returns the adapter bound by `RunWithTransaction`, or `fallback` outside that context.

## Important fallback behavior

`RunWithTransaction` is a compatibility helper. If an adapter returns `storage.ErrTransactionsUnsupported`, the helper invokes the callback with the ordinary adapter instead of failing.

Do not use that behavior for operations that require rollback. For strict atomicity:

1. require `adapter.Capabilities().Transactions`;
2. call `adapter.Transaction` directly;
3. fail closed when the capability is absent.

Custom adapters built without a real transaction callback can also execute their callback non-transactionally while reporting `Transactions: false`. The capability check remains mandatory.

## Memory transactions

The memory adapter:

1. copies a base snapshot and a working snapshot;
2. runs the callback against the working copy;
3. discards it on callback error or cancellation;
4. merges only the transaction's changes into current live state;
5. retains unrelated concurrent writes;
6. validates unique constraints again before commit.

A concurrent unique conflict can make commit fail. This is useful rollback behavior for tests, but it is not a named SQL isolation level and is not durable.

## SQLite transactions

SQLite uses `database/sql.BeginTx` and holds the adapter's write gate for the complete callback. Other adapter mutations cannot interleave with it. Reads use the database connection according to the selected driver's behavior.

## PostgreSQL transactions

PostgreSQL uses a normal `database/sql` transaction. Atomic consume and increment operations use guarded statements. Isolation defaults come from the driver/database because the public adapter currently calls `BeginTx(ctx, nil)`.

## MySQL transactions

MySQL uses `database/sql.BeginTx`. Operations that need a returned row can use `SELECT ... FOR UPDATE` inside a real transaction because MySQL has no portable DML `RETURNING` syntax.

Ordinary DML rollback is supported. MySQL's non-atomic DDL behavior is a separate migration concern.

## SQL Server transactions

SQL Server uses `database/sql.BeginTx`. Returning mutations use `OUTPUT`. Enabled DML triggers on managed target tables can make those statements invalid; see [SQL Server](/docs/storage/sql-server).

## MongoDB transactions

MongoDB uses a driver session transaction and binds its session to every operation context supplied to the callback.

Transactions require a replica set or supported sharded deployment. On standalone MongoDB, construct the adapter with:

```go
mongostore.Options{
    Schema:              schema,
    DisableTransactions: true,
}
```

The adapter then reports `Transactions: false`, and direct `Transaction` returns an error matching `storage.ErrTransactionsUnsupported`.

## Atomic methods outside an explicit transaction

Native adapters provide two single-record atomic methods:

- `ConsumeOne` selects and removes one matching record so only one concurrent caller wins.
- `IncrementOne` evaluates guards, increments numeric fields, and applies `Set` values in one protected mutation.

Prefer these methods over manually combining `FindOne` with `Delete` or `Update`. A multi-call sequence is racy unless it runs in a strict transaction with backend-appropriate locking.

## Context cancellation

Transactions check context before beginning and before commit. Drivers also receive the context for queries. If the callback returns nil after the outer context has been cancelled, native adapters reject commit and roll back where the backend supports it.

Never replace a request context with `context.Background()` inside a transaction unless the work is intentionally detached and independently bounded.
