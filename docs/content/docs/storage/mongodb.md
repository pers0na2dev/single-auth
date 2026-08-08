---
title: "MongoDB"
---

Configure MongoDB ObjectID, UUID, and text IDs with replica-set transactions and index setup.

The MongoDB adapter uses the official MongoDB Go driver and binds an existing `*mongo.Database`. Your application owns and closes the client.

## Complete setup

```go
package authsetup

import (
    "context"
    "fmt"
    "time"

    "go.mongodb.org/mongo-driver/v2/mongo"
    mongooptions "go.mongodb.org/mongo-driver/v2/mongo/options"

    singleauth "github.com/pers0na2dev/single-auth"
    "github.com/pers0na2dev/single-auth/storage"
    mongostore "github.com/pers0na2dev/single-auth/storage/mongodb"
)

func OpenMongoDB(
    ctx context.Context,
    uri string,
    databaseName string,
    secret string,
) (*singleauth.Auth, *mongo.Client, error) {
    if len(secret) < 32 {
        return nil, nil, fmt.Errorf("authentication secret must contain at least 32 characters")
    }

    client, err := mongo.Connect(
        mongooptions.Client().
            ApplyURI(uri).
            SetServerSelectionTimeout(15 * time.Second),
    )
    if err != nil {
        return nil, nil, err
    }
    if err := client.Ping(ctx, nil); err != nil {
        client.Disconnect(ctx)
        return nil, nil, err
    }

    schema := storage.CoreSchema()
    adapter, err := mongostore.New(
        client.Database(databaseName),
        mongostore.Options{
            Schema: schema,
            IDType: mongostore.ObjectID,
        },
    )
    if err != nil {
        client.Disconnect(ctx)
        return nil, nil, err
    }

    auth, err := singleauth.New(singleauth.Options{
        BaseURL:  "https://example.com",
        Secret:   secret,
        Database: adapter,
    })
    if err != nil {
        client.Disconnect(ctx)
        return nil, nil, err
    }

    if err := auth.RunMigrationsContext(ctx); err != nil {
        client.Disconnect(ctx)
        return nil, nil, err
    }

    return auth, client, nil
}
```

Shutdown with:

```go
if err := client.Disconnect(ctx); err != nil {
    return err
}
```

Use the [fully merged schema](/docs/storage/schemas) instead of `storage.CoreSchema()` when plugins or custom fields are enabled.

## Constructor and options

```go
adapter, err := mongostore.New(database, mongostore.Options{
    Schema:               schema,
    IDType:               mongostore.TextID,
    Clock:                time.Now,
    DefaultFindManyLimit: 250,
    DisableTransactions:  false,
})
```

Options:

- `Schema`: zero selects `storage.CoreSchema()`.
- `IDGenerator`: optional application-side generator.
- `IDType`: BSON representation for IDs and ID references.
- `Clock`: defaults to `time.Now`.
- `DefaultFindManyLimit`: zero selects 100; negative values are rejected.
- `DisableTransactions`: disables session transactions for standalone deployments.

A nil database is rejected. Construction validates configuration but does not contact or modify MongoDB.

## ID types

| Value | BSON representation | Default generation |
| --- | --- | --- |
| `mongostore.ObjectID` | BSON ObjectID | `bson.NewObjectID()` |
| `mongostore.UUIDID` | BSON binary subtype 4 | Random RFC 4122 UUID |
| `mongostore.TextID` | BSON string | Random text, or custom `IDGenerator` |

When `IDType` is omitted:

- no custom generator selects `ObjectID`;
- a custom generator selects `TextID`.

Public IDs and ID references are decoded to strings. ObjectIDs use their hexadecimal form and BSON UUIDs use canonical UUID text.

## Names and schema metadata

MongoDB keeps native BSON scalar values. `FieldAttribute.Reference` provides ID encoding and join metadata, but MongoDB does not enforce foreign keys or `ON DELETE` actions. Application flows that require cascades must delete dependent documents explicitly.

Collection names:

- must not be empty;
- must not contain NUL or `$`;
- must not start with `system.`;
- must not exceed 120 bytes.

Physical field names:

- must not contain NUL or `.`;
- must not start with `$`;
- cannot be `id` or `_id`, because `_id` is the adapter-owned physical primary key.

## Collection and index setup

```go
if err := adapter.EnsureSchema(ctx); err != nil {
    return err
}
```

`EnsureSchema`:

- creates missing collections;
- creates configured unique and non-unique single-field indexes;
- is safe to repeat;
- runs outside a transaction because collection creation is not allowed in several transaction topologies.

It does not validate or rewrite existing document shapes, remove fields, rename collections, or backfill data.

Inspect the deterministic plan without changing the database:

```go
plan, err := mongostore.PlanSchema(schema)
if err != nil {
    return err
}

jsonPlan := plan.JSON()
```

The package can also return an optional mongosh artifact through `plan.JavaScript()` or `adapter.CreateSchema`. These are generated text artifacts only. Normal setup through `EnsureSchema` is entirely Go and does not require a JavaScript runtime.

## Transactions

MongoDB multi-document transactions require a replica set or a supported sharded deployment.

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

The adapter binds the driver session to every operation context passed to the callback; callers do not need a driver-specific session context.

For a standalone MongoDB instance:

```go
adapter, err := mongostore.New(database, mongostore.Options{
    Schema:              schema,
    DisableTransactions: true,
})
```

`Capabilities().Transactions` is then false, and direct `Transaction` returns an error matching `storage.ErrTransactionsUnsupported`.
