---
title: "Migrations"
---

Inspect databases, build deterministic additive plans, run native schema setup, and understand rollback behavior.

single-auth migration APIs are explicit and additive. Constructing `Auth` or an adapter never changes the database automatically.

The normal deployment workflow is:

1. compose the final core, additional, rate-limit, and plugin schema;
2. construct the native adapter with that schema;
3. initialize single-auth;
4. call `RunMigrationsContext` during a controlled startup or deployment stage;
5. begin serving traffic only after migration succeeds.

## Run migrations through Auth

```go
auth, err := singleauth.New(options)
if err != nil {
    return err
}

if err := auth.RunMigrationsContext(ctx); err != nil {
    return err
}
```

The background-context convenience method is:

```go
if err := auth.RunMigrations(); err != nil {
    return err
}
```

Prefer `RunMigrationsContext` in services so shutdown and deployment deadlines can cancel database work.

`Auth.Context()` exposes the same migration callback and database metadata:

```go
snapshot, err := auth.Context()
if err != nil {
    return err
}

if err := snapshot.RunMigrationsContext(ctx); err != nil {
    return err
}
```

If the configured adapter does not provide native schema setup, the call returns an error matching `singleauth.ErrFullMigrationsRequireDatabase`.

The default memory adapter needs no migration and does not implement migration interfaces.

## Run a native adapter directly

Every native durable adapter implements `storage.SchemaEnsurer`:

```go
type SchemaEnsurer interface {
    EnsureSchema(context.Context) error
}
```

```go
if err := adapter.EnsureSchema(ctx); err != nil {
    return err
}
```

Running the concrete adapter directly is useful before `singleauth.New`, or when database migrations are a separate command in your deployment.

Keep the concrete adapter variable when you need adapter-specific planning methods. `Auth.Adapter()` returns the runtime's storage wrapper and should be treated as the operational `storage.Adapter`, not as a way to recover a concrete PostgreSQL or MySQL type.

## What EnsureSchema changes

Relational native adapters inspect the current database and can:

- create missing tables;
- add missing data columns;
- add internal presence columns;
- create missing unique and non-unique indexes;
- create missing foreign keys;
- return successfully without executing DDL when no changes are needed.

MongoDB can:

- create missing collections;
- create configured indexes;
- return successfully when those objects already exist.

## What migrations never do

The built-in migration flow does not:

- drop a table, collection, column, or index;
- rename a table, collection, or field;
- change an existing physical type;
- rewrite an existing foreign-key action;
- remove unknown objects;
- backfill application values;
- infer data conversions for a changed schema.

Plan destructive or semantic changes separately with backups, review, and an application-specific rollout.

## Required fields on populated tables

Adding a required field without a database-usable default can fail when the table already contains rows. Use a staged migration:

1. add the field as optional;
2. deploy code capable of handling both states;
3. backfill existing rows;
4. add the required constraint through a reviewed database migration;
5. update the single-auth schema.

`DefaultValue` is an adapter-side value factory for new records. It does not automatically produce a SQL default suitable for backfilling every existing row.

## Rollback behavior

```go
policy, err := migration.RollbackPolicyForDialect(migration.Postgres)
```

| Dialect | Policy | Behavior on DDL failure |
| --- | --- | --- |
| SQLite | `RollbackAtomic` | Transaction rolls back supported DDL |
| PostgreSQL | `RollbackAtomic` | Transaction rolls back supported DDL |
| SQL Server | `RollbackAtomic` | Transaction rolls back supported DDL |
| MySQL | `RollbackMayPartiallyApply` | Earlier DDL may remain because of implicit commits |

MySQL retries must inspect the database again. Native `EnsureSchema` does that automatically. Never assume rolling back the Go `sql.Tx` reverted earlier MySQL DDL.

MongoDB collection/index setup runs outside a transaction because collection creation is disallowed in several transaction topologies.

## SQLite foreign-key limitation

SQLite cannot add a foreign key to an already existing column with a metadata-only `ALTER TABLE`. Native setup creates references inline for new tables and new columns. Adding a reference to an old column requires a deliberate table rebuild.

## Generic relational planner

Package `github.com/pers0na2dev/single-auth/storage/migration` provides a database-neutral catalog and plan API for SQLite, PostgreSQL, MySQL, and SQL Server.

### Inspect

```go
catalog, err := migration.Inspect(
    ctx,
    database,
    migration.Postgres,
)
```

Supported dialect constants:

```text
migration.SQLite
migration.Postgres
migration.MySQL
migration.MSSQL
```

`Inspect` uses the current database and current schema/namespace exposed by the connection.

For a PostgreSQL namespace that is not the current `search_path` schema:

```go
catalog, err := migration.InspectPostgresSchema(
    ctx,
    database,
    "identity",
)
```

### Build from an existing catalog

```go
plan, err := migration.Build(
    schema,
    catalog,
    migration.Options{
        Dialect: migration.Postgres,
        IDMode:  migration.UUIDID,
    },
)
```

ID modes:

```text
migration.TextID
migration.UUIDID
migration.SerialID
```

The zero ID mode selects text IDs. Keep the migration ID mode aligned with the concrete adapter ID type.

### Inspect and build in one call

```go
plan, err := migration.BuildFromDatabase(
    ctx,
    database,
    schema,
    migration.Options{
        Dialect: migration.MySQL,
        IDMode:  migration.TextID,
    },
)
```

### Review a plan

```go
fmt.Print(plan.SQL())

for _, table := range plan.ToBeCreated {
    fmt.Printf("create table %s\n", table.Table)
}
for _, table := range plan.ToBeAdded {
    fmt.Printf("add fields to %s\n", table.Table)
}
```

`Plan` exposes:

```go
type Plan struct {
    ToBeCreated []TableChange
    ToBeAdded   []TableChange
    Statements  []string
}
```

### Execute a plan

```go
if err := plan.Run(ctx, database); err != nil {
    return err
}
```

`Run` executes statements in order through one `database/sql` transaction. The MySQL partial-application warning still applies.

Native adapter `EnsureSchema` is preferred for normal runtime setup because it also performs backend-specific index and foreign-key inspection and repair.

## Backend-specific deterministic planners

These functions validate a schema and return a stable plan without touching a database:

### SQLite

```go
plan, err := sqlitestore.PlanSchema(schema)
sqlText := plan.SQL()
```

SQLite IDs are text.

### PostgreSQL

```go
plan, err := postgresstore.PlanSchemaWithDatabaseSchema(
    schema,
    postgresstore.UUIDID,
    "identity",
)
sqlText := plan.SQL()
```

Also available:

- `postgresstore.PlanSchema`
- `postgresstore.PlanSchemaWithIDType`

The PostgreSQL namespace must already exist.

### MySQL

```go
plan, err := mysqlstore.PlanSchemaWithIDType(
    schema,
    mysqlstore.SerialID,
)
sqlText := plan.SQL()
```

`mysqlstore.PlanSchema` selects text IDs.

### SQL Server

```go
plan, err := mssqlstore.PlanSchemaWithIDType(
    schema,
    mssqlstore.SerialID,
)
sqlText := plan.SQL()
```

`mssqlstore.PlanSchema` selects text IDs.

### MongoDB

```go
plan, err := mongostore.PlanSchema(schema)
jsonText := plan.JSON()
```

The JSON plan describes collections and indexes. Normal execution remains the Go `EnsureSchema` method.

## SchemaCreator

Durable native adapters also implement:

```go
type SchemaCreator interface {
    CreateSchema(
        context.Context,
        storage.Schema,
        string,
    ) (storage.SchemaCreation, error)
}
```

```go
creation, err := adapter.CreateSchema(
    ctx,
    schema,
    "migrations/001_auth.sql",
)
if err != nil {
    return err
}

fmt.Print(creation.Code)
```

`SchemaCreation` contains:

```go
type SchemaCreation struct {
    Code      string
    Path      string
    Append    bool
    Overwrite bool
}
```

The adapter does not write `Path`. It returns code and metadata so your migration tooling can decide how to persist it. Native adapters currently return append-oriented artifacts.

MongoDB's offline creator can return a mongosh text artifact. This does not add a runtime dependency: `EnsureSchema`, all production storage operations, and all ordinary tests remain native Go.

## Deployment guidance

- Run migrations from one controlled process or job, even when statements are idempotent.
- Use a context deadline appropriate for metadata locks and large catalogs.
- Review generated SQL before production use.
- Back up data before application-specific destructive migrations.
- Keep adapter ID type, schema aliases, and migration ID mode synchronized.
- Re-run native `EnsureSchema` after a partially applied MySQL migration.
- Do not serve requests if required migration work failed.
