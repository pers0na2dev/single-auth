---
title: "github.com/pers0na2dev/single-auth/storage/sqlite"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/sqlite.

- Import path: `github.com/pers0na2dev/single-auth/storage/sqlite`
- Package name: `sqlite`

Package sqlite implements the single-auth storage contract on top of an
already opened SQLite database/sql handle. The package deliberately does not
import a concrete SQL driver. The caller must configure connection-wide
SQLite settings such as foreign_keys and busy_timeout through its driver;
RETURNING and JSON functions must be available in the selected SQLite build.

## Types

### `Adapter`

Adapter is a driver-independent SQLite adapter over an already opened DB.
The caller owns the DB and remains responsible for closing it.

```go
type Adapter struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Adapter`

### `New`

New validates options and binds an already opened SQLite database. It does
not mutate the database; call EnsureSchema explicitly when schema creation is
desired.

```go
func New(db *sql.DB, options Options) (*Adapter, error)
```

## Methods on `Adapter`

### `Capabilities`

```go
func (a *Adapter) Capabilities() storage.Capabilities
```

### `ConsumeOne`

```go
func (a *Adapter) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error)
```

### `Count`

```go
func (e Adapter) Count(ctx context.Context, params storage.CountParams) (int64, error)
```

### `Create`

```go
func (a *Adapter) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error)
```

### `CreateSchema`

CreateSchema implements storage.SchemaCreator and returns migration SQL
without modifying the caller's database.

```go
func (a *Adapter) CreateSchema(ctx context.Context, schema storage.Schema, path string) (storage.SchemaCreation, error)
```

### `Delete`

```go
func (a *Adapter) Delete(ctx context.Context, params storage.DeleteParams) error
```

### `DeleteMany`

```go
func (a *Adapter) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error)
```

### `EnsureSchema`

EnsureSchema creates missing tables and reconciles additive fields using one
transactional native SQLite plan.

```go
func (a *Adapter) EnsureSchema(ctx context.Context) error
```

### `FindMany`

```go
func (e Adapter) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error)
```

### `FindOne`

```go
func (e Adapter) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error)
```

### `ID`

```go
func (a *Adapter) ID() string
```

### `IncrementOne`

```go
func (a *Adapter) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error)
```

### `Schema`

Schema returns an isolated copy of the configured schema.

```go
func (a *Adapter) Schema() storage.Schema
```

### `Transaction`

Transaction executes callback in a real database/sql transaction. A
callback error or context cancellation is rolled back; successful callbacks
are committed before Transaction returns.

```go
func (a *Adapter) Transaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error
```

### `Update`

```go
func (a *Adapter) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error)
```

### `UpdateMany`

```go
func (a *Adapter) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error)
```

### `IDGenerator`

IDGenerator creates a canonical identifier for a model.

```go
type IDGenerator func(model string) (any, error)
```

### `Options`

Options configure an Adapter. A zero Schema selects storage.CoreSchema and
a zero DefaultFindManyLimit selects reference implementation's default of 100.

```go
type Options struct {
	Schema               storage.Schema
	IDGenerator          IDGenerator
	Clock                func() time.Time
	DefaultFindManyLimit int
}
```

### `SchemaPlan`

SchemaPlan is deterministic SQLite DDL for a storage schema.

```go
type SchemaPlan struct {
	Statements []string
}
```

## Constructors and functions for `SchemaPlan`

### `PlanSchema`

PlanSchema validates schema and returns deterministic create-table/index
statements. Every statement is idempotent for a fresh or already-created
schema with the same columns.

```go
func PlanSchema(schema storage.Schema) (SchemaPlan, error)
```

## Methods on `SchemaPlan`

### `SQL`

SQL renders the plan as executable semicolon-terminated statements.

```go
func (plan SchemaPlan) SQL() string
```

