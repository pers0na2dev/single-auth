---
title: "github.com/pers0na2dev/single-auth/storage/mysql"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/mysql.

- Import path: `github.com/pers0na2dev/single-auth/storage/mysql`
- Package name: `mysql`

Package mysql implements the single-auth storage contract on top of an
already opened database/sql handle for MySQL-compatible servers.

The package deliberately imports no concrete driver. The caller owns the
handle and its DSN. For stable date round trips, configure the selected
driver to parse TIMESTAMP values and use the same time zone on the client and
server (UTC is the least surprising choice). A text TIMESTAMP fallback is
supported for drivers that return []byte, but zone-less text is interpreted
as UTC.

MySQL has no portable INSERT, UPDATE, or DELETE RETURNING form. Operations
that must return a row therefore use a real transaction; guarded single-row
mutations claim their target with SELECT ... FOR UPDATE before mutating it.

Package mysql implements the single-auth storage contract on top of an
already opened MySQL database/sql handle. It deliberately imports no
concrete MySQL driver; the caller owns and closes the handle.

## Types

### `Adapter`

Adapter is a driver-independent MySQL adapter over an already opened
database/sql handle. The caller owns the handle.

```go
type Adapter struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Adapter`

### `New`

New validates options and binds db without mutating it. Call EnsureSchema
explicitly if this adapter should create missing tables and constraints.

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

CreateSchema returns deterministic migration SQL without modifying db.

```go
func (a *Adapter) CreateSchema(ctx context.Context, schema storage.Schema, path string) (storage.SchemaCreation, error)
```

### `Delete`

```go
func (e Adapter) Delete(ctx context.Context, params storage.DeleteParams) error
```

### `DeleteMany`

```go
func (e Adapter) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error)
```

### `EnsureSchema`

EnsureSchema creates missing tables and reconciles additive fields on one
pinned connection. MySQL DDL implicitly commits, so failure may leave an
additive prefix applied; a retry always re-inspects the database first.

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

Transaction executes callback in a database/sql transaction. Callback
failure or outer-context cancellation rolls back; success commits before
Transaction returns.

```go
func (a *Adapter) Transaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error
```

### `Update`

```go
func (a *Adapter) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error)
```

### `UpdateMany`

```go
func (e Adapter) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error)
```

### `IDGenerator`

IDGenerator creates a canonical identifier for a model.

```go
type IDGenerator func(model string) (any, error)
```

### `IDType`

IDType selects the physical MySQL primary-key representation.

```go
type IDType string
```

## Constants associated with `IDType`

```go
const (
	TextID IDType = "text"

	UUIDID IDType = "uuid"

	SerialID IDType = "serial"
)
```

### `Options`

Options configure an Adapter. A zero Schema selects storage.CoreSchema and
a zero DefaultFindManyLimit selects reference implementation's default of 100.

```go
type Options struct {
	Schema               storage.Schema
	IDGenerator          IDGenerator
	IDType               IDType
	Clock                func() time.Time
	DefaultFindManyLimit int
}
```

### `SchemaPlan`

SchemaPlan is deterministic MySQL DDL for a storage schema.

```go
type SchemaPlan struct{ Statements []string }
```

## Constructors and functions for `SchemaPlan`

### `PlanSchema`

PlanSchema validates schema and emits idempotent CREATE TABLE statements.
Indexes and foreign keys are inline so CREATE TABLE IF NOT EXISTS is itself
the idempotency boundary. Session-scoped FOREIGN_KEY_CHECKS permits cyclic
plugin schemas and out-of-order references.

```go
func PlanSchema(schema storage.Schema) (SchemaPlan, error)
```

### `PlanSchemaWithIDType`

PlanSchemaWithIDType plans a schema for text, UUID, or identity IDs.

```go
func PlanSchemaWithIDType(schema storage.Schema, idType IDType) (SchemaPlan, error)
```

## Methods on `SchemaPlan`

### `SQL`

SQL renders the plan as executable semicolon-terminated statements.

```go
func (plan SchemaPlan) SQL() string
```

