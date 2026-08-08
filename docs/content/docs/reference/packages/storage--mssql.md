---
title: "github.com/pers0na2dev/single-auth/storage/mssql"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/mssql.

- Import path: `github.com/pers0na2dev/single-auth/storage/mssql`
- Package name: `mssql`

Package mssql implements the single-auth storage contract on top of an
already opened SQL Server database/sql handle.

The package is driver-neutral: callers select and configure a SQL Server
driver, open the *sql.DB, and retain ownership of its lifetime. Generated
statements use SQL Server's @pN parameter syntax and require SQL Server 2016
or newer (database compatibility level 130 or newer) for OPENJSON queries.

reference implementation's MSSQL scalar contract stores JSON and arrays in VARCHAR,
booleans in SMALLINT, and dates in DATETIME2(3). Dates are encoded as UTC ISO
strings and zone-less DATETIME2 values returned by a driver are interpreted
as UTC.

Create, single-row update, ConsumeOne, and IncrementOne use OUTPUT to return
the affected row in one statement. SQL Server tables with enabled triggers
for those DML actions are not supported because SQL Server rejects OUTPUT
without OUTPUT INTO on such a target.

Package mssql implements the single-auth storage contract on top of an
already opened SQL Server database/sql handle. It deliberately imports no
concrete SQL Server driver; the caller owns and closes the handle.

## Types

### `Adapter`

Adapter is a driver-independent SQL Server adapter over an already opened
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
func (e Adapter) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error)
```

### `Count`

```go
func (e Adapter) Count(ctx context.Context, params storage.CountParams) (int64, error)
```

### `Create`

```go
func (e Adapter) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error)
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

EnsureSchema creates missing tables and reconciles additive fields using one
transactional native SQL Server plan.

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
func (e Adapter) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error)
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
func (e Adapter) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error)
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

IDType selects the physical SQL Server primary-key representation.

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

SchemaPlan is deterministic SQL Server DDL for a storage schema.

```go
type SchemaPlan struct{ Statements []string }
```

## Constructors and functions for `SchemaPlan`

### `PlanSchema`

PlanSchema validates schema and emits idempotent table blocks first, index
blocks second, and foreign-key blocks last. Deferring foreign keys permits
cyclic plugin schemas while ensuring every referenced table already exists.

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

