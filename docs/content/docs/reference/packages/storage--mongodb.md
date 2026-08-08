---
title: "github.com/pers0na2dev/single-auth/storage/mongodb"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/mongodb.

- Import path: `github.com/pers0na2dev/single-auth/storage/mongodb`
- Package name: `mongodb`

Package mongodb implements the single-auth storage contract on top of the
official MongoDB Go driver.

## Types

### `Adapter`

Adapter persists reference implementation records in an existing MongoDB database. The
caller owns the client and database handles.

```go
type Adapter struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Adapter`

### `New`

New validates options and binds database without mutating it. Call
EnsureSchema explicitly to create missing collections and indexes.

```go
func New(database *mongo.Database, options Options) (*Adapter, error)
```

## Methods on `Adapter`

### `Capabilities`

```go
func (adapter *Adapter) Capabilities() storage.Capabilities
```

### `ConsumeOne`

```go
func (executor Adapter) ConsumeOne(ctx context.Context, params storage.ConsumeOneParams) (storage.Record, error)
```

### `Count`

```go
func (executor Adapter) Count(ctx context.Context, params storage.CountParams) (int64, error)
```

### `Create`

```go
func (executor Adapter) Create(ctx context.Context, params storage.CreateParams) (storage.Record, error)
```

### `CreateSchema`

CreateSchema returns an idempotent mongosh artifact without modifying the
configured database.

```go
func (adapter *Adapter) CreateSchema(ctx context.Context, schema storage.Schema, path string) (storage.SchemaCreation, error)
```

### `Delete`

```go
func (executor Adapter) Delete(ctx context.Context, params storage.DeleteParams) error
```

### `DeleteMany`

```go
func (executor Adapter) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error)
```

### `EnsureSchema`

EnsureSchema creates missing collections and every configured index. It is
safe to call repeatedly and deliberately runs outside a transaction because
MongoDB disallows collection creation in several transaction topologies.

```go
func (adapter *Adapter) EnsureSchema(ctx context.Context) error
```

### `FindMany`

```go
func (executor Adapter) FindMany(ctx context.Context, params storage.FindManyParams) ([]storage.Record, error)
```

### `FindOne`

```go
func (executor Adapter) FindOne(ctx context.Context, params storage.FindOneParams) (storage.Record, error)
```

### `ID`

```go
func (adapter *Adapter) ID() string
```

### `IncrementOne`

```go
func (executor Adapter) IncrementOne(ctx context.Context, params storage.IncrementOneParams) (storage.Record, error)
```

### `Schema`

Schema returns an isolated copy of the configured schema.

```go
func (adapter *Adapter) Schema() storage.Schema
```

### `Transaction`

Transaction executes callback in a MongoDB session transaction. The
transaction adapter binds the session to every operation context so callers
do not need to manually propagate a driver-specific context.

```go
func (adapter *Adapter) Transaction(ctx context.Context, callback func(storage.TransactionAdapter) error) error
```

### `Update`

```go
func (executor Adapter) Update(ctx context.Context, params storage.UpdateParams) (storage.Record, error)
```

### `UpdateMany`

```go
func (executor Adapter) UpdateMany(ctx context.Context, params storage.UpdateManyParams) (int64, error)
```

### `CollectionPlan`

CollectionPlan describes one MongoDB collection and its secondary indexes.

```go
type CollectionPlan struct {
	Model   string      `json:"model"`
	Name    string      `json:"name"`
	Indexes []IndexPlan `json:"indexes,omitempty"`
}
```

### `IDGenerator`

IDGenerator creates a canonical identifier for a model.

```go
type IDGenerator func(model string) (any, error)
```

### `IDType`

IDType selects the BSON representation used by primary and foreign keys.

```go
type IDType string
```

## Constants associated with `IDType`

```go
const (
	ObjectID IDType = "object-id"

	UUIDID IDType = "uuid"

	TextID IDType = "text"
)
```

### `IndexPlan`

IndexPlan describes one ascending single-field index.

```go
type IndexPlan struct {
	Name   string `json:"name"`
	Field  string `json:"field"`
	Unique bool   `json:"unique,omitempty"`
}
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
	// DisableTransactions is useful for standalone MongoDB deployments, which
	// do not support multi-document transactions. Transaction then returns
	// storage.ErrTransactionsUnsupported and Capabilities reports false.
	DisableTransactions bool
}
```

### `SchemaPlan`

SchemaPlan is a deterministic collection and index creation plan.

```go
type SchemaPlan struct {
	Collections []CollectionPlan `json:"collections"`
}
```

## Constructors and functions for `SchemaPlan`

### `PlanSchema`

PlanSchema validates schema and returns collections and indexes in stable
order. MongoDB creates the unique _id index automatically.

```go
func PlanSchema(schema storage.Schema) (SchemaPlan, error)
```

## Methods on `SchemaPlan`

### `JSON`

JSON returns a stable human-readable representation useful for review and
golden tests.

```go
func (plan SchemaPlan) JSON() string
```

### `JavaScript`

JavaScript renders an idempotent mongosh migration artifact.

```go
func (plan SchemaPlan) JavaScript() string
```

