---
title: "github.com/pers0na2dev/single-auth/storage/memory"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/memory.

- Import path: `github.com/pers0na2dev/single-auth/storage/memory`
- Package name: `memory`

Package memory provides the concurrent in-memory single-auth adapter.

## Types

### `Adapter`

Adapter is a concurrent in-memory implementation of the complete storage
contract. Inputs and outputs are deep copied, so callers cannot race with or
mutate stored state through retained maps and slices.

```go
type Adapter struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Adapter`

### `MustNew`

MustNew is New for static configurations and tests.

```go
func MustNew(options ...Option) *Adapter
```

### `New`

New constructs an adapter with the five reference implementation core models.

```go
func New(options ...Option) (*Adapter, error)
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

### `Delete`

```go
func (e Adapter) Delete(ctx context.Context, params storage.DeleteParams) error
```

### `DeleteMany`

```go
func (e Adapter) DeleteMany(ctx context.Context, params storage.DeleteManyParams) (int64, error)
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

Transaction runs against an isolated copy. A successful callback merges only
its base-to-working delta into the live state, preserving unrelated writes
that completed concurrently. A failed or cancelled callback discards it.

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

### `Database`

Database is the caller-owned, adapter-native backing store used by
reference implementation's memory adapter. The adapter serializes access internally, but
callers must not read or mutate the map concurrently with adapter operations.

```go
type Database map[string][]storage.Record
```

### `IDGenerator`

```go
type IDGenerator func(model string) (any, error)
```

### `Option`

```go
type Option func(*config) error
```

## Constructors and functions for `Option`

### `WithClock`

WithClock injects the clock used by schema defaults and on-update values.

```go
func WithClock(clock func() time.Time) Option
```

### `WithDatabase`

WithDatabase uses database as the adapter's backing object instead of
allocating a private map. Mutations and successful transaction commits keep
the map identity intact, matching @single-auth/memory-adapter's MemoryDB
contract. Records already present in the map must use adapter-native physical
model and field names.

```go
func WithDatabase(database Database) Option
```

### `WithDefaultFindManyLimit`

WithDefaultFindManyLimit changes reference implementation's default limit of 100.

```go
func WithDefaultFindManyLimit(limit int) Option
```

### `WithIDGenerator`

WithIDGenerator injects deterministic, serial, or backend-shaped IDs.

```go
func WithIDGenerator(generator IDGenerator) Option
```

### `WithInitialData`

WithInitialData seeds canonical records at construction time. Input is deep
copied and then passed through the same transforms as Create.

```go
func WithInitialData(data map[string][]storage.Record) Option
```

### `WithScalarCapabilities`

WithScalarCapabilities exercises adapter-factory conversions while retaining
memory's native transaction, join, and atomic-operation guarantees.

```go
func WithScalarCapabilities(capabilities storage.Capabilities) Option
```

### `WithSchema`

WithSchema replaces the default core schema. Compose plugin fields with
storage.Schema.Merge before passing the result.

```go
func WithSchema(schema storage.Schema) Option
```

