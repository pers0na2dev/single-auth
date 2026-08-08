---
title: "github.com/pers0na2dev/single-auth/storage/migration"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/migration.

- Import path: `github.com/pers0na2dev/single-auth/storage/migration`
- Package name: `migration`

Package migration plans and executes reference implementation-compatible relational
schema migrations against an introspected database catalog.

## Functions

### `MatchType`

```go
func MatchType(columnDataType string, fieldType storage.FieldType, dialect Dialect) bool
```

## Types

### `Catalog`

```go
type Catalog struct {
	Database string
	Schema   string
	Tables   []Table
}
```

## Constructors and functions for `Catalog`

### `Inspect`

```go
func Inspect(ctx context.Context, database *sql.DB, dialect Dialect) (Catalog, error)
```

### `InspectPostgresSchema`

InspectPostgresSchema inspects one explicit PostgreSQL schema in the current
database. It is used by adapters configured for a namespace that is not the
connection's current search_path.

```go
func InspectPostgresSchema(ctx context.Context, database *sql.DB, schema string) (Catalog, error)
```

### `Column`

```go
type Column struct {
	Name     string
	DataType string
}
```

### `Dialect`

```go
type Dialect string
```

## Constants associated with `Dialect`

```go
const (
	SQLite   Dialect = "sqlite"
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
	MSSQL    Dialect = "mssql"
)
```

### `IDMode`

```go
type IDMode string
```

## Constants associated with `IDMode`

```go
const (
	TextID   IDMode = "text"
	UUIDID   IDMode = "uuid"
	SerialID IDMode = "serial"
)
```

### `Options`

```go
type Options struct {
	Dialect Dialect
	IDMode  IDMode
}
```

### `Plan`

```go
type Plan struct {
	ToBeCreated []TableChange
	ToBeAdded   []TableChange
	Statements  []string
}
```

## Constructors and functions for `Plan`

### `Build`

```go
func Build(schema storage.Schema, catalog Catalog, options Options) (Plan, error)
```

### `BuildFromDatabase`

```go
func BuildFromDatabase(ctx context.Context, database *sql.DB, schema storage.Schema, options Options) (Plan, error)
```

## Methods on `Plan`

### `Run`

Run executes statements in order inside one database transaction. SQLite,
PostgreSQL, and SQL Server provide atomic rollback for the supported DDL.
MySQL can retain successfully executed statements after an error; callers
must re-inspect and build a fresh plan before retrying rather than reusing the
failed Plan. See RollbackPolicyForDialect.

```go
func (plan Plan) Run(ctx context.Context, database *sql.DB) error
```

### `SQL`

```go
func (plan Plan) SQL() string
```

### `RollbackPolicy`

RollbackPolicy describes what remains in the database when Plan.Run fails
after at least one DDL statement has executed.

```go
type RollbackPolicy string
```

## Constants associated with `RollbackPolicy`

```go
const (
	RollbackAtomic RollbackPolicy = "atomic"

	RollbackMayPartiallyApply RollbackPolicy = "may-partially-apply"
)
```

## Constructors and functions for `RollbackPolicy`

### `RollbackPolicyForDialect`

RollbackPolicyForDialect returns the failure policy used by Plan.Run for a
supported dialect. Plan.Run still opens a transaction for every backend,
but MySQL cannot provide transactional DDL semantics.

```go
func RollbackPolicyForDialect(dialect Dialect) (RollbackPolicy, error)
```

### `Table`

```go
type Table struct {
	Database string
	Schema   string
	Name     string
	Columns  []Column
}
```

### `TableChange`

```go
type TableChange struct {
	Table  string
	Fields map[string]storage.FieldAttribute
	Order  int
}
```

