---
title: "github.com/pers0na2dev/single-auth/storage/secondary"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/storage/secondary.

- Import path: `github.com/pers0na2dev/single-auth/storage/secondary`
- Package name: `secondary`

Package secondary defines optional key-value storage contracts used for
sessions, verification values, and rate-limit counters.

## Types

### `GetAndDeleter`

GetAndDeleter provides cross-process atomic consumption for single-use
values.

```go
type GetAndDeleter interface {
	GetAndDelete(context.Context, string) (string, error)
}
```

### `Storage`

Storage is the string-valued secondary storage contract.

```go
type Storage interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string, int64) error
	Delete(context.Context, string) error
}
```

### `ValueGetAndDeleter`

ValueGetAndDeleter provides atomic consumption for object-valued stores.

```go
type ValueGetAndDeleter interface {
	GetAndDeleteValue(context.Context, string) (any, error)
}
```

### `ValueStorage`

ValueStorage is the object-valued form of Storage. Set receives canonical
JSON while GetValue may return an already-decoded value.

```go
type ValueStorage interface {
	GetValue(context.Context, string) (any, error)
	Set(context.Context, string, string, int64) error
	Delete(context.Context, string) error
}
```

