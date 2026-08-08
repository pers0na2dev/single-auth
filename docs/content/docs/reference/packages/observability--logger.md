---
title: "github.com/pers0na2dev/single-auth/observability/logger"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/observability/logger.

- Import path: `github.com/pers0na2dev/single-auth/observability/logger`
- Package name: `logger`

Package logger provides structured, leveled logging for single-auth.

## Functions

### `ShouldPublish`

ShouldPublish applies the configured threshold order.

```go
func ShouldPublish(current, candidate Level) bool
```

### `ValidLevel`

ValidLevel reports whether level is supported.

```go
func ValidLevel(level Level) bool
```

## Types

### `Handler`

Handler receives the unformatted message when a custom logger is supplied.
Success is reported as Info because the public callback does not expose a
separate success level.

```go
type Handler func(level Level, message string, args ...any)
```

### `Level`

Level is ordered from the most verbose to the most severe level.

```go
type Level string
```

## Constants associated with `Level`

```go
const (
	Debug   Level = "debug"
	Info    Level = "info"
	Success Level = "success"
	Warn    Level = "warn"
	Error   Level = "error"
)
```

### `Logger`

Logger is immutable and safe for concurrent use when its configured writer
or custom callback is safe for concurrent use.

```go
type Logger struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Logger`

### `MustNew`

MustNew creates a Logger or panics for invalid static configuration.

```go
func MustNew(options Options) *Logger
```

### `New`

New snapshots options and creates a logger.

```go
func New(options Options) (*Logger, error)
```

## Methods on `Logger`

### `Debug`

```go
func (logger *Logger) Debug(message string, args ...any)
```

### `Error`

```go
func (logger *Logger) Error(message string, args ...any)
```

### `Info`

```go
func (logger *Logger) Info(message string, args ...any)
```

### `Level`

Level returns the configured threshold.

```go
func (logger *Logger) Level() Level
```

### `Success`

```go
func (logger *Logger) Success(message string, args ...any)
```

### `Warn`

```go
func (logger *Logger) Warn(message string, args ...any)
```

### `Options`

Options configures a Logger. Level defaults to Warn. DisableColors is a
pointer so an omitted value can retain terminal auto-detection.

```go
type Options struct {
	Disabled      bool
	DisableColors *bool
	Level         Level
	Log           Handler

	// Output fields are useful for hosts and deterministic tests. Nil selects
	// stdout for debug/info/success and stderr for warn/error.
	Output      io.Writer
	ErrorOutput io.Writer
	Now         func() time.Time
}
```

