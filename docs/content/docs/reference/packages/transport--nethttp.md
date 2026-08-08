---
title: "github.com/pers0na2dev/single-auth/transport/nethttp"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/transport/nethttp.

- Import path: `github.com/pers0na2dev/single-auth/transport/nethttp`
- Package name: `nethttp`

Package nethttp adapts the transport-neutral authentication dispatcher to
the standard library's net/http server.

## Functions

### `CheckRateLimit`

CheckRateLimit adapts one net/http request to the transport-neutral limiter.

```go
func CheckRateLimit(
	ctx context.Context,
	limiter *ratelimit.Limiter,
	request *http.Request,
) (ratelimit.Result, error)
```

### `NewHandler`

NewHandler constructs a standard-library handler. It is a convenience
wrapper for New.

```go
func NewHandler(dispatcher *engine.Dispatcher, options ...Option) http.Handler
```

### `RateLimitMiddleware`

RateLimitMiddleware enforces limiter before invoking next. Storage and rule
resolution errors are delegated to onError; when it is nil they receive a
stable 500 response.

```go
func RateLimitMiddleware(
	limiter *ratelimit.Limiter,
	next http.Handler,
	onError func(http.ResponseWriter, *http.Request, error),
) http.Handler
```

### `WriteRateLimit`

WriteRateLimit writes the stable 429 response used by single-auth.

```go
func WriteRateLimit(writer http.ResponseWriter, retryAfter int64)
```

## Types

### `Adapter`

Adapter is an immutable net/http bridge around one dispatcher.

```go
type Adapter struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Adapter`

### `New`

New constructs an immutable adapter.

```go
func New(dispatcher *engine.Dispatcher, options ...Option) *Adapter
```

## Methods on `Adapter`

### `ServeHTTP`

ServeHTTP implements http.Handler.

```go
func (adapter *Adapter) ServeHTTP(writer http.ResponseWriter, request *http.Request)
```

### `ErrorHandler`

ErrorHandler observes dispatcher and response-write errors after their
stable wire response has been selected. It must be safe for concurrent use.

```go
type ErrorHandler func(context.Context, error)
```

### `Option`

Option configures an Adapter. Options are applied once by New, so the
resulting handler is immutable and safe for concurrent use.

```go
type Option func(*config)
```

## Constructors and functions for `Option`

### `WithErrorHandler`

WithErrorHandler installs a non-mutating error observer. The adapter always
writes the response returned by the dispatcher; the observer cannot replace
it.

```go
func WithErrorHandler(handler ErrorHandler) Option
```

### `WithMaxBodyBytes`

WithMaxBodyBytes rejects request bodies larger than limit with a stable 413
response. A non-positive limit leaves body size enforcement to net/http and
the hosting server.

```go
func WithMaxBodyBytes(limit int64) Option
```

