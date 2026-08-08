---
title: "github.com/pers0na2dev/single-auth/transport/fiber"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/transport/fiber.

- Import path: `github.com/pers0na2dev/single-auth/transport/fiber`
- Package name: `fiber`

Package fiber adapts the transport-neutral authentication dispatcher to
Fiber v3 without converting through net/http.

## Functions

### `CheckRateLimit`

CheckRateLimit adapts one Fiber request to the transport-neutral limiter.

```go
func CheckRateLimit(
	requestContext context.Context,
	limiter *ratelimit.Limiter,
	request fiberframework.Ctx,
) (ratelimit.Result, error)
```

### `NewHandler`

NewHandler constructs a Fiber v3 handler. It is a convenience wrapper for
New.

```go
func NewHandler(dispatcher *engine.Dispatcher, options ...Option) fiberframework.Handler
```

### `RateLimitMiddleware`

RateLimitMiddleware enforces limiter before continuing the Fiber chain.

```go
func RateLimitMiddleware(
	limiter *ratelimit.Limiter,
	onError func(fiberframework.Ctx, error) error,
) fiberframework.Handler
```

### `WriteRateLimit`

WriteRateLimit writes the stable 429 response used by single-auth.

```go
func WriteRateLimit(request fiberframework.Ctx, retryAfter int64) error
```

## Types

### `Adapter`

Adapter is an immutable Fiber v3 bridge around the direct fasthttp adapter.
It performs no conversion through net/http.

```go
type Adapter struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Adapter`

### `New`

New constructs an immutable Fiber v3 adapter.

```go
func New(dispatcher *engine.Dispatcher, options ...Option) *Adapter
```

## Methods on `Adapter`

### `Handler`

Handler returns the adapter as a Fiber v3 handler.

```go
func (adapter *Adapter) Handler() fiberframework.Handler
```

### `Serve`

Serve dispatches one Fiber v3 request. Fiber's user context is the
authoritative request context; applications can derive it from a stable
server-lifecycle context when shutdown cancellation is required.

```go
func (adapter *Adapter) Serve(ctx fiberframework.Ctx) error
```

### `ErrorHandler`

ErrorHandler observes dispatcher errors after their stable wire response has
been written. It must be safe for concurrent use.

```go
type ErrorHandler func(context.Context, error)
```

### `Option`

Option configures an Adapter once during construction.

```go
type Option func(*config)
```

## Constructors and functions for `Option`

### `WithErrorHandler`

WithErrorHandler installs a non-mutating error observer.

```go
func WithErrorHandler(handler ErrorHandler) Option
```

### `WithMaxBodyBytes`

WithMaxBodyBytes rejects bodies larger than limit with a stable 413
response. A non-positive value leaves enforcement to Fiber's BodyLimit.

```go
func WithMaxBodyBytes(limit int) Option
```

