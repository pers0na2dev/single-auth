---
title: "github.com/pers0na2dev/single-auth/transport/fasthttp"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/transport/fasthttp.

- Import path: `github.com/pers0na2dev/single-auth/transport/fasthttp`
- Package name: `fasthttp`

Package fasthttp adapts the transport-neutral authentication dispatcher to
github.com/valyala/fasthttp without converting through net/http.

## Functions

### `CheckRateLimit`

CheckRateLimit adapts one native fasthttp request to the transport-neutral
limiter. requestContext may be nil.

```go
func CheckRateLimit(
	requestContext context.Context,
	limiter *ratelimit.Limiter,
	request *fasthttpserver.RequestCtx,
) (ratelimit.Result, error)
```

### `NewHandler`

NewHandler constructs a fasthttp request handler. It is a convenience
wrapper for New.

```go
func NewHandler(
	dispatcher *engine.Dispatcher,
	options ...Option,
) fasthttpserver.RequestHandler
```

### `RateLimitMiddleware`

RateLimitMiddleware enforces limiter before invoking a native fasthttp
handler.

```go
func RateLimitMiddleware(
	limiter *ratelimit.Limiter,
	next fasthttpserver.RequestHandler,
	onError func(*fasthttpserver.RequestCtx, error),
) fasthttpserver.RequestHandler
```

### `WriteRateLimit`

WriteRateLimit writes the stable 429 response used by single-auth.

```go
func WriteRateLimit(request *fasthttpserver.RequestCtx, retryAfter int64)
```

## Types

### `Adapter`

Adapter is an immutable fasthttp bridge around one dispatcher.

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

### `Handler`

Handler returns the adapter as a fasthttp.RequestHandler.

```go
func (adapter *Adapter) Handler() fasthttpserver.RequestHandler
```

### `Serve`

Serve dispatches one fasthttp request. By default RequestCtx is used as the
Go context, which propagates server shutdown. Use WithContextProvider when
the host has a stable, finer-grained request or server-lifecycle context.

```go
func (adapter *Adapter) Serve(ctx *fasthttpserver.RequestCtx)
```

### `ServeContext`

ServeContext dispatches one fasthttp request with an explicit host context.
Fiber uses this method with fiber.Ctx.Context; it still performs no net/http
conversion.

```go
func (adapter *Adapter) ServeContext(
	requestContext context.Context,
	ctx *fasthttpserver.RequestCtx,
)
```

### `ContextProvider`

ContextProvider returns an authoritative request-scoped context supplied by
the host. When present, the adapter does not also retain RequestCtx as a
cancellation source: fasthttp mutates its server-wide shutdown channel while
shutting down, so asynchronous users of RequestCtx.Done can otherwise race
with Server.Shutdown. Hosts that need shutdown cancellation should derive the
provided context from their own stable server-lifecycle context.

```go
type ContextProvider func(*fasthttpserver.RequestCtx) context.Context
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

### `WithContextProvider`

WithContextProvider installs the bridge used for request deadlines and
cancellation managed by the host application.

```go
func WithContextProvider(provider ContextProvider) Option
```

### `WithErrorHandler`

WithErrorHandler installs a non-mutating error observer.

```go
func WithErrorHandler(handler ErrorHandler) Option
```

### `WithMaxBodyBytes`

WithMaxBodyBytes rejects already-buffered bodies larger than limit. A
non-positive value leaves size enforcement to fasthttp.Server's
MaxRequestBodySize.

```go
func WithMaxBodyBytes(limit int) Option
```

