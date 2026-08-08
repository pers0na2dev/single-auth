---
title: "github.com/pers0na2dev/single-auth/observability/instrumentation"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/observability/instrumentation.

- Import path: `github.com/pers0na2dev/single-auth/observability/instrumentation`
- Package name: `instrumentation`

Package instrumentation provides the reference implementation-compatible tracing primitives.
The no-op API is always available and lets callers keep instrumentation code
enabled when no OpenTelemetry provider is installed.

## Constants

```go
const (
	AttrDBCollectionName       = "db.collection.name"
	AttrDBOperationName        = "db.operation.name"
	AttrHTTPResponseStatusCode = "http.response.status_code"
	AttrHTTPRoute              = "http.route"
	AttrOperationID            = "single_auth.operation_id"
	AttrHookType               = "single_auth.hook.type"
	AttrContext                = "single_auth.context"
)
```

```go
const (
	InstrumentationScope = "single-auth"

	InstrumentationVersion = "1.6.26"
)
```

## Variables

```go
var (
	NoopOpenTelemetryAPI = OpenTelemetryAPI{
		SpanStatusCode: SpanStatusCodes{
			UNSET: SpanStatusCodeUnset,
			OK:    SpanStatusCodeOK,
			ERROR: SpanStatusCodeError,
		},
		Trace: TraceAPI{/* contains filtered or unexported fields */},
	}
)
```

## Functions

### `SetTracerProvider`

SetTracerProvider installs a process-wide provider and returns an idempotent
restore function. Passing nil selects the dependency-free no-op provider.
The restore only takes effect while this installation is still current, so
an older cleanup cannot overwrite a newer provider.

```go
func SetTracerProvider(provider TracerProvider) (restore func())
```

### `WithSpan`

WithSpan traces a synchronous callback and preserves its exact result or
panic. With no configured provider it remains a dependency-free no-op.

```go
func WithSpan[T any](name string, attributes map[string]any, fn func() T) (result T)
```

### `WithSpanContext`

WithSpanContext is the context-aware form for nested Go operations. The
callback receives the context containing the active child span.

```go
func WithSpanContext[T any](
	ctx context.Context,
	name string,
	attributes map[string]any,
	fn func(context.Context) T,
) (result T)
```

### `WithSpanContextErr`

WithSpanContextErr is the context-aware error-returning form. It ends the
span only after fn completes, which maps to the reference implementation's Promise handling.

```go
func WithSpanContextErr[T any](
	ctx context.Context,
	name string,
	attributes map[string]any,
	fn func(context.Context) (T, error),
) (result T, err error)
```

### `WithSpanErr`

WithSpanErr is the idiomatic Go form for callbacks whose asynchronous
equivalent returns a rejected Promise. Both the value and error propagate
unchanged.

```go
func WithSpanErr[T any](name string, attributes map[string]any, fn func() (T, error)) (T, error)
```

## Types

### `ActiveSpanCallback`

ActiveSpanCallback is the common callback form for callers that do not need
a statically typed result.

```go
type ActiveSpanCallback func(Span) any
```

### `NoopSpan`

NoopSpan is safe to call from every no-telemetry code path. It contains no
mutable state and a single instance may be shared concurrently.

```go
type NoopSpan struct{}
```

## Methods on `NoopSpan`

### `End`

```go
func (*NoopSpan) End()
```

### `RecordException`

```go
func (*NoopSpan) RecordException(_ any)
```

### `SetAttribute`

```go
func (*NoopSpan) SetAttribute(_ string, _ any)
```

### `SetStatus`

```go
func (*NoopSpan) SetStatus(_ any)
```

### `UpdateName`

```go
func (span *NoopSpan) UpdateName(_ string) Span
```

### `NoopTracer`

NoopTracer executes the callback synchronously with one shared no-op span.
It accepts the three the reference implementation/OpenTelemetry call forms:

	StartActiveSpan(name, callback)
	StartActiveSpan(name, options, callback)
	StartActiveSpan(name, options, context, callback)

```go
type NoopTracer struct {
	// contains filtered or unexported fields
}
```

## Methods on `NoopTracer`

### `StartActiveSpan`

StartActiveSpan returns exactly the callback result. The callback is found
at the final argument, matching the JavaScript runtime implementation. A
variadic surface is necessary because Go has no method overloading.

```go
func (tracer *NoopTracer) StartActiveSpan(_ string, arguments ...any) any
```

### `OpenTelemetryAPI`

OpenTelemetryAPI mirrors the object surface consumed by the reference implementation.

```go
type OpenTelemetryAPI struct {
	SpanStatusCode SpanStatusCodes
	Trace          TraceAPI
}
```

### `Span`

Span is the mutation surface the reference implementation uses while tracing an operation.

```go
type Span interface {
	End()
	SetAttribute(key string, value any)
	SetStatus(status any)
	RecordException(exception any)
	UpdateName(name string) Span
}
```

### `SpanOptions`

SpanOptions is the options-bearing start-active-span form. Attribute values
are deliberately unconstrained because the no-op tracer never observes or
transforms them.

```go
type SpanOptions struct {
	Attributes map[string]any
}
```

### `SpanScope`

SpanScope is a manually delimited active span. It is used by runtimes whose
callback API has a continuation boundary: the span can finish before that
continuation starts while the caller still receives its eventual result.
End and EndWithFailure are idempotent and safe to race.

```go
type SpanScope struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `SpanScope`

### `StartSpanContext`

StartSpanContext starts a span and returns the context carrying it together
with an idempotent lifecycle handle. Most callers should use WithSpanContext
or WithSpanContextErr; this form exists for explicit continuation boundaries.

```go
func StartSpanContext(
	ctx context.Context,
	name string,
	attributes map[string]any,
) (context.Context, *SpanScope)
```

## Methods on `SpanScope`

### `End`

End completes the span successfully.

```go
func (scope *SpanScope) End()
```

### `EndWithFailure`

EndWithFailure completes the span with the reference implementation's redirect-aware failure
semantics.

```go
func (scope *SpanScope) EndWithFailure(failure any)
```

### `SpanStatus`

SpanStatus is accepted by SetStatus. The no-op span intentionally ignores
both fields.

```go
type SpanStatus struct {
	Code    SpanStatusCode
	Message string
}
```

### `SpanStatusCode`

SpanStatusCode matches the numeric values from OpenTelemetry's public API.

```go
type SpanStatusCode int
```

## Constants associated with `SpanStatusCode`

```go
const (
	SpanStatusCodeUnset SpanStatusCode = iota
	SpanStatusCodeOK
	SpanStatusCodeError
)
```

### `SpanStatusCodes`

SpanStatusCodes exposes the object-shaped enum surface used by the reference implementation.

```go
type SpanStatusCodes struct {
	UNSET SpanStatusCode
	OK    SpanStatusCode
	ERROR SpanStatusCode
}
```

### `TraceAPI`

TraceAPI provides the the reference implementation subset of OpenTelemetry's trace API.

```go
type TraceAPI struct {
	// contains filtered or unexported fields
}
```

## Methods on `TraceAPI`

### `GetActiveSpan`

GetActiveSpan reports no ambient span in no-op mode.

```go
func (TraceAPI) GetActiveSpan() Span
```

### `GetTracer`

GetTracer returns the same immutable tracer for every scope and version.

```go
func (trace TraceAPI) GetTracer(_ ...string) *NoopTracer
```

### `Tracer`

Tracer starts a span and returns the context carrying that active span.

```go
type Tracer interface {
	Start(ctx context.Context, name string, attributes map[string]any) (context.Context, Span)
}
```

### `TracerProvider`

TracerProvider is the transport-neutral hook used by the instrumentation
package. OpenTelemetry adapters can implement it without making OTel a hard
dependency of the pure/no-op entry point.

```go
type TracerProvider interface {
	Tracer(scope, version string) Tracer
}
```

## Variables associated with `TracerProvider`

NoopTracerProvider is the safe provider used when no tracing integration is
configured or when a configured provider fails while starting a span.

```go
var NoopTracerProvider TracerProvider = noopTracerProvider{}
```

## Constructors and functions for `TracerProvider`

### `CurrentTracerProvider`

CurrentTracerProvider returns the configured provider or the no-op fallback.

```go
func CurrentTracerProvider() TracerProvider
```

