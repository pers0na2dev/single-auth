package instrumentation

import (
	"fmt"
	"reflect"
)

// SpanStatusCode matches the numeric values from OpenTelemetry's public API.
type SpanStatusCode int

const (
	SpanStatusCodeUnset SpanStatusCode = iota
	SpanStatusCodeOK
	SpanStatusCodeError
)

// SpanStatusCodes exposes the object-shaped enum surface used by the reference implementation.
type SpanStatusCodes struct {
	UNSET SpanStatusCode
	OK    SpanStatusCode
	ERROR SpanStatusCode
}

// SpanStatus is accepted by SetStatus. The no-op span intentionally ignores
// both fields.
type SpanStatus struct {
	Code    SpanStatusCode
	Message string
}

// Span is the mutation surface the reference implementation uses while tracing an operation.
type Span interface {
	End()
	SetAttribute(key string, value any)
	SetStatus(status any)
	RecordException(exception any)
	UpdateName(name string) Span
}

// NoopSpan is safe to call from every no-telemetry code path. It contains no
// mutable state and a single instance may be shared concurrently.
type NoopSpan struct{}

func (*NoopSpan) End()                          {}
func (*NoopSpan) SetAttribute(_ string, _ any)  {}
func (*NoopSpan) SetStatus(_ any)               {}
func (*NoopSpan) RecordException(_ any)         {}
func (span *NoopSpan) UpdateName(_ string) Span { return span }

// SpanOptions is the options-bearing start-active-span form. Attribute values
// are deliberately unconstrained because the no-op tracer never observes or
// transforms them.
type SpanOptions struct {
	Attributes map[string]any
}

// ActiveSpanCallback is the common callback form for callers that do not need
// a statically typed result.
type ActiveSpanCallback func(Span) any

// NoopTracer executes the callback synchronously with one shared no-op span.
// It accepts the three the reference implementation/OpenTelemetry call forms:
//
//	StartActiveSpan(name, callback)
//	StartActiveSpan(name, options, callback)
//	StartActiveSpan(name, options, context, callback)
type NoopTracer struct{ span *NoopSpan }

// StartActiveSpan returns exactly the callback result. The callback is found
// at the final argument, matching the JavaScript runtime implementation. A
// variadic surface is necessary because Go has no method overloading.
func (tracer *NoopTracer) StartActiveSpan(_ string, arguments ...any) any {
	if len(arguments) < 1 || len(arguments) > 3 {
		panic("instrumentation: StartActiveSpan expects callback, options+callback, or options+context+callback")
	}
	callback := reflect.ValueOf(arguments[len(arguments)-1])
	if !callback.IsValid() || callback.Kind() != reflect.Func {
		panic("instrumentation: final StartActiveSpan argument must be a callback")
	}
	callbackType := callback.Type()
	if callbackType.NumIn() != 1 || callbackType.IsVariadic() {
		panic("instrumentation: StartActiveSpan callback must accept exactly one span")
	}
	if callbackType.NumOut() > 1 {
		panic("instrumentation: StartActiveSpan callback must return at most one value")
	}

	span := defaultNoopSpan
	if tracer != nil && tracer.span != nil {
		span = tracer.span
	}
	spanValue := reflect.ValueOf(span)
	parameter := callbackType.In(0)
	if !spanValue.Type().AssignableTo(parameter) {
		if parameter.Kind() != reflect.Interface || !spanValue.Type().Implements(parameter) {
			panic(fmt.Sprintf(
				"instrumentation: StartActiveSpan callback argument %s cannot receive %s",
				parameter, spanValue.Type(),
			))
		}
	}
	result := callback.Call([]reflect.Value{spanValue})
	if len(result) == 0 {
		return nil
	}
	return result[0].Interface()
}

// TraceAPI provides the the reference implementation subset of OpenTelemetry's trace API.
type TraceAPI struct{ tracer *NoopTracer }

// GetTracer returns the same immutable tracer for every scope and version.
func (trace TraceAPI) GetTracer(_ ...string) *NoopTracer {
	if trace.tracer != nil {
		return trace.tracer
	}
	return defaultNoopTracer
}

// GetActiveSpan reports no ambient span in no-op mode.
func (TraceAPI) GetActiveSpan() Span { return nil }

// OpenTelemetryAPI mirrors the object surface consumed by the reference implementation.
type OpenTelemetryAPI struct {
	SpanStatusCode SpanStatusCodes
	Trace          TraceAPI
}

var (
	defaultNoopSpan   = &NoopSpan{}
	defaultNoopTracer = &NoopTracer{span: defaultNoopSpan}

	// NoopOpenTelemetryAPI is the process-wide no-telemetry fallback.
	NoopOpenTelemetryAPI = OpenTelemetryAPI{
		SpanStatusCode: SpanStatusCodes{
			UNSET: SpanStatusCodeUnset,
			OK:    SpanStatusCodeOK,
			ERROR: SpanStatusCodeError,
		},
		Trace: TraceAPI{tracer: defaultNoopTracer},
	}
)
