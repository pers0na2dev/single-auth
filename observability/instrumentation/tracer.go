package instrumentation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"

	"github.com/pers0na2dev/single-auth/core/contract"
)

const (
	// InstrumentationScope is the OpenTelemetry scope used by the reference implementation.
	InstrumentationScope = "single-auth"
	// InstrumentationVersion is the pinned the reference implementation compatibility version.
	InstrumentationVersion = "1.6.26"
)

// TracerProvider is the transport-neutral hook used by the instrumentation
// package. OpenTelemetry adapters can implement it without making OTel a hard
// dependency of the pure/no-op entry point.
type TracerProvider interface {
	Tracer(scope, version string) Tracer
}

// Tracer starts a span and returns the context carrying that active span.
type Tracer interface {
	Start(ctx context.Context, name string, attributes map[string]any) (context.Context, Span)
}

type providerState struct {
	provider TracerProvider
}

var activeProvider atomic.Pointer[providerState]

type noopTracerProvider struct{}

func (noopTracerProvider) Tracer(string, string) Tracer { return dependencyFreeTracer{} }

type dependencyFreeTracer struct{}

func (dependencyFreeTracer) Start(ctx context.Context, _ string, _ map[string]any) (context.Context, Span) {
	return ctx, defaultNoopSpan
}

// NoopTracerProvider is the safe provider used when no tracing integration is
// configured or when a configured provider fails while starting a span.
var NoopTracerProvider TracerProvider = noopTracerProvider{}

// SetTracerProvider installs a process-wide provider and returns an idempotent
// restore function. Passing nil selects the dependency-free no-op provider.
// The restore only takes effect while this installation is still current, so
// an older cleanup cannot overwrite a newer provider.
func SetTracerProvider(provider TracerProvider) (restore func()) {
	installed := &providerState{provider: provider}
	previous := activeProvider.Swap(installed)
	var restored atomic.Bool
	return func() {
		if restored.Load() {
			return
		}
		if activeProvider.CompareAndSwap(installed, previous) {
			restored.Store(true)
		}
	}
}

// CurrentTracerProvider returns the configured provider or the no-op fallback.
func CurrentTracerProvider() TracerProvider {
	state := activeProvider.Load()
	if state == nil || state.provider == nil {
		return NoopTracerProvider
	}
	return state.provider
}

func startSpan(ctx context.Context, name string, attributes map[string]any) (
	spanContext context.Context,
	span Span,
) {
	if ctx == nil {
		ctx = context.Background()
	}
	spanContext = ctx
	span = defaultNoopSpan
	defer func() {
		if recover() != nil {
			spanContext = ctx
			span = defaultNoopSpan
		}
	}()
	tracer := CurrentTracerProvider().Tracer(InstrumentationScope, InstrumentationVersion)
	if tracer == nil {
		return spanContext, span
	}
	startedContext, startedSpan := tracer.Start(ctx, name, cloneAttributes(attributes))
	if startedContext != nil {
		spanContext = startedContext
	}
	if startedSpan != nil {
		span = startedSpan
	}
	return spanContext, span
}

func cloneAttributes(attributes map[string]any) map[string]any {
	if attributes == nil {
		return map[string]any{}
	}
	clone := make(map[string]any, len(attributes))
	for key, value := range attributes {
		clone[key] = value
	}
	return clone
}

func endSpanWithFailure(span Span, failure any) {
	if status, redirect := redirectStatus(failure); redirect {
		safeSpanCall(func() { span.SetAttribute(AttrHTTPResponseStatusCode, status) })
		safeSpanCall(func() { span.SetStatus(SpanStatus{Code: SpanStatusCodeOK}) })
	} else {
		safeSpanCall(func() { span.RecordException(failure) })
		safeSpanCall(func() {
			span.SetStatus(SpanStatus{
				Code:    SpanStatusCodeError,
				Message: failureMessage(failure),
			})
		})
	}
	safeSpanCall(span.End)
}

func endSpan(span Span) {
	safeSpanCall(span.End)
}

func safeSpanCall(call func()) {
	defer func() { _ = recover() }()
	call()
}

func failureMessage(failure any) string {
	if err, ok := failure.(error); ok {
		return err.Error()
	}
	return fmt.Sprint(failure)
}

func redirectStatus(failure any) (int, bool) {
	if err, ok := failure.(error); ok {
		var apiError *contract.APIError
		if errors.As(err, &apiError) && apiError != nil {
			return apiError.Status, apiError.Status >= 300 && apiError.Status < 400
		}
	}

	// Custom integrations sometimes mirror the JavaScript APIError shape
	// rather than using contract.APIError. Accept Name + StatusCode fields while
	// retaining the reference implementation's exact APIError/3xx guard.
	value := reflect.ValueOf(failure)
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return 0, false
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return 0, false
	}
	name := value.Type().Name()
	if field := value.FieldByName("Name"); field.IsValid() && field.Kind() == reflect.String {
		name = field.String()
	}
	if name != "APIError" {
		return 0, false
	}
	statusField := value.FieldByName("StatusCode")
	if !statusField.IsValid() {
		statusField = value.FieldByName("Status")
	}
	status, ok := reflectedStatus(statusField)
	return status, ok && status >= 300 && status < 400
}

func reflectedStatus(value reflect.Value) (int, bool) {
	if !value.IsValid() {
		return 0, false
	}
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return int(value.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int(value.Uint()), true
	default:
		return 0, false
	}
}
