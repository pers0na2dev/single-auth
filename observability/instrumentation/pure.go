package instrumentation

import (
	"context"
	"sync/atomic"
)

const (
	AttrDBCollectionName       = "db.collection.name"
	AttrDBOperationName        = "db.operation.name"
	AttrHTTPResponseStatusCode = "http.response.status_code"
	AttrHTTPRoute              = "http.route"
	AttrOperationID            = "single_auth.operation_id"
	AttrHookType               = "single_auth.hook.type"
	AttrContext                = "single_auth.context"
)

// SpanScope is a manually delimited active span. It is used by runtimes whose
// callback API has a continuation boundary: the span can finish before that
// continuation starts while the caller still receives its eventual result.
// End and EndWithFailure are idempotent and safe to race.
type SpanScope struct {
	span  Span
	ended atomic.Bool
}

// StartSpanContext starts a span and returns the context carrying it together
// with an idempotent lifecycle handle. Most callers should use WithSpanContext
// or WithSpanContextErr; this form exists for explicit continuation boundaries.
func StartSpanContext(
	ctx context.Context,
	name string,
	attributes map[string]any,
) (context.Context, *SpanScope) {
	spanContext, span := startSpan(ctx, name, attributes)
	return spanContext, &SpanScope{span: span}
}

// End completes the span successfully.
func (scope *SpanScope) End() {
	if scope == nil || !scope.ended.CompareAndSwap(false, true) {
		return
	}
	endSpan(scope.span)
}

// EndWithFailure completes the span with the reference implementation's redirect-aware failure
// semantics.
func (scope *SpanScope) EndWithFailure(failure any) {
	if scope == nil || !scope.ended.CompareAndSwap(false, true) {
		return
	}
	endSpanWithFailure(scope.span, failure)
}

// WithSpan traces a synchronous callback and preserves its exact result or
// panic. With no configured provider it remains a dependency-free no-op.
func WithSpan[T any](name string, attributes map[string]any, fn func() T) (result T) {
	if fn == nil {
		panic("instrumentation: span callback is nil")
	}
	_, span := startSpan(context.Background(), name, attributes)
	defer func() {
		if failure := recover(); failure != nil {
			endSpanWithFailure(span, failure)
			panic(failure)
		}
		endSpan(span)
	}()
	return fn()
}

// WithSpanErr is the idiomatic Go form for callbacks whose asynchronous
// equivalent returns a rejected Promise. Both the value and error propagate
// unchanged.
func WithSpanErr[T any](name string, attributes map[string]any, fn func() (T, error)) (T, error) {
	if fn == nil {
		panic("instrumentation: span callback is nil")
	}
	return WithSpanContextErr(context.Background(), name, attributes, func(context.Context) (T, error) {
		return fn()
	})
}

// WithSpanContext is the context-aware form for nested Go operations. The
// callback receives the context containing the active child span.
func WithSpanContext[T any](
	ctx context.Context,
	name string,
	attributes map[string]any,
	fn func(context.Context) T,
) (result T) {
	if fn == nil {
		panic("instrumentation: span callback is nil")
	}
	spanContext, span := startSpan(ctx, name, attributes)
	defer func() {
		if failure := recover(); failure != nil {
			endSpanWithFailure(span, failure)
			panic(failure)
		}
		endSpan(span)
	}()
	return fn(spanContext)
}

// WithSpanContextErr is the context-aware error-returning form. It ends the
// span only after fn completes, which maps to the reference implementation's Promise handling.
func WithSpanContextErr[T any](
	ctx context.Context,
	name string,
	attributes map[string]any,
	fn func(context.Context) (T, error),
) (result T, err error) {
	if fn == nil {
		panic("instrumentation: span callback is nil")
	}
	spanContext, span := startSpan(ctx, name, attributes)
	defer func() {
		if failure := recover(); failure != nil {
			endSpanWithFailure(span, failure)
			panic(failure)
		}
	}()
	result, err = fn(spanContext)
	if err != nil {
		endSpanWithFailure(span, err)
		return result, err
	}
	endSpan(span)
	return result, nil
}
