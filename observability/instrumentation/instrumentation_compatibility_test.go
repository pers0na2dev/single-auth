package instrumentation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
)

type instrumentationOracle struct {
	Cases []instrumentationOracleCase
}

type instrumentationOracleCase struct {
	ID          string                     `json:"id"`
	Title       string                     `json:"title"`
	Observation instrumentationObservation `json:"observation"`
}

type instrumentationObservation struct {
	Result instrumentationValue  `json:"result"`
	Error  *instrumentationError `json:"error"`
	Spans  []instrumentationSpan `json:"spans"`
}

type instrumentationValue struct {
	Kind  string `json:"kind"`
	Value any    `json:"value,omitempty"`
}

type instrumentationError struct {
	Name       string `json:"name"`
	Message    string `json:"message"`
	StatusCode *int   `json:"statusCode"`
}

type instrumentationStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type instrumentationScope struct {
	Name    string  `json:"name"`
	Version *string `json:"version"`
}

type instrumentationSpan struct {
	Name              string                `json:"name"`
	Attributes        map[string]any        `json:"attributes"`
	Status            instrumentationStatus `json:"status"`
	ExceptionMessages []string              `json:"exceptionMessages"`
	Scope             instrumentationScope  `json:"scope"`
}

func TestInstrumentationBehavior(t *testing.T) {
	oracle := loadInstrumentationOracle(t)
	for _, testCase := range oracle.Cases {
		testCase := testCase
		t.Run(instrumentationCaseName(testCase.Title), func(t *testing.T) {
			actual := runInstrumentationOracleCase(t, testCase.Title)
			assertInstrumentationObservation(t, actual, testCase.Observation)
		})
	}
}

func runInstrumentationOracleCase(t *testing.T, title string) instrumentationObservation {
	t.Helper()
	provider := newRecordingProvider()
	var restore func()
	if title == "withSpan runs without throwing when the package fails to load" {
		restore = SetTracerProvider(failingTracerProvider{})
	} else {
		restore = SetTracerProvider(provider)
	}
	defer restore()

	var result any
	var failure any
	switch title {
	case "creates a span with name and attributes for sync function":
		result = WithSpan("test.sync", map[string]any{
			AttrDBOperationName:  "findOne",
			AttrDBCollectionName: "user",
		}, func() int { return 42 })
	case "creates a span for async function":
		value, err := WithSpanErr("test.async", map[string]any{"endpoint": "getSession"}, func() (string, error) {
			time.Sleep(time.Millisecond)
			return "session-id", nil
		})
		result, failure = value, err
	case "records error status and exception when sync function throws":
		result, failure = captureInstrumentationPanic(func() any {
			return WithSpan("test.sync.error", map[string]any{"foo": "bar"}, func() any {
				panic(errors.New("sync failure"))
			})
		})
	case "records error status and exception when async function rejects":
		_, err := WithSpanErr("test.async.error", map[string]any{"baz": 1}, func() (any, error) {
			return nil, errors.New("async failure")
		})
		failure = err
	case "creates multiple sequential spans":
		WithSpan("first", map[string]any{"order": 1}, func() int { return 1 })
		WithSpan("second", map[string]any{"order": 2}, func() int { return 2 })
	case "creates nested spans when withSpan is composed":
		result = WithSpan("outer", map[string]any{"depth": 0}, func() string {
			return WithSpan("inner", map[string]any{"depth": 1}, func() string { return "ok" })
		})
	case "does not record error status for redirect APIErrors (sync)":
		result, failure = captureInstrumentationPanic(func() any {
			return WithSpan("test.redirect.sync", map[string]any{}, func() any {
				panic(contract.NewAPIError(302, "FOUND", "Found"))
			})
		})
	case "does not record error status for redirect APIErrors (async)":
		_, err := WithSpanErr("test.redirect.async", map[string]any{}, func() (any, error) {
			return nil, contract.NewAPIError(302, "FOUND", "Found")
		})
		failure = err
	case "still records error status for non-redirect APIErrors":
		result, failure = captureInstrumentationPanic(func() any {
			return WithSpan("test.apierror.404", map[string]any{}, func() any {
				panic(contract.NewAPIError(404, "NOT_FOUND", "Not Found"))
			})
		})
	case "withSpan runs without throwing when the package fails to load":
		result = WithSpan("fallback", map[string]any{"k": 1}, func() int { return 99 })
	default:
		if !strings.HasPrefix(title, "uses ") || !strings.HasSuffix(title, " instrumentation scope") {
			t.Fatalf("unknown frozen instrumentation test %q", title)
		}
		result = WithSpan("scope.check", map[string]any{}, func() any { return nil })
	}
	if err, ok := failure.(error); ok && err == nil {
		failure = nil
	}
	return instrumentationObservation{
		Result: normalizeInstrumentationValue(result),
		Error:  snapshotInstrumentationError(failure),
		Spans:  provider.Finished(),
	}
}

func instrumentationCaseName(title string) string {
	if strings.HasPrefix(title, "uses ") && strings.HasSuffix(title, " instrumentation scope") {
		return "uses configured instrumentation scope"
	}
	return title
}

func captureInstrumentationPanic(fn func() any) (result, failure any) {
	defer func() {
		if recovered := recover(); recovered != nil {
			failure = recovered
		}
	}()
	result = fn()
	return result, nil
}

func normalizeInstrumentationValue(value any) instrumentationValue {
	if value == nil {
		return instrumentationValue{Kind: "undefined"}
	}
	return instrumentationValue{Kind: "value", Value: value}
}

func snapshotInstrumentationError(failure any) *instrumentationError {
	if failure == nil {
		return nil
	}
	snapshot := &instrumentationError{Name: "Error", Message: fmt.Sprint(failure)}
	if err, ok := failure.(error); ok {
		snapshot.Message = err.Error()
		if apiError, matched := contract.AsAPIError(err); matched {
			snapshot.Name = "APIError"
			status := apiError.Status
			snapshot.StatusCode = &status
		}
	}
	return snapshot
}

type recordingProvider struct {
	mu       sync.Mutex
	finished []instrumentationSpan
}

func newRecordingProvider() *recordingProvider { return &recordingProvider{} }

func (provider *recordingProvider) Tracer(scope, version string) Tracer {
	return recordingTracer{provider: provider, scope: scope, version: version}
}

func (provider *recordingProvider) Finished() []instrumentationSpan {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	result := make([]instrumentationSpan, len(provider.finished))
	copy(result, provider.finished)
	return result
}

type recordingTracer struct {
	provider *recordingProvider
	scope    string
	version  string
}

func (tracer recordingTracer) Start(
	ctx context.Context,
	name string,
	attributes map[string]any,
) (context.Context, Span) {
	span := &recordingSpan{
		provider:   tracer.provider,
		name:       name,
		attributes: attributes,
		scope:      tracer.scope,
		version:    tracer.version,
	}
	return ctx, span
}

type recordingSpan struct {
	mu                sync.Mutex
	provider          *recordingProvider
	name              string
	attributes        map[string]any
	status            instrumentationStatus
	exceptionMessages []string
	scope             string
	version           string
	ended             bool
}

func (span *recordingSpan) End() {
	span.mu.Lock()
	if span.ended {
		span.mu.Unlock()
		return
	}
	span.ended = true
	version := span.version
	snapshot := instrumentationSpan{
		Name:              span.name,
		Attributes:        cloneInstrumentationAttributes(span.attributes),
		Status:            span.status,
		ExceptionMessages: append([]string{}, span.exceptionMessages...),
		Scope:             instrumentationScope{Name: span.scope, Version: &version},
	}
	span.mu.Unlock()

	span.provider.mu.Lock()
	span.provider.finished = append(span.provider.finished, snapshot)
	span.provider.mu.Unlock()
}

func (span *recordingSpan) SetAttribute(key string, value any) {
	span.mu.Lock()
	defer span.mu.Unlock()
	span.attributes[key] = value
}

func (span *recordingSpan) SetStatus(value any) {
	span.mu.Lock()
	defer span.mu.Unlock()
	switch status := value.(type) {
	case SpanStatus:
		span.status = instrumentationStatus{Code: int(status.Code), Message: status.Message}
	case *SpanStatus:
		if status != nil {
			span.status = instrumentationStatus{Code: int(status.Code), Message: status.Message}
		}
	}
}

func (span *recordingSpan) RecordException(exception any) {
	span.mu.Lock()
	defer span.mu.Unlock()
	message := fmt.Sprint(exception)
	if err, ok := exception.(error); ok {
		message = err.Error()
	}
	span.exceptionMessages = append(span.exceptionMessages, message)
}

func (span *recordingSpan) UpdateName(name string) Span {
	span.mu.Lock()
	span.name = name
	span.mu.Unlock()
	return span
}

func cloneInstrumentationAttributes(attributes map[string]any) map[string]any {
	clone := make(map[string]any, len(attributes))
	for key, value := range attributes {
		clone[key] = value
	}
	return clone
}

type failingTracerProvider struct{}

func (failingTracerProvider) Tracer(string, string) Tracer {
	panic("simulated missing optional peer")
}

func assertInstrumentationObservation(t *testing.T, actual, expected instrumentationObservation) {
	t.Helper()
	for index := range actual.Spans {
		if actual.Spans[index].Scope.Name != InstrumentationScope {
			t.Fatalf("span %d scope = %q, want %q", index, actual.Spans[index].Scope.Name, InstrumentationScope)
		}
		if index < len(expected.Spans) {
			expected.Spans[index].Scope.Name = InstrumentationScope
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("instrumentation observation = %#v, want %#v", actual, expected)
	}
}

func loadInstrumentationOracle(t *testing.T) instrumentationOracle {
	t.Helper()
	return instrumentationOracle{Cases: instrumentationCases}
}
