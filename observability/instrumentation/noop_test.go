package instrumentation

import (
	"testing"
)

func TestReferenceNoopInstrumentation(t *testing.T) {
	runners := map[string]func(*testing.T){
		"status-codes": func(t *testing.T) {
			codes := NoopOpenTelemetryAPI.SpanStatusCode
			if codes.UNSET != 0 || codes.OK != 1 || codes.ERROR != 2 {
				t.Fatalf("SpanStatusCode=%#v", codes)
			}
		},
		"trace-access": func(t *testing.T) {
			tracer := NoopOpenTelemetryAPI.Trace.GetTracer("t")
			if tracer == nil {
				t.Fatal("GetTracer returned nil")
			}
			if other := NoopOpenTelemetryAPI.Trace.GetTracer("other", "1.0"); other != tracer {
				t.Fatalf("GetTracer returned different no-op tracers: %p != %p", other, tracer)
			}
			if active := NoopOpenTelemetryAPI.Trace.GetActiveSpan(); active != nil {
				t.Fatalf("GetActiveSpan=%#v, want nil", active)
			}
		},
		"active-span-forms": testAllStartActiveSpanForms,
		"safe-mutators": func(t *testing.T) {
			value := NoopOpenTelemetryAPI.Trace.GetTracer("t").StartActiveSpan(
				"noop", SpanOptions{}, ActiveSpanCallback(func(span Span) any { return span }),
			)
			span, ok := value.(Span)
			if !ok || span == nil {
				t.Fatalf("StartActiveSpan returned %#v", value)
			}
			span.End()
			span.SetAttribute("k", "v")
			span.SetStatus(SpanStatus{Code: SpanStatusCodeOK})
			span.RecordException(assertionError("ignored"))
			if renamed := span.UpdateName("renamed"); renamed != span {
				t.Fatalf("UpdateName returned %#v, want original span %#v", renamed, span)
			}
		},
	}

	for _, name := range []string{"status-codes", "trace-access", "active-span-forms", "safe-mutators"} {
		t.Run(name, runners[name])
	}
}

func testAllStartActiveSpanForms(t *testing.T) {
	tracer := NoopOpenTelemetryAPI.Trace.GetTracer("t")
	seen := make([]Span, 0, 3)
	callback := func(result int) ActiveSpanCallback {
		return func(span Span) any {
			if span == nil {
				t.Fatal("callback received nil span")
			}
			seen = append(seen, span)
			return result
		}
	}

	if got := tracer.StartActiveSpan("two-arg", callback(1)); got != 1 {
		t.Fatalf("two-argument result=%#v, want 1", got)
	}
	if got := tracer.StartActiveSpan("three-arg", SpanOptions{Attributes: map[string]any{}}, callback(2)); got != 2 {
		t.Fatalf("three-argument result=%#v, want 2", got)
	}
	if got := tracer.StartActiveSpan("four-arg", SpanOptions{}, struct{}{}, callback(3)); got != 3 {
		t.Fatalf("four-argument result=%#v, want 3", got)
	}
	if len(seen) != 3 || seen[0] != seen[1] || seen[1] != seen[2] {
		t.Fatalf("callbacks did not receive the shared no-op span: %#v", seen)
	}
}

type assertionError string

func (err assertionError) Error() string { return string(err) }
