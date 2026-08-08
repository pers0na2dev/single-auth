package instrumentation

import (
	"errors"
	"reflect"
	"runtime/debug"
	"strings"
	"testing"
)

var pureInstrumentationCases = []struct {
	name     string
	expected any
}{
	{name: "does not reference OpenTelemetry at runtime", expected: map[string]any{"containsOpenTelemetry": false}},
	{name: "propagates async rejections", expected: map[string]any{"message": "boom"}},
	{name: "propagates sync throws", expected: map[string]any{"message": "boom"}},
	{name: "returns the result of a sync function", expected: map[string]any{"result": 42}},
	{name: "returns the result of an async function", expected: map[string]any{"result": "ok"}},
}

func TestPureInstrumentationBehavior(t *testing.T) {
	for _, vector := range pureInstrumentationCases {
		vector := vector
		t.Run(vector.name, func(t *testing.T) {
			actual := runPureInstrumentationVector(t, vector.name)
			if !reflect.DeepEqual(actual, vector.expected) {
				t.Fatalf("pure instrumentation observation = %#v, want %#v", actual, vector.expected)
			}
		})
	}
}

func runPureInstrumentationVector(t *testing.T, title string) any {
	t.Helper()
	switch title {
	case "returns the result of a sync function":
		return map[string]any{"result": WithSpan("test.sync", map[string]any{"k": 1}, func() int { return 42 })}
	case "returns the result of an async function":
		result := WithSpan("test.async", map[string]any{"k": 1}, func() <-chan string {
			ready := make(chan string, 1)
			ready <- "ok"
			close(ready)
			return ready
		})
		return map[string]any{"result": <-result}
	case "propagates sync throws":
		message := capturePurePanic(func() {
			WithSpan("test.sync.err", map[string]any{}, func() int {
				panic(errors.New("boom"))
			})
		})
		return map[string]any{"message": message}
	case "propagates async rejections":
		result := WithSpan("test.async.err", map[string]any{}, func() <-chan error {
			ready := make(chan error, 1)
			ready <- errors.New("boom")
			close(ready)
			return ready
		})
		return map[string]any{"message": (<-result).Error()}
	default:
		if title != "does not reference OpenTelemetry at runtime" {
			t.Fatalf("unknown pure instrumentation test %q", title)
			return nil
		}
		containsOpenTelemetry := false
		if build, ok := debug.ReadBuildInfo(); ok {
			for _, dependency := range build.Deps {
				if strings.Contains(strings.ToLower(dependency.Path), "opentelemetry") {
					containsOpenTelemetry = true
					break
				}
			}
		}
		return map[string]any{"containsOpenTelemetry": containsOpenTelemetry}
	}
}

func capturePurePanic(fn func()) (message string) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if err, ok := recovered.(error); ok {
				message = err.Error()
			} else {
				message = strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(reflect.ValueOf(recovered).String()), "\n", " "))
			}
		}
	}()
	fn()
	return ""
}
