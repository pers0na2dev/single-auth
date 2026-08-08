package deprecateutil

import (
	"bytes"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type deprecateOracle struct {
	Tests []deprecateOracleTest
}

type deprecateOracleTest struct {
	ID        string                    `json:"id"`
	Scenarios []deprecateOracleScenario `json:"scenarios"`
}

type deprecateOracleScenario struct {
	Message        string                `json:"message"`
	LoggerProvided bool                  `json:"loggerProvided"`
	Warnings       []string              `json:"warnings"`
	Calls          []deprecateOracleCall `json:"calls"`
}

type deprecateOracleCall struct {
	Args          []int `json:"args"`
	Output        *int  `json:"output"`
	ReceiverValue *int  `json:"receiverValue"`
}

type captureLogger struct {
	mutex    sync.Mutex
	warnings []string
}

func (logger *captureLogger) Warn(message string) {
	logger.mutex.Lock()
	defer logger.mutex.Unlock()
	logger.warnings = append(logger.warnings, message)
}

func (logger *captureLogger) snapshot() []string {
	logger.mutex.Lock()
	defer logger.mutex.Unlock()
	return append([]string(nil), logger.warnings...)
}

type boundReceiver struct {
	value int
	calls *[]deprecateOracleCall
}

func (receiver *boundReceiver) add(value int) int {
	output := receiver.value + value
	*receiver.calls = append(*receiver.calls, deprecateOracleCall{
		Args:          []int{value},
		Output:        intPointer(output),
		ReceiverValue: intPointer(receiver.value),
	})
	return output
}

func TestDeprecateBehavior(t *testing.T) {
	for _, testCase := range deprecateCases {
		testCase := testCase
		t.Run(testCase.ID, func(t *testing.T) {
			if len(testCase.Scenarios) != 1 {
				t.Fatalf("expected one scenario, found %d", len(testCase.Scenarios))
			}
			expected := testCase.Scenarios[0]
			actual := runDeprecateOracleScenario(t, testCase.ID, expected)
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("deprecate scenario mismatch\nactual=%#v\nexpected=%#v", actual, expected)
			}
		})
	}
}

func TestDeprecatePreservesExactGoFunctionType(t *testing.T) {
	type variadicFunction func(prefix string, values ...int) (string, int)
	original := variadicFunction(func(prefix string, values ...int) (string, int) {
		total := 0
		for _, value := range values {
			total += value
		}
		return prefix, total
	})
	logger := &captureLogger{}
	wrapped := Deprecate(original, "variadic", logger)
	prefix, total := wrapped("sum", 1, 2, 3)
	if prefix != "sum" || total != 6 {
		t.Fatalf("wrapped variadic result=(%q,%d)", prefix, total)
	}
	if reflect.TypeOf(wrapped) != reflect.TypeOf(original) {
		t.Fatalf("wrapped type=%T want=%T", wrapped, original)
	}
}

func runDeprecateOracleScenario(t *testing.T, id string, expected deprecateOracleScenario) deprecateOracleScenario {
	t.Helper()
	actual := deprecateOracleScenario{
		Message:        expected.Message,
		LoggerProvided: expected.LoggerProvided,
		Warnings:       make([]string, 0, len(expected.Warnings)),
		Calls:          make([]deprecateOracleCall, 0, len(expected.Calls)),
	}
	logger := &captureLogger{}

	invokeVoid := func() {
		actual.Calls = append(actual.Calls, deprecateOracleCall{Args: []int{}})
	}
	withLogger := func(function func()) func() {
		if expected.LoggerProvided {
			return Deprecate(function, expected.Message, logger)
		}
		return Deprecate(function, expected.Message)
	}

	switch {
	case strings.HasSuffix(id, "::should fall back to console.warn if no logger provided"):
		if expected.LoggerProvided {
			t.Fatal("fallback scenario unexpectedly has a logger")
		}
		var fallback bytes.Buffer
		previousWriter := fallbackLogger.Writer()
		fallbackLogger.SetOutput(&fallback)
		defer fallbackLogger.SetOutput(previousWriter)
		withLogger(invokeVoid)()
		actual.Warnings = warningLines(fallback.String())

	case strings.HasSuffix(id, "::should pass arguments and return value correctly"):
		function := func(left, right int) int {
			output := left + right
			actual.Calls = append(actual.Calls, deprecateOracleCall{
				Args:   []int{left, right},
				Output: intPointer(output),
			})
			return output
		}
		wrapped := Deprecate(function, expected.Message, logger)
		if len(expected.Calls) != 1 || len(expected.Calls[0].Args) != 2 {
			t.Fatalf("invalid arguments oracle: %#v", expected.Calls)
		}
		_ = wrapped(expected.Calls[0].Args[0], expected.Calls[0].Args[1])
		actual.Warnings = logger.snapshot()

	case strings.HasSuffix(id, "::should preserve this context"):
		receiver := &boundReceiver{value: 10, calls: &actual.Calls}
		wrapped := Deprecate(receiver.add, expected.Message, logger)
		if len(expected.Calls) != 1 || len(expected.Calls[0].Args) != 1 {
			t.Fatalf("invalid receiver oracle: %#v", expected.Calls)
		}
		_ = wrapped(expected.Calls[0].Args[0])
		actual.Warnings = logger.snapshot()

	case strings.HasSuffix(id, "::should use provided logger if available"):
		withLogger(invokeVoid)()
		actual.Warnings = logger.snapshot()

	case strings.HasSuffix(id, "::should warn once when called multiple times"):
		wrapped := withLogger(invokeVoid)
		for range expected.Calls {
			wrapped()
		}
		actual.Warnings = logger.snapshot()

	default:
		t.Fatalf("unhandled deprecate manifest ID %q", id)
	}
	return actual
}

func warningLines(output string) []string {
	trimmed := strings.TrimSuffix(output, "\n")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "\n")
}

func intPointer(value int) *int {
	return &value
}
