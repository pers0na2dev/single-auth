package hostutil

import (
	"fmt"
	"testing"
)

func TestHostClassificationAndRouting(t *testing.T) {
	for index, testCase := range hostCases {
		t.Run(fmt.Sprintf("%s/%d", testCase.operation, index), func(t *testing.T) {
			switch testCase.operation {
			case "classifyHost":
				if got := ClassifyHost(testCase.input); testCase.classification == nil || got != *testCase.classification {
					t.Fatalf("ClassifyHost(%q) = %#v, want %#v", testCase.input, got, testCase.classification)
				}
			case "isLoopbackHost":
				assertHostBool(t, testCase, IsLoopbackHost(testCase.input))
			case "isLoopbackIP":
				assertHostBool(t, testCase, IsLoopbackIP(testCase.input))
			case "isPublicRoutableHost":
				assertHostBool(t, testCase, IsPublicRoutableHost(testCase.input))
			default:
				t.Fatalf("unknown host operation %q", testCase.operation)
			}
		})
	}
}

func assertHostBool(t *testing.T, testCase hostCase, got bool) {
	t.Helper()
	if testCase.boolOutput == nil || got != *testCase.boolOutput {
		t.Fatalf("%s(%q) = %t, want %v", testCase.operation, testCase.input, got, testCase.boolOutput)
	}
}
