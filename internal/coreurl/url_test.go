package coreurl

import (
	"fmt"
	"testing"
)

func TestURLNormalizationAndSafety(t *testing.T) {
	for index, testCase := range urlUtilityCases {
		t.Run(fmt.Sprintf("%s/%d", testCase.operation, index), func(t *testing.T) {
			switch testCase.operation {
			case "normalizePathname":
				got := NormalizePathname(testCase.inputs[0], testCase.inputs[1])
				if got != testCase.stringOutput {
					t.Fatalf("NormalizePathname(%q, %q) = %q, want %q", testCase.inputs[0], testCase.inputs[1], got, testCase.stringOutput)
				}
			case "isSafeUrlScheme":
				got := IsSafeURLScheme(testCase.inputs[0])
				if testCase.boolOutput == nil || got != *testCase.boolOutput {
					t.Fatalf("IsSafeURLScheme(%q) = %t, want %v", testCase.inputs[0], got, testCase.boolOutput)
				}
			case "safeUrlSchema":
				err := ValidateSafeURL(testCase.inputs[0])
				got := err == nil
				if testCase.boolOutput == nil || got != *testCase.boolOutput {
					t.Fatalf("ValidateSafeURL(%q) success = %t, want %v (err=%v)", testCase.inputs[0], got, testCase.boolOutput, err)
				}
			default:
				t.Fatalf("unknown URL utility operation %q", testCase.operation)
			}
		})
	}
}
