package logger

import (
	"fmt"
	"testing"
)

type shouldPublishCase struct {
	CurrentLogLevel Level
	LogLevel        Level
	Expected        bool
}

func TestShouldPublishLevelMatrix(t *testing.T) {
	for _, testCase := range shouldPublishCases {
		testCase := testCase
		t.Run(fmt.Sprintf("%s-to-%s", testCase.CurrentLogLevel, testCase.LogLevel), func(t *testing.T) {
			t.Parallel()
			if got := ShouldPublish(testCase.CurrentLogLevel, testCase.LogLevel); got != testCase.Expected {
				t.Fatalf("ShouldPublish(%q, %q) = %t, want %t", testCase.CurrentLogLevel, testCase.LogLevel, got, testCase.Expected)
			}
		})
	}
}
