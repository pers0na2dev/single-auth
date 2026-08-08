package iputil

import (
	"fmt"
	"reflect"
	"testing"
)

func TestIPUtilities(t *testing.T) {
	for index, testCase := range ipCases {
		t.Run(fmt.Sprintf("%s/%d", testCase.function, index), func(t *testing.T) {
			switch testCase.function {
			case "isValidIP":
				got := IsValidIP(testCase.value)
				if testCase.wantBool == nil || got != *testCase.wantBool {
					t.Fatalf("IsValidIP(%q) = %t, want %v", testCase.value, got, testCase.wantBool)
				}
			case "normalizeIP":
				got := NormalizeIP(testCase.value, NormalizeOptions{IPv6Subnet: testCase.subnet})
				if testCase.wantString == nil || got != *testCase.wantString {
					t.Fatalf("NormalizeIP(%q) = %q, want %v", testCase.value, got, testCase.wantString)
				}
			case "createRateLimitKey":
				got := CreateRateLimitKey(testCase.value, testCase.second)
				if testCase.wantString == nil || got != *testCase.wantString {
					t.Fatalf("CreateRateLimitKey(%q, %q) = %q, want %v", testCase.value, testCase.second, got, testCase.wantString)
				}
			case "getIPFromHeader":
				got := GetIPFromHeader(testCase.value, HeaderOptions{IPv6Subnet: testCase.subnet, TrustedProxies: testCase.proxies})
				if !equalOptionalString(got, testCase.wantString) {
					t.Fatalf("GetIPFromHeader(%q) = %v, want %v", testCase.value, got, testCase.wantString)
				}
			case "findInvalidTrustedProxies":
				got := FindInvalidTrustedProxies(testCase.entries)
				if !reflect.DeepEqual(got, testCase.wantStrings) {
					t.Fatalf("FindInvalidTrustedProxies(%q) = %q, want %q", testCase.entries, got, testCase.wantStrings)
				}
			default:
				t.Fatalf("unknown IP utility %q", testCase.function)
			}
		})
	}
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
