package stringutil

import "testing"

func TestCapitalizeFirstLetter(t *testing.T) {
	for _, testCase := range []struct{ input, want string }{
		{input: "hello", want: "Hello"},
		{input: "HELLO", want: "HELLO"},
		{input: "", want: ""},
	} {
		if got := CapitalizeFirstLetter(testCase.input); got != testCase.want {
			t.Fatalf("CapitalizeFirstLetter(%q) = %q, want %q", testCase.input, got, testCase.want)
		}
	}
}

func TestCaseConversion(t *testing.T) {
	for _, testCase := range stringUtilityCases {
		t.Run(testCase.operation+"/"+testCase.input, func(t *testing.T) {
			var got string
			switch testCase.operation {
			case "toSnakeCase":
				got = ToSnakeCase(testCase.input)
			case "toKebabCase":
				got = ToKebabCase(testCase.input)
			case "toCamelCase":
				got = ToCamelCase(testCase.input)
			case "toPascalCase":
				got = ToPascalCase(testCase.input)
			default:
				t.Fatalf("unknown case conversion %q", testCase.operation)
			}
			if got != testCase.want {
				t.Fatalf("%s(%q) = %q, want %q", testCase.operation, testCase.input, got, testCase.want)
			}
		})
	}
}
