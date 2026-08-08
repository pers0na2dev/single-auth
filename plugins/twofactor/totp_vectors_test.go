package twofactor

import (
	"testing"
	"time"
)

func TestGenerateTOTPVectors(t *testing.T) {
	cases := []struct {
		name     string
		secret   string
		at       time.Time
		digits   int
		period   time.Duration
		expected string
	}{
		{
			name:     "application secret",
			secret:   "my-super-secret-key",
			at:       time.Unix(1_700_000_000, 0),
			digits:   6,
			period:   30 * time.Second,
			expected: "494508",
		},
		{
			name:     "eight digit RFC vector",
			secret:   "12345678901234567890",
			at:       time.Unix(59, 0),
			digits:   8,
			period:   30 * time.Second,
			expected: "94287082",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			actual, err := GenerateTOTP(test.secret, test.at, test.digits, test.period)
			if err != nil {
				t.Fatal(err)
			}
			if actual != test.expected {
				t.Fatalf("code = %q, want %q", actual, test.expected)
			}
		})
	}
}
