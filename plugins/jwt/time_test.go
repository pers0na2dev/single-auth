package jwt

import (
	"testing"
	"time"
)

func TestToExpJWTMatchesUpstreamInputs(t *testing.T) {
	iat := float64(1000)
	cases := []struct {
		input any
		want  float64
	}{
		{3600, 3600}, {0, 0}, {9999999, 9999999},
		{3600.5, 3600.5},
		{time.Date(2024, 1, 1, 0, 0, 0, 500_000_000, time.UTC), 1704067200},
		{time.UnixMilli(-500), -1},
		{"1h", 4600}, {"7d", 605800}, {"30m", 2800}, {"1s", 1001},
		{"1 hour", 4600}, {"7 days", 605800}, {"30 minutes", 2800},
		{"-1h", -2600}, {"1h ago", -2600}, {"+ 1.5h", 6400},
		{"1 month", 2593000}, {"1 year", 31558600},
		{"0.5s ago", 1000},
	}
	for _, test := range cases {
		got, err := ToExpJWT(test.input, iat)
		if err != nil {
			t.Errorf("ToExpJWT(%#v): %v", test.input, err)
			continue
		}
		if got != test.want {
			t.Errorf("ToExpJWT(%#v) = %v, want %v", test.input, got, test.want)
		}
	}
}

func TestToExpJWTRejectsUpstreamInvalidFormats(t *testing.T) {
	for _, input := range []string{"invalid", "", "abc123", "-1h ago", "+1h from now", "1h "} {
		if _, err := ToExpJWT(input, 1000); err == nil {
			t.Errorf("ToExpJWT(%q) accepted invalid input", input)
		}
	}
}
