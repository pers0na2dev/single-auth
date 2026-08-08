package oauthprovider

import (
	"strings"
	"testing"
)

type safeURLCase struct {
	Title       string
	Observation safeURLExpectation
}

type safeURLExpectation struct {
	Input           string
	Success         bool
	MessageContains []string
}

func TestOAuthProviderSafeURLs(t *testing.T) {
	for _, vector := range safeURLCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			err := ValidateSafeURL(vector.Observation.Input)
			if actual := err == nil; actual != vector.Observation.Success {
				t.Fatalf("ValidateSafeURL(%q) success = %v, want %v (error: %v)", vector.Observation.Input, actual, vector.Observation.Success, err)
			}
			for _, fragment := range vector.Observation.MessageContains {
				if err == nil || !strings.Contains(err.Error(), fragment) {
					t.Fatalf("ValidateSafeURL(%q) error = %v, want fragment %q", vector.Observation.Input, err, fragment)
				}
			}
		})
	}
}
