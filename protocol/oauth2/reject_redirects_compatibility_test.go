package oauth2

import (
	"errors"
	"testing"
)

type rejectRedirectsOracle struct {
	ManifestTestIDs []string                    `json:"manifestTestIDs"`
	Tests           []rejectRedirectsOracleTest `json:"tests"`
}

type rejectRedirectsOracleTest struct {
	ID          string                           `json:"id"`
	Title       string                           `json:"title"`
	Observation rejectRedirectsOracleObservation `json:"observation"`
}

type rejectRedirectsOracleObservation struct {
	Endpoint string                      `json:"endpoint"`
	Cases    []rejectRedirectsOracleCase `json:"cases"`
}

type rejectRedirectsOracleCase struct {
	Response     ResponseMetadata `json:"response"`
	Threw        bool             `json:"threw"`
	ErrorName    *string          `json:"errorName"`
	ErrorMessage *string          `json:"errorMessage"`
}

func TestRejectRedirectsBehavior(t *testing.T) {
	oracle := loadRejectRedirectsOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			for _, testCase := range vector.Observation.Cases {
				err := AssertResponseMetadataNotRedirect(vector.Observation.Endpoint, testCase.Response)
				if (err != nil) != testCase.Threw {
					t.Fatalf("response=%#v error=%v, threw=%v", testCase.Response, err, testCase.Threw)
				}
				if err == nil {
					continue
				}
				var redirectError *RedirectRefusedError
				if !errors.As(err, &redirectError) || !errors.Is(err, ErrOAuthRedirect) {
					t.Fatalf("redirect error type=%T value=%v", err, err)
				}
				if testCase.ErrorMessage == nil || err.Error() != *testCase.ErrorMessage {
					t.Fatalf("redirect error=%q, want %v", err.Error(), testCase.ErrorMessage)
				}
			}
		})
	}
}

func loadRejectRedirectsOracle(t *testing.T) rejectRedirectsOracle {
	t.Helper()
	return rejectRedirectsOracle{Tests: rejectRedirectCases}
}
