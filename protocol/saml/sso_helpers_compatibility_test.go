package saml

import (
	"errors"
	"reflect"
	"testing"
)

type ssoHelpersOracle struct {
	ManifestTestIDs []string               `json:"manifestTestIDs"`
	Tests           []ssoHelpersOracleTest `json:"tests"`
}

type ssoHelpersOracleTest struct {
	ID          string                      `json:"id"`
	Title       string                      `json:"title"`
	Observation ssoHelpersOracleObservation `json:"observation"`
}

type ssoHelpersOracleObservation struct {
	Action      string              `json:"action"`
	Status      *int                `json:"status"`
	ContentType *string             `json:"contentType"`
	Body        *string             `json:"body"`
	Error       *ssoHelpersAPIError `json:"error"`
}

type ssoHelpersAPIError struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	StatusCode int            `json:"statusCode"`
	Message    string         `json:"message"`
	Body       map[string]any `json:"body"`
}

func TestSSOCreateSAMLPostFormBehavior(t *testing.T) {
	oracle := loadSSOHelpersOracle(t)
	for _, vector := range oracle.Tests {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			form, err := BuildPOSTForm(vector.Observation.Action, SAMLResponseParameter, "base64value", "")
			if vector.Observation.Error == nil {
				if err != nil {
					t.Fatal(err)
				}
				if vector.Observation.Status == nil || *vector.Observation.Status != 200 ||
					vector.Observation.ContentType == nil || *vector.Observation.ContentType != "text/html" ||
					vector.Observation.Body == nil || form != *vector.Observation.Body {
					t.Fatalf("SAML POST form status=%v contentType=%v body=%q, want %#v", vector.Observation.Status, vector.Observation.ContentType, form, vector.Observation)
				}
				return
			}
			var apiError *APIError
			if !errors.As(err, &apiError) {
				t.Fatalf("SAML POST error type=%T value=%v", err, err)
			}
			actual := ssoHelpersAPIError{
				Name: "APIError", Status: apiError.Status, StatusCode: apiError.StatusCode,
				Message: apiError.Message, Body: apiError.Body,
			}
			if !reflect.DeepEqual(actual, *vector.Observation.Error) || !IsErrorCode(err, "SAML_POST_BINDING_LOCATION_INVALID") {
				t.Fatalf("SAML POST API error=%#v, want %#v", actual, *vector.Observation.Error)
			}
		})
	}
}

func loadSSOHelpersOracle(t *testing.T) ssoHelpersOracle {
	t.Helper()
	return ssoHelpersOracle{Tests: ssoHelperCases}
}
