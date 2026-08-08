package oauthprovider

import (
	"bytes"
	"encoding/json"
	"net/url"
	"testing"
)

type querySerializationCase struct {
	Title       string
	Observation querySerializationObservation
}

type querySerializationObservation struct {
	Operation string                   `json:"operation"`
	Input     querySerializationInput  `json:"input"`
	Output    querySerializationOutput `json:"output"`
}

type querySerializationInput struct {
	Query  string `json:"query"`
	Prompt string `json:"prompt"`
}

type querySerializationOutput struct {
	Query            json.RawMessage `json:"query"`
	OriginalQuery    string          `json:"originalQuery"`
	SerializedResult string          `json:"serializedResult"`
	IsNull           bool            `json:"isNull"`
	IsDate           bool            `json:"isDate"`
	EpochMS          *int64          `json:"epochMs"`
}

func TestOAuthQuerySerializationRuntime(t *testing.T) {
	for _, vector := range querySerializationCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			switch vector.Observation.Operation {
			case "searchParamsToQuery":
				params := parseQuerySerializationInput(t, vector.Observation.Input.Query)
				assertQuerySerializationJSON(t, SearchParamsToQuery(params), vector.Observation.Output.Query)
			case "removePromptFromQuery":
				params := parseQuerySerializationInput(t, vector.Observation.Input.Query)
				result := RemovePromptFromQuery(params, vector.Observation.Input.Prompt)
				assertQuerySerializationJSON(t, SearchParamsToQuery(result), vector.Observation.Output.Query)
				if params.Encode() != vector.Observation.Output.OriginalQuery {
					t.Fatalf("original query mutated: got %q want %q", params.Encode(), vector.Observation.Output.OriginalQuery)
				}
				if result.Encode() != vector.Observation.Output.SerializedResult {
					t.Fatalf("serialized result=%q want=%q", result.Encode(), vector.Observation.Output.SerializedResult)
				}
			case "getSignedQueryIssuedAt":
				issuedAt, ok := GetSignedQueryIssuedAt(vector.Observation.Input.Query)
				if ok == vector.Observation.Output.IsNull || ok != vector.Observation.Output.IsDate {
					t.Fatalf("issuedAt defined=%t want output %#v", ok, vector.Observation.Output)
				}
				if ok && (vector.Observation.Output.EpochMS == nil || issuedAt.UnixMilli() != *vector.Observation.Output.EpochMS) {
					t.Fatalf("issuedAt epoch=%d want=%#v", issuedAt.UnixMilli(), vector.Observation.Output.EpochMS)
				}
			default:
				t.Fatalf("unknown query serialization operation %q", vector.Observation.Operation)
			}
		})
	}
}

func parseQuerySerializationInput(t *testing.T, raw string) url.Values {
	t.Helper()
	params, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return params
}

func assertQuerySerializationJSON(t *testing.T, actual any, expected json.RawMessage) {
	t.Helper()
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, expected); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, compact.Bytes()) {
		t.Fatalf("query shape=%s want=%s", encoded, compact.Bytes())
	}
}
