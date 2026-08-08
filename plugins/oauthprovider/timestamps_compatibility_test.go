package oauthprovider

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

type timestampCase struct {
	Title        string
	Observations []timestampObservation
}

type timestampObservation struct {
	Operation string          `json:"operation"`
	Label     string          `json:"label"`
	Input     timestampInput  `json:"input"`
	Output    timestampOutput `json:"output"`
}

type timestampInput struct {
	Kind    string          `json:"kind"`
	Value   json.RawMessage `json:"value"`
	EpochMS *int64          `json:"epochMs"`
}

type timestampOutput struct {
	Defined bool   `json:"defined"`
	IsDate  bool   `json:"isDate"`
	EpochMS *int64 `json:"epochMs"`
}

func TestOAuthTimestampRuntime(t *testing.T) {
	for _, vector := range timestampCases {
		vector := vector
		t.Run(vector.Title, func(t *testing.T) {
			for _, observation := range vector.Observations {
				observation := observation
				t.Run(observation.Label, func(t *testing.T) {
					input := materializeTimestampInput(t, observation.Input)
					var actual time.Time
					var defined bool
					switch observation.Operation {
					case "normalize":
						actual, defined = NormalizeTimestampValue(input)
					case "resolve":
						actual, defined = ResolveSessionAuthTime(input)
					default:
						t.Fatalf("unknown timestamp operation %q", observation.Operation)
					}
					if defined != observation.Output.Defined || defined != observation.Output.IsDate {
						t.Fatalf("defined=%t, want output %#v", defined, observation.Output)
					}
					if !defined {
						if observation.Output.EpochMS != nil {
							t.Fatalf("undefined timestamp has epoch %d", *observation.Output.EpochMS)
						}
						return
					}
					if observation.Output.EpochMS == nil || actual.UnixMilli() != *observation.Output.EpochMS {
						t.Fatalf("timestamp epoch=%d, want %#v", actual.UnixMilli(), observation.Output.EpochMS)
					}
				})
			}
		})
	}
}

func TestNormalizeTimestampValueSupportsAdapterShapes(t *testing.T) {
	expected := int64(1774295570569)
	for _, value := range []any{
		expected,
		float64(expected) + 0.9,
		json.Number("1774295570569.0"),
		time.UnixMilli(expected).UTC().Format(time.RFC3339Nano),
		time.UnixMilli(expected),
	} {
		actual, ok := NormalizeTimestampValue(value)
		if !ok || actual.UnixMilli() != expected {
			t.Fatalf("NormalizeTimestampValue(%#v) = %v, %t", value, actual, ok)
		}
	}
	if actual, ok := NormalizeTimestampValue(math.Inf(1)); ok || !actual.IsZero() {
		t.Fatalf("infinite timestamp = %v, %t", actual, ok)
	}
}

func materializeTimestampInput(t *testing.T, input timestampInput) any {
	t.Helper()
	switch input.Kind {
	case "nan":
		return math.NaN()
	case "date":
		if input.EpochMS == nil {
			t.Fatal("date input lacks epochMs")
		}
		return time.UnixMilli(*input.EpochMS).UTC()
	case "json":
		var value any
		decoder := json.NewDecoder(strings.NewReader(string(input.Value)))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	default:
		t.Fatalf("unknown timestamp input kind %q", input.Kind)
		return nil
	}
}
