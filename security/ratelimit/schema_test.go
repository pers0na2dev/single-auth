package ratelimit

import (
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/storage"
)

func TestSchemaMatchesUpstreamRateLimitModel(t *testing.T) {
	schema := Schema()
	if err := schema.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(schema.Models) != 1 {
		t.Fatalf("models = %#v", schema.Models)
	}
	model, exists := schema.Models["rateLimit"]
	if !exists || model.ModelName != "rateLimit" || len(model.Fields) != 3 {
		t.Fatalf("model = %#v", model)
	}
	key := model.Fields["key"]
	if key.Type != storage.FieldString || !key.Unique || key.Index {
		t.Fatalf("key = %#v", key)
	}
	count := model.Fields["count"]
	if count.Type != storage.FieldNumber || count.Unique || count.BigInt {
		t.Fatalf("count = %#v", count)
	}
	lastRequest := model.Fields["lastRequest"]
	if lastRequest.Type != storage.FieldNumber || !lastRequest.BigInt || lastRequest.DefaultValue == nil {
		t.Fatalf("lastRequest = %#v", lastRequest)
	}
	wantTime := time.Unix(1_700_000_000, 123_000_000)
	value, err := lastRequest.DefaultValue(storage.ValueContext{Now: func() time.Time { return wantTime }})
	if err != nil || value != wantTime.UnixMilli() {
		t.Fatalf("lastRequest default = %#v, %v", value, err)
	}
	for name, field := range model.Fields {
		if !field.IsRequired() {
			t.Errorf("field %q is not required", name)
		}
	}
}

func TestSchemaSupportsPhysicalModelNameAndCoreMerge(t *testing.T) {
	extension := SchemaWithModelName("auth_rate_limit")
	if extension.Models["rateLimit"].ModelName != "auth_rate_limit" {
		t.Fatalf("physical name = %q", extension.Models["rateLimit"].ModelName)
	}
	merged, err := storage.CoreSchema().Merge(extension)
	if err != nil {
		t.Fatal(err)
	}
	model, canonical, err := merged.ResolveModel("auth_rate_limit")
	if err != nil || canonical != "rateLimit" || model.ModelName != "auth_rate_limit" {
		t.Fatalf("resolved = %#v %q %v", model, canonical, err)
	}
	if got := SchemaWithModelName("").Models["rateLimit"].ModelName; got != "rateLimit" {
		t.Fatalf("empty-name fallback = %q", got)
	}
}
