package openapi

import (
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func inputTestGenerator(t *testing.T, endpoints ...engine.Endpoint) *Generator {
	t.Helper()
	schema := storage.CoreSchema()
	delete(schema.Models, "rateLimit")
	generator, err := NewGenerator(GeneratorOptions{
		Schema: schema, BaseURL: "http://localhost:3000/api/auth",
		ListEndpoints: func() []engine.Endpoint { return append([]engine.Endpoint(nil), endpoints...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return generator
}

func metadataEndpoint(name, path, method string, metadata Metadata) engine.Endpoint {
	return WithMetadata(engine.Endpoint{
		Name: name, Path: path, Methods: []string{method},
		Handler: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(contract.StatusOK, map[string]any{"success": true})
		},
	}, metadata)
}

func generatedPath(t *testing.T, generator *Generator, path string) PathItem {
	t.Helper()
	document, err := generator.Generate(contract.NewRequest("GET", "/", contract.RequestOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	item, exists := document.Paths[path]
	if !exists {
		t.Fatalf("missing path %s", path)
	}
	return item
}

func requestSchema(t *testing.T, operation *Operation) Schema {
	t.Helper()
	if operation == nil || operation.RequestBody == nil {
		t.Fatal("missing request body")
	}
	media, exists := operation.RequestBody.Content["application/json"]
	if !exists || media.Schema == nil {
		t.Fatal("missing application/json schema")
	}
	return *media.Schema
}

func TestNullableObjectIntersectionsMergeWithOpenAPI31NullType(t *testing.T) {
	body := Intersection(
		Object(Prop("email", String())).Nullable(),
		Object(Prop("otp", String())).Nullable(),
	)
	operation := generatedPath(t, inputTestGenerator(t,
		metadataEndpoint("nullable", "/test/nullable-intersection", "POST", Metadata{Body: inputPointer(body)}),
	), "/test/nullable-intersection").Post
	schema := requestSchema(t, operation)
	if operation.RequestBody.Required == nil || !*operation.RequestBody.Required ||
		!reflect.DeepEqual(schema.Type, []string{"object", "null"}) ||
		!reflect.DeepEqual(schema.Required, []string{"email", "otp"}) {
		t.Fatalf("request body=%#v schema=%#v", operation.RequestBody, schema)
	}
}

func TestDefaultWrappedBodiesAreOptionalWithoutEvaluatingDefaults(t *testing.T) {
	calls := 0
	body := Object(Prop("nonce", String())).DefaultFactory(func() any {
		calls++
		return map[string]any{"nonce": "generated"}
	})
	operation := generatedPath(t, inputTestGenerator(t,
		metadataEndpoint("defaultFactory", "/test/default-factory-body", "POST", Metadata{Body: inputPointer(body)}),
	), "/test/default-factory-body").Post
	schema := requestSchema(t, operation)
	if operation.RequestBody.Required == nil || *operation.RequestBody.Required || calls != 0 ||
		schema.Type != "object" || schema.Default != nil || schema.Properties["nonce"].Type != "string" {
		t.Fatalf("calls=%d body=%#v schema=%#v", calls, operation.RequestBody, schema)
	}
}

func TestObjectUnionIntersectionUsesAllOfAndAnyOf(t *testing.T) {
	body := Intersection(
		Object(Prop("organizationId", String().Optional())),
		Union(
			Object(Prop("roleName", String())),
			Object(Prop("roleId", String())),
		),
	)
	schema := requestSchema(t, generatedPath(t, inputTestGenerator(t,
		metadataEndpoint("chooseRole", "/test/choose-role", "POST", Metadata{Body: inputPointer(body)}),
	), "/test/choose-role").Post)
	if len(schema.AllOf) != 2 || schema.AllOf[0].Type != "object" || len(schema.AllOf[1].AnyOf) != 2 ||
		!reflect.DeepEqual(schema.AllOf[1].AnyOf[0].Required, []string{"roleName"}) ||
		!reflect.DeepEqual(schema.AllOf[1].AnyOf[1].Required, []string{"roleId"}) {
		t.Fatalf("schema=%#v", schema)
	}
}

func TestObjectRecordIntersectionPreservesKeyAndValueSchemas(t *testing.T) {
	body := Intersection(
		Object(Prop("knownField", String())),
		Record(String().Min(2).Describe("Custom field names must be at least two characters"), Boolean()),
	)
	schema := requestSchema(t, generatedPath(t, inputTestGenerator(t,
		metadataEndpoint("updateFields", "/test/update-fields", "POST", Metadata{Body: inputPointer(body)}),
	), "/test/update-fields").Post)
	additional, ok := schema.AdditionalProperties.(Schema)
	if !ok || additional.Type != "boolean" || schema.PropertyNames == nil ||
		schema.PropertyNames.Type != "string" || schema.PropertyNames.MinLength == nil || *schema.PropertyNames.MinLength != 2 ||
		schema.PropertyNames.Description != "Custom field names must be at least two characters" ||
		!reflect.DeepEqual(schema.Required, []string{"knownField"}) {
		t.Fatalf("schema=%#v", schema)
	}
}

func TestWrappedQueryParametersRetainStringConstraints(t *testing.T) {
	query := Object(
		Prop("direct", String().Min(3)),
		Prop("optional", String().Min(4).Optional()),
		Prop("defaulted", String().Min(5).Default("abcde")),
		Prop("bounded", String().Min(6).Max(12)),
	)
	operation := generatedPath(t, inputTestGenerator(t,
		metadataEndpoint("constrained", "/test/query-constraints", "GET", Metadata{Query: inputPointer(query)}),
	), "/test/query-constraints").Get
	want := map[string][2]int{"direct": {3, 0}, "optional": {4, 0}, "defaulted": {5, 0}, "bounded": {6, 12}}
	if len(operation.Parameters) != len(want) {
		t.Fatalf("parameters=%#v", operation.Parameters)
	}
	for _, parameter := range operation.Parameters {
		limits, exists := want[parameter.Name]
		if !exists || parameter.Schema == nil || parameter.Schema.Type != "string" ||
			parameter.Schema.MinLength == nil || *parameter.Schema.MinLength != limits[0] {
			t.Fatalf("parameter=%#v", parameter)
		}
		if limits[1] == 0 && parameter.Schema.MaxLength != nil || limits[1] != 0 && (parameter.Schema.MaxLength == nil || *parameter.Schema.MaxLength != limits[1]) {
			t.Fatalf("parameter max=%#v", parameter)
		}
	}
}

func TestWrapperSemanticsComputeRequiredFieldsWithoutFactoryCalls(t *testing.T) {
	calls := 0
	body := Object(
		Prop("optionalNullable", String().Optional().Nullable()),
		Prop("nullableDefault", String().DefaultFactory(func() any { calls++; return "generated" }).Nullable()),
		Prop("prefaulted", String().Prefault("value")),
		Prop("nonOptional", String().Optional().NonOptional()),
		Prop("unionOptional", Union(String(), Undefined())),
	)
	operation := generatedPath(t, inputTestGenerator(t,
		metadataEndpoint("wrappers", "/test/wrapper-semantics", "POST", Metadata{Body: inputPointer(body)}),
	), "/test/wrapper-semantics").Post
	schema := requestSchema(t, operation)
	if calls != 0 || !reflect.DeepEqual(schema.Required, []string{"nonOptional"}) ||
		!reflect.DeepEqual(schema.Properties["optionalNullable"].Type, []string{"string", "null"}) ||
		!reflect.DeepEqual(schema.Properties["nullableDefault"].Type, []string{"string", "null"}) ||
		schema.Properties["nullableDefault"].Default != nil || schema.Properties["prefaulted"].Default != nil ||
		schema.Properties["prefaulted"].Type != "string" || schema.Properties["nonOptional"].Type != "string" ||
		schema.Properties["unionOptional"].Type != "string" {
		t.Fatalf("calls=%d schema=%#v", calls, schema)
	}
}

func TestGeneratedOperationsHaveStandardResponsesAndIndependentValues(t *testing.T) {
	responseSchema := Schema{Type: "object", Properties: map[string]Schema{"ok": {Type: "boolean"}}, Required: []string{"ok"}}
	metadata := Metadata{
		OperationID: "probe", Description: "probe",
		Responses: map[string]Response{"200": {
			Description: "Success", Content: map[string]MediaType{"application/json": {Schema: &responseSchema}},
		}},
	}
	endpoint := metadataEndpoint("probe", "/probe/:id", "GET", metadata)
	endpoint.Methods = []string{"GET", "POST"}
	document, err := inputTestGenerator(t, endpoint).Generate(contract.NewRequest("GET", "/", contract.RequestOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	item := document.Paths["/probe/{id}"]
	if item.Get.OperationID != "probe" || item.Post.OperationID != "probePost" ||
		len(item.Get.Parameters) != 1 || item.Get.Parameters[0].Name != "id" ||
		item.Get.Parameters[0].Required == nil || !*item.Get.Parameters[0].Required {
		t.Fatalf("item=%#v", item)
	}
	item.Get.Parameters[0].Name = "changed"
	item.Get.Responses["200"] = Response{Description: "changed"}
	if item.Post.Parameters[0].Name != "id" || item.Post.Responses["200"].Description != "Success" {
		t.Fatalf("operations share data: %#v", item)
	}
	for _, status := range []string{"400", "401", "403", "404", "429", "500"} {
		if _, exists := item.Post.Responses[status]; !exists {
			t.Fatalf("missing response %s", status)
		}
	}
}
